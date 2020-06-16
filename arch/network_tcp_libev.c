#define UA_INTERNAL

#include <open62541/network_tcp.h>
#include <open62541/plugin/log_stdout.h>
#include <open62541/util.h>

#include "open62541_queue.h"
#include "ua_securechannel.h"

#include <string.h>  // memset

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#ifdef UA_ENABLE_LIBEV

#include <ev.h>
#include <open62541/server_config.h>

static UA_StatusCode
connection_getsendbuffer(UA_Connection *connection,
                         size_t length, UA_ByteString *buf) {
    UA_SecureChannel *channel = connection->channel;
    if(channel && channel->config.sendBufferSize < length)
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    return UA_ByteString_allocBuffer(buf, length);
}

static void
connection_releasesendbuffer(UA_Connection *connection,
                             UA_ByteString *buf) {
    UA_ByteString_deleteMembers(buf);
}

static void
connection_releaserecvbuffer(UA_Connection *connection,
                             UA_ByteString *buf) {
    UA_ByteString_deleteMembers(buf);
}

static UA_StatusCode
connection_write(UA_Connection *connection, UA_ByteString *buf) {
    if(connection->state == UA_CONNECTIONSTATE_CLOSED) {
        UA_ByteString_deleteMembers(buf);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    /* Prevent OS signals when sending to a closed socket */
    int flags = 0;
    flags |= MSG_NOSIGNAL;

    /* Send the full buffer. This may require several calls to send */
    size_t nWritten = 0;
    do {
        ssize_t n = 0;
        do {
            size_t bytes_to_send = buf->length - nWritten;
            n = UA_send(connection->sockfd,
                     (const char*)buf->data + nWritten,
                     bytes_to_send, flags);
            if(n < 0 && UA_ERRNO != UA_INTERRUPTED && UA_ERRNO != UA_AGAIN) {
                connection->close(connection);
                UA_ByteString_deleteMembers(buf);
                return UA_STATUSCODE_BADCONNECTIONCLOSED;
            }
        } while(n < 0);
        nWritten += (size_t)n;
    } while(nWritten < buf->length);

    /* Free the buffer */
    UA_ByteString_deleteMembers(buf);
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
connection_recv(UA_Connection *connection, UA_ByteString *response,
                UA_UInt32 timeout) {
    if(connection->state == UA_CONNECTIONSTATE_CLOSED)
        return UA_STATUSCODE_BADCONNECTIONCLOSED;

    /* Listen on the socket for the given timeout until a message arrives */
    fd_set fdset;
    FD_ZERO(&fdset);
    UA_fd_set(connection->sockfd, &fdset);
    UA_UInt32 timeout_usec = timeout * 1000;
    struct timeval tmptv = {(long int)(timeout_usec / 1000000),
                            (int)(timeout_usec % 1000000)};
    int resultsize = UA_select(connection->sockfd+1, &fdset, NULL, NULL, &tmptv);

    /* No result */
    if(resultsize == 0)
        return UA_STATUSCODE_GOODNONCRITICALTIMEOUT;

    if(resultsize == -1) {
        /* The call to select was interrupted. Act as if it timed out. */
        if(UA_ERRNO == EINTR)
            return UA_STATUSCODE_GOODNONCRITICALTIMEOUT;

        /* The error cannot be recovered. Close the connection. */
        connection->close(connection);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    UA_Boolean internallyAllocated = !response->length;

    /* Allocate the buffer  */
    if(internallyAllocated) {
        size_t bufferSize = 16384; /* Use as default for a new SecureChannel */
        UA_SecureChannel *channel = connection->channel;
        if(channel && channel->config.recvBufferSize > 0)
            bufferSize = channel->config.recvBufferSize;
        UA_StatusCode res = UA_ByteString_allocBuffer(response, bufferSize);
        if(res != UA_STATUSCODE_GOOD)
            return res;
    }

    /* Get the received packet(s) */
    ssize_t ret = UA_recv(connection->sockfd, (char*)response->data, response->length, 0);

    /* The remote side closed the connection */
    if(ret == 0) {
        if(internallyAllocated)
            UA_ByteString_deleteMembers(response);
        connection->close(connection);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    /* Error case */
    if(ret < 0) {
        if(internallyAllocated)
            UA_ByteString_deleteMembers(response);
        if(UA_ERRNO == UA_INTERRUPTED || (timeout > 0) ?
           false : (UA_ERRNO == UA_EAGAIN || UA_ERRNO == UA_WOULDBLOCK))
            return UA_STATUSCODE_GOOD; /* statuscode_good but no data -> retry */
        connection->close(connection);
        return UA_STATUSCODE_BADCONNECTIONCLOSED;
    }

    /* Set the length of the received buffer */
    response->length = (size_t)ret;
    return UA_STATUSCODE_GOOD;
}


/***************************/
/* Server NetworkLayer TCP */
/***************************/

#define MAXBACKLOG     100
#define NOHELLOTIMEOUT 120000 /* timeout in ms before close the connection
                               * if server does not receive Hello Message */

typedef struct ConnectionEntry {
    UA_Connection connection;
    LIST_ENTRY(ConnectionEntry) pointers;
} ConnectionEntry;

typedef struct {
    const UA_Logger *logger;
    UA_UInt16 port;
    UA_UInt16 maxConnections;
    LIST_HEAD(, ConnectionEntry) connections;
    UA_UInt16 connectionsSize;
    UA_ServerNetworkLayer *nl;
    UA_Server *server;
    struct ev_loop *loop;
    ev_io listener;
} ServerNetworkLayerTCP_libev;

typedef struct {
    ServerNetworkLayerTCP_libev *layer;
    ev_io watcher;
} ConnectionHandle;

static void
ServerNetworkLayerTCP_freeConnection(UA_Connection *connection) {
    UA_free(connection->handle);
    UA_free(connection);
}

static void
ServerNetworkLayerTCP_close(UA_Connection *connection) {
    if(connection->state == UA_CONNECTIONSTATE_CLOSED)
        return;
    ConnectionHandle *chandle = (ConnectionHandle*)connection->handle;
    ev_io_stop(chandle->layer->loop, &chandle->watcher);
    UA_shutdown((UA_SOCKET)connection->sockfd, 2);
    UA_close(connection->sockfd);
    connection->state = UA_CONNECTIONSTATE_CLOSED;
}

static UA_Boolean
purgeFirstConnectionWithoutChannel(ServerNetworkLayerTCP_libev *layer) {
    ConnectionEntry *e;
    LIST_FOREACH(e, &layer->connections, pointers) {
        if(e->connection.channel == NULL) {
            LIST_REMOVE(e, pointers);
            layer->connectionsSize--;
            e->connection.close(&e->connection);
            e->connection.free(&e->connection);
            return true;
        }
    }
    return false;
}

static void
layerRecvCallback(struct ev_loop *loop, ev_io *w, int revents)
{
    ConnectionEntry *e = (ConnectionEntry*)w->data;
    ServerNetworkLayerTCP_libev *layer = ((ConnectionHandle*)e->connection.handle)->layer;
    UA_ServerNetworkLayer *nl = layer->nl;

    UA_LOG_TRACE(layer->logger, UA_LOGCATEGORY_NETWORK,
                    "Connection %i | Activity on the socket",
                    (int)(w->fd));

    UA_ByteString buf = UA_BYTESTRING_NULL;
    UA_StatusCode retval = connection_recv(&e->connection, &buf, 0);

    if(retval == UA_STATUSCODE_GOOD) {
        /* Process packets */
        UA_Server_processBinaryMessage(layer->server, &e->connection, &buf);
        connection_releaserecvbuffer(&e->connection, &buf);
    } else if(retval == UA_STATUSCODE_BADCONNECTIONCLOSED) {
        /* The socket is shutdown but not closed */
        UA_LOG_INFO(layer->logger, UA_LOGCATEGORY_NETWORK,
                    "Connection %i | Closed",
                    (int)(w->fd));
        LIST_REMOVE(e, pointers);
        layer->connectionsSize--;
        UA_close(w->fd);
        UA_Server_removeConnection(layer->server, &e->connection);
        if(nl->statistics) {
            nl->statistics->currentConnectionCount--;
        }
        ev_io_stop(loop, w);
        UA_free(w);
    }
}

static void
layerAcceptCallback(struct ev_loop *loop, ev_io *w, int revents)
{
    ServerNetworkLayerTCP_libev *layer = (ServerNetworkLayerTCP_libev*)w->data;

    struct sockaddr_storage remote;
    socklen_t remote_size = sizeof(remote);
    UA_SOCKET newsockfd = UA_accept(w->fd,
                                (struct sockaddr*)&remote, &remote_size);
    if(newsockfd == UA_INVALID_SOCKET)
        return;

    UA_LOG_TRACE(layer->logger, UA_LOGCATEGORY_NETWORK,
                "Connection %i | New TCP connection on server socket %i",
                (int)newsockfd, (int)(w->fd));

    if(layer->maxConnections && layer->connectionsSize >= layer->maxConnections &&
      !purgeFirstConnectionWithoutChannel(layer)) {
        UA_LOG_SOCKET_ERRNO_WRAP(
            UA_LOG_ERROR(layer->logger, UA_LOGCATEGORY_NETWORK,
                             "Cannot set socket option TCP_NODELAY. Error: %s",
                             errno_str));
   }

    /* Set nonblocking */
    UA_socket_set_nonblocking(newsockfd);//TODO: check return value

    /* Do not merge packets on the socket (disable Nagle's algorithm) */
    int dummy = 1;
    if(UA_setsockopt(newsockfd, IPPROTO_TCP, TCP_NODELAY,
               (const char *)&dummy, sizeof(dummy)) < 0) {
        UA_LOG_SOCKET_ERRNO_WRAP(
                UA_LOG_ERROR(layer->logger, UA_LOGCATEGORY_NETWORK,
                             "Cannot set socket option TCP_NODELAY. Error: %s",
                             errno_str));
        UA_close(newsockfd);
        return;
    }

#if defined(UA_getnameinfo)
    /* Get the peer name for logging */
    char remote_name[100];
    int res = UA_getnameinfo((struct sockaddr*)&remote,
                          sizeof(struct sockaddr_storage),
                          remote_name, sizeof(remote_name),
                          NULL, 0, NI_NUMERICHOST);
    if(res == 0) {
        UA_LOG_INFO(layer->logger, UA_LOGCATEGORY_NETWORK,
                    "Connection %i | New connection over TCP from %s",
                    (int)newsockfd, remote_name);
    } else {
        UA_LOG_SOCKET_ERRNO_WRAP(UA_LOG_WARNING(layer->logger, UA_LOGCATEGORY_NETWORK,
                                                "Connection %i | New connection over TCP, "
                                                "getnameinfo failed with error: %s",
                                                (int)newsockfd, errno_str));
    }
#else
    UA_LOG_INFO(layer->logger, UA_LOGCATEGORY_NETWORK,
                "Connection %i | New connection over TCP",
                (int)newsockfd);
#endif
    /* Allocate and initialize the connection */
    ConnectionEntry *e = (ConnectionEntry*)UA_malloc(sizeof(ConnectionEntry));
    if(!e) {
        UA_close(newsockfd);
        return;
    }

    UA_Connection *c = &e->connection;
    ConnectionHandle *connectionHandle = (ConnectionHandle*)UA_calloc(1, sizeof(ConnectionHandle));
    connectionHandle->layer = layer;
    memset(c, 0, sizeof(UA_Connection));
    c->sockfd = newsockfd;
    c->handle = connectionHandle;
    c->send = connection_write;
    c->close = ServerNetworkLayerTCP_close;
    c->free = ServerNetworkLayerTCP_freeConnection;
    c->getSendBuffer = connection_getsendbuffer;
    c->releaseSendBuffer = connection_releasesendbuffer;
    c->releaseRecvBuffer = connection_releaserecvbuffer;
    c->state = UA_CONNECTIONSTATE_OPENING;
    c->openingDate = UA_DateTime_nowMonotonic();

    ev_io_init(&connectionHandle->watcher, &layerRecvCallback, newsockfd, EV_READ);
    connectionHandle->watcher.data = e;
    ev_io_start(loop, &connectionHandle->watcher);

    /* Add to the linked list */
    LIST_INSERT_HEAD(&layer->connections, e, pointers);
    UA_ServerNetworkLayer *nl = layer->nl;
    if(nl->statistics) {
        nl->statistics->currentConnectionCount++;
        nl->statistics->cumulatedConnectionCount++;
    }
    layer->connectionsSize++;
}

static UA_StatusCode
initListenerSocket(ServerNetworkLayerTCP_libev *layer)
{
    int listener;     // Listening socket descriptor
    int yes=1;        // For setsockopt() SO_REUSEADDR, below
    int rv;

    struct addrinfo hints, *ai, *p;

    // Get us a socket and bind it
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    char portno[6];
    UA_snprintf(portno, 6, "%d", layer->port);
    if ((rv = UA_getaddrinfo(NULL, portno, &hints, &ai)) != 0) {
        UA_LOG_ERROR(layer->logger, UA_LOGCATEGORY_NETWORK, "Could not get host info: %s\n", gai_strerror(rv));
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }
    
    for(p = ai; p != NULL; p = p->ai_next) {
        listener = UA_socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (listener < 0) {
            continue;
        }
        
        // Lose the pesky "address already in use" error message
        UA_setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

        if (UA_bind(listener, p->ai_addr, p->ai_addrlen) < 0) {
            UA_close(listener);
            continue;
        }

        break;
    }

    // If we got here, it means we didn't get bound
    if (p == NULL) {
        UA_LOG_ERROR(layer->logger, UA_LOGCATEGORY_NETWORK, "Could not create listening socket: %s\n", gai_strerror(rv));
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    UA_freeaddrinfo(ai); // All done with this

    // Listen
    if (UA_listen(listener, MAXBACKLOG) == -1) {
        UA_LOG_ERROR(layer->logger, UA_LOGCATEGORY_NETWORK, "Cannot listen on created socket: %s\n", strerror(errno));
        return UA_STATUSCODE_BADCOMMUNICATIONERROR;
    }

    ev_io_init(&layer->listener, layerAcceptCallback, listener, EV_READ);
    layer->listener.data = layer;
    ev_io_start(layer->loop, &layer->listener);

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
ServerNetworkLayerTCP_libev_start(UA_ServerNetworkLayer *nl, UA_Server *server,
                                  const UA_String *customHostname)
{
    ServerNetworkLayerTCP_libev *layer = (ServerNetworkLayerTCP_libev*)nl->handle;
    layer->loop = (struct ev_loop*)UA_Server_getConfig(server)->externalEventLoop;
    if(!layer->loop)
        return UA_STATUSCODE_BADINVALIDARGUMENT;
    layer->nl = nl;
    layer->server = server;
    initListenerSocket(layer);
    return UA_STATUSCODE_GOOD; 
}

static UA_StatusCode
ServerNetworkLayerTCP_libev_listen(UA_ServerNetworkLayer *nl, UA_Server *server,
                                   UA_UInt16 timeout)
{
    return UA_STATUSCODE_GOOD;
}

static void
ServerNetworkLayerTCP_libev_stop(UA_ServerNetworkLayer *nl, UA_Server *server)
{
    ServerNetworkLayerTCP_libev *layer = (ServerNetworkLayerTCP_libev*)nl->handle;
    UA_LOG_INFO(layer->logger, UA_LOGCATEGORY_NETWORK,
                "Shutting down the TCP network layer");

    /* Close the server sockets */
    ev_io_stop(layer->loop, &layer->listener);
    UA_shutdown(layer->listener.fd, 2);
    UA_close(layer->listener.fd);

    /* Close open connections */
    ConnectionEntry *e;
    LIST_FOREACH(e, &layer->connections, pointers)
        ServerNetworkLayerTCP_close(&e->connection);

    UA_deinitialize_architecture_network();
}

static void
ServerNetworkLayerTCP_libev_deleteMembers(UA_ServerNetworkLayer *nl) {
    ServerNetworkLayerTCP_libev *layer = (ServerNetworkLayerTCP_libev*)nl->handle;
    UA_String_deleteMembers(&nl->discoveryUrl);

    ConnectionEntry *e, *e_tmp;
    LIST_FOREACH_SAFE(e, &layer->connections, pointers, e_tmp) {
        LIST_REMOVE(e, pointers);
        layer->connectionsSize--;
        ServerNetworkLayerTCP_close(&e->connection);
        ServerNetworkLayerTCP_freeConnection(&e->connection);
        if(nl->statistics) {
            nl->statistics->currentConnectionCount--;
        }
    }
    UA_free(layer);
}

UA_ServerNetworkLayer
UA_ServerNetworkLayerTCP_libev(UA_ConnectionConfig config, UA_UInt16 port,
                               UA_UInt16 maxConnections, UA_Logger *logger) {
    UA_ServerNetworkLayer nl;
    memset(&nl, 0, sizeof(UA_ServerNetworkLayer));
    nl.clear = ServerNetworkLayerTCP_libev_deleteMembers;
    nl.localConnectionConfig = config;
    nl.start = ServerNetworkLayerTCP_libev_start;
    nl.listen = ServerNetworkLayerTCP_libev_listen;
    nl.stop = ServerNetworkLayerTCP_libev_stop;
    nl.handle = NULL;

    ServerNetworkLayerTCP_libev *layer = (ServerNetworkLayerTCP_libev*)
        UA_calloc(1,sizeof(ServerNetworkLayerTCP_libev));
    if(!layer)
        return nl;
    nl.handle = layer;

    layer->logger = logger;
    layer->port = port;
    layer->maxConnections = maxConnections;

    return nl;
}

/***************************/
/* Client NetworkLayer TCP */
/***************************/

typedef struct TCPClientConnection {
    struct addrinfo hints, *server;
    UA_DateTime connStart;
    char* endpointURL;
    UA_UInt32 timeout;
    ev_io iow;
    struct ev_loop *loop;
    UA_Logger *logger;
    UA_Client *client;
} TCPClientConnection;

static void
ClientNetworkLayerTCP_close(UA_Connection *connection) {
    if(connection->state == UA_CONNECTIONSTATE_CLOSED)
        return;

    if(connection->sockfd != UA_INVALID_SOCKET) {
        TCPClientConnection *tcpConnection = (TCPClientConnection *)connection->handle;
        ev_io_stop(tcpConnection->loop, &tcpConnection->iow);
        UA_shutdown(connection->sockfd, 2);
        UA_close(connection->sockfd);
    }
    connection->state = UA_CONNECTIONSTATE_CLOSED;
}

static void
ClientNetworkLayerTCP_free(UA_Connection *connection) {
    if(!connection->handle)
        return;
    
    TCPClientConnection *tcpConnection = (TCPClientConnection *)connection->handle;
    if(tcpConnection->server)
        UA_freeaddrinfo(tcpConnection->server);
    UA_free(tcpConnection);
    connection->handle = NULL;
}

static void
ClientNetworkLayerTCP_eventCallback(struct ev_loop *loop, ev_io *w, int revents) {
    UA_Connection *connection = (UA_Connection*)w->data;
    TCPClientConnection *tcpConnection = (TCPClientConnection*)connection->handle;
    UA_Client *client = tcpConnection->client;
    switch(connection->state) {
        case UA_CONNECTIONSTATE_OPENING: {
            OPTVAL_TYPE so_error;
            socklen_t len = sizeof so_error;
            int ret = UA_getsockopt(w->fd, SOL_SOCKET, SO_ERROR, &so_error, &len);

            if(ret == 0 && so_error == 0) {
                /* Connected */
                connection->state = UA_CONNECTIONSTATE_ESTABLISHED;
                ev_io_stop(loop, w);
                ev_io_set(w, w->fd, EV_READ);
                ev_io_start(loop, w);
                UA_Client_connect_iterate(client, 0);
                UA_LOG_WARNING(tcpConnection->logger, UA_LOGCATEGORY_NETWORK, "CONNECTED!!!");
            } else {
                /* General error */
                ClientNetworkLayerTCP_close(connection);
                UA_Client_closeChannel(client, UA_STATUSCODE_BADCONNECTIONREJECTED);
                UA_LOG_WARNING(tcpConnection->logger, UA_LOGCATEGORY_NETWORK,
                                "Connection to failed with error: %s",
                                strerror(ret == 0 ? so_error : UA_ERRNO));
            }
            return;
        }
        case UA_CONNECTIONSTATE_ESTABLISHED: {
            UA_ByteString buf = UA_BYTESTRING_NULL;
            UA_StatusCode retval = connection_recv(connection, &buf, 0);

            if(retval == UA_STATUSCODE_GOOD) {
                /* Process packets */
                UA_Client_processBinaryMessage(client, connection, &buf);
                connection_releaserecvbuffer(connection, &buf);
            }

            UA_SecureChannelState channelState;
            UA_Client_getState(client, &channelState, NULL, NULL);
            if(retval != UA_STATUSCODE_GOOD ||
                channelState == UA_SECURECHANNELSTATE_CLOSING) {
                UA_LOG_WARNING(tcpConnection->logger, UA_LOGCATEGORY_NETWORK,
                                    "Receiving the response failed with StatusCode %s",
                                    UA_StatusCode_name(retval));
                ev_io_stop(loop, w);
                UA_Client_closeChannel(client, UA_STATUSCODE_BADCONNECTIONCLOSED);
                break;
            }
        }
        default:
            return;
    }
}

UA_StatusCode
UA_ClientConnectionTCP_poll_libev(UA_Client *client, void *data, UA_UInt32 timeout) {
    UA_Connection *connection = (UA_Connection*) data;
    if(connection->state == UA_CONNECTIONSTATE_CLOSED)
        return UA_STATUSCODE_BADDISCONNECT;
    if(connection->state == UA_CONNECTIONSTATE_ESTABLISHED)
        return UA_STATUSCODE_GOOD;
    if(!UA_Client_getConfig(client)->externalEventLoop)
        return UA_STATUSCODE_BADDISCONNECT;

    TCPClientConnection *tcpConnection = (TCPClientConnection*) connection->handle;
    UA_SOCKET clientsockfd = connection->sockfd;
    UA_ClientConfig *config = UA_Client_getConfig(client);
    if(!tcpConnection->client)
        tcpConnection->client = client;

    /* Connection timeout? */
    if((UA_Double) (UA_DateTime_nowMonotonic() - tcpConnection->connStart)
       > tcpConnection->timeout * UA_DATETIME_MSEC ) {
        ClientNetworkLayerTCP_close(connection);
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_NETWORK, "Timed out");
        return UA_STATUSCODE_BADDISCONNECT;
    }

    if(clientsockfd <= 0) {
        clientsockfd = UA_socket(tcpConnection->server->ai_family,
                                 tcpConnection->server->ai_socktype,
                                 tcpConnection->server->ai_protocol);
        connection->sockfd = (UA_Int32)clientsockfd; /* cast for win32 */
    }

    if(clientsockfd == UA_INVALID_SOCKET) {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not create client socket: %s", strerror(UA_ERRNO));
        ClientNetworkLayerTCP_close(connection);
        return UA_STATUSCODE_BADDISCONNECT;
    }

    /* Non blocking connect to be able to timeout */
    if(UA_socket_set_nonblocking(clientsockfd) != UA_STATUSCODE_GOOD) {
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_NETWORK,
                       "Could not set the client socket to nonblocking");
        ClientNetworkLayerTCP_close(connection);
        return UA_STATUSCODE_BADDISCONNECT;
    }

    /* Non blocking connect */
    int error = UA_connect(clientsockfd, tcpConnection->server->ai_addr,
                           tcpConnection->server->ai_addrlen);

    if((error == -1) && (UA_ERRNO != UA_ERR_CONNECTION_PROGRESS)) {
        ClientNetworkLayerTCP_close(connection);
        UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_NETWORK,
                       "Connection to  failed with error: %s", strerror(UA_ERRNO));
        return UA_STATUSCODE_BADDISCONNECT;
    }

    /* Use select to wait and check if connected */
    if(error == -1 && (UA_ERRNO == UA_ERR_CONNECTION_PROGRESS)) {
        if(tcpConnection->iow.fd == UA_INVALID_SOCKET) {
            ev_io_init(&tcpConnection->iow, ClientNetworkLayerTCP_eventCallback, clientsockfd, EV_WRITE);
            tcpConnection->iow.data = data;
            tcpConnection->loop = (struct ev_loop*)UA_Client_getConfig(client)->externalEventLoop;
            ev_io_start(tcpConnection->loop, &tcpConnection->iow);
        }
    } else {
        connection->state = UA_CONNECTIONSTATE_ESTABLISHED;
        return UA_STATUSCODE_GOOD;
    }

#ifdef SO_NOSIGPIPE
    int val = 1;
    int sso_result = setsockopt(connection->sockfd, SOL_SOCKET,
                                SO_NOSIGPIPE, (void*)&val, sizeof(val));
    if(sso_result < 0)
    UA_LOG_WARNING(&config->logger, UA_LOGCATEGORY_NETWORK,
                    "Couldn't set SO_NOSIGPIPE");
#endif

    return UA_STATUSCODE_GOOD;
}

UA_Connection
UA_ClientConnectionTCP_init_libev(UA_ConnectionConfig config, const UA_String endpointUrl,
                                  UA_UInt32 timeout, UA_Logger *logger) {
    UA_initialize_architecture_network();

    UA_Connection connection;
    memset(&connection, 0, sizeof(UA_Connection));

    connection.state = UA_CONNECTIONSTATE_OPENING;
    connection.send = connection_write;
    connection.recv = connection_recv;
    connection.close = ClientNetworkLayerTCP_close;
    connection.free = ClientNetworkLayerTCP_free;
    connection.getSendBuffer = connection_getsendbuffer;
    connection.releaseSendBuffer = connection_releasesendbuffer;
    connection.releaseRecvBuffer = connection_releaserecvbuffer;

    TCPClientConnection *tcpClientConnection = (TCPClientConnection*) UA_malloc(
                    sizeof(TCPClientConnection));
    memset(tcpClientConnection, 0, sizeof(TCPClientConnection));
    tcpClientConnection->iow.fd = UA_INVALID_SOCKET;
    tcpClientConnection->logger = logger;
    connection.handle = (void*) tcpClientConnection;
    tcpClientConnection->timeout = timeout;
    UA_String hostnameString = UA_STRING_NULL;
    UA_String pathString = UA_STRING_NULL;
    UA_UInt16 port = 0;
    char hostname[512];
    tcpClientConnection->connStart = UA_DateTime_nowMonotonic();

    UA_StatusCode parse_retval = UA_parseEndpointUrl(&endpointUrl,
                    &hostnameString, &port, &pathString);
    if(parse_retval != UA_STATUSCODE_GOOD || hostnameString.length > 511) {
        UA_LOG_WARNING(logger, UA_LOGCATEGORY_NETWORK,
                       "Server url is invalid: %.*s",
                       (int)endpointUrl.length, endpointUrl.data);
        connection.state = UA_CONNECTIONSTATE_CLOSED;
        return connection;
    }
    memcpy(hostname, hostnameString.data, hostnameString.length);
    hostname[hostnameString.length] = 0;

    if(port == 0) {
        port = 4840;
        UA_LOG_INFO(logger, UA_LOGCATEGORY_NETWORK,
                    "No port defined, using default port %" PRIu16, port);
    }

    memset(&tcpClientConnection->hints, 0, sizeof(tcpClientConnection->hints));
    tcpClientConnection->hints.ai_family = AF_UNSPEC;
    tcpClientConnection->hints.ai_socktype = SOCK_STREAM;
    char portStr[6];
    UA_snprintf(portStr, 6, "%d", port);
    int error = UA_getaddrinfo(hostname, portStr, &tcpClientConnection->hints,
                    &tcpClientConnection->server);
    if(error != 0 || !tcpClientConnection->server) {
        UA_LOG_SOCKET_ERRNO_GAI_WRAP(UA_LOG_WARNING(logger, UA_LOGCATEGORY_NETWORK,
                                                    "DNS lookup of %s failed with error %s",
                                                    hostname, errno_str));
        connection.state = UA_CONNECTIONSTATE_CLOSED;
        return connection;
    }
    return connection;
}


#endif // UA_ENABLE_LIBEV
