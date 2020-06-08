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
    struct ev_loop *loop;
    UA_UInt16 port;
    UA_UInt16 maxConnections;
    LIST_HEAD(, ConnectionEntry) connections;
    UA_UInt16 connectionsSize;
    UA_ServerNetworkLayer *nl;
    UA_Server *server;
} ServerNetworkLayerTCP_libev;

static void
ServerNetworkLayerTCP_freeConnection(UA_Connection *connection) {
    UA_free(connection);
}

/* This performs only 'shutdown'. 'close' is called when the shutdown
 * socket is returned from select. */
static void
ServerNetworkLayerTCP_close(UA_Connection *connection) {
    if(connection->state == UA_CONNECTIONSTATE_CLOSED)
        return;
    UA_shutdown((UA_SOCKET)connection->sockfd, 2);
    connection->state = UA_CONNECTIONSTATE_CLOSED;
}

static UA_Boolean
purgeFirstConnectionWithoutChannel(ServerNetworkLayerTCP_libev *layer) {
    ConnectionEntry *e;
    LIST_FOREACH(e, &layer->connections, pointers) {
        if(e->connection.channel == NULL) {
            LIST_REMOVE(e, pointers);
            layer->connectionsSize--;
            UA_close(e->connection.sockfd);
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
    ServerNetworkLayerTCP_libev *layer = (ServerNetworkLayerTCP_libev*)e->connection.handle;
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
    memset(c, 0, sizeof(UA_Connection));
    c->sockfd = newsockfd;
    c->handle = layer;
    c->send = connection_write;
    c->close = ServerNetworkLayerTCP_close;
    c->free = ServerNetworkLayerTCP_freeConnection;
    c->getSendBuffer = connection_getsendbuffer;
    c->releaseSendBuffer = connection_releasesendbuffer;
    c->releaseRecvBuffer = connection_releaserecvbuffer;
    c->state = UA_CONNECTIONSTATE_OPENING;
    c->openingDate = UA_DateTime_nowMonotonic();

    /* Add to the linked list */
    LIST_INSERT_HEAD(&layer->connections, e, pointers);
    UA_ServerNetworkLayer *nl = layer->nl;
    if(nl->statistics) {
        nl->statistics->currentConnectionCount++;
        nl->statistics->cumulatedConnectionCount++;
    }

    struct ev_io *neww = (struct ev_io*)UA_malloc(sizeof(struct ev_io));
    ev_io_init(neww, &layerRecvCallback, newsockfd, EV_READ);
    neww->data = e;
    ev_io_start(loop, neww);
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

    struct ev_io *w = (struct ev_io*)UA_malloc(sizeof(struct ev_io));
    ev_io_init(w, layerAcceptCallback, listener, EV_READ);
    w->data = (void*)layer;
    ev_io_start(layer->loop, w);

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
}

static void
ServerNetworkLayerTCP_libev_deleteMembers(UA_ServerNetworkLayer *nl)
{
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

#endif // UA_ENABLE_LIBEV
