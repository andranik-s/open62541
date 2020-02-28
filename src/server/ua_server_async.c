/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2019 (c) Fraunhofer IOSB (Author: Klaus Schick)
 *    Copyright 2019 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 */

#include <pthread.h>
#include "ua_server_internal.h"

#if UA_MULTITHREADING >= 100

/******************/
/* Async Services */
/******************/

UA_Service_async
UA_getAsyncService(const UA_DataType *requestType) {
    if(requestType->typeId.identifierType != UA_NODEIDTYPE_NUMERIC ||
            requestType->typeId.namespaceIndex != 0)
        return NULL;

    switch(requestType->typeId.identifier.numeric) {
#ifdef UA_ENABLE_METHODCALLS
    case UA_NS0ID_CALLREQUEST:
        return Service_Call_async;
#endif
    
    default:
        return NULL;
    }
}

/*****************/
/* Async Manager */
/*****************/

struct UA_AsyncRequest {
    TAILQ_ENTRY(UA_AsyncRequest) entry;
    UA_NodeId sessionId;
    UA_UInt32 requestId;
    const UA_DataType *requestType;
    const UA_RequestHeader *request;
    const UA_DataType *responseType;
    UA_ResponseHeader *response;
    UA_Service service;
};

typedef struct UA_AsyncRequest UA_AsyncRequest;

typedef TAILQ_HEAD(UA_AsyncRequestQueue, UA_AsyncRequest) UA_AsyncRequestQueue;

struct UA_AsyncManager {
    UA_Server *server;
    UA_AsyncRequestQueue requestQueue;        /* New operations for the workers */
    bool isStopping;
    pthread_mutex_t mutex;
    pthread_cond_t serviceCondition;
};

UA_AsyncManager *
UA_AsyncManager_new(UA_Server *server) {
    UA_AsyncManager *am = (UA_AsyncManager*)UA_calloc(1, sizeof(UA_AsyncManager));
    am->server = server;
    TAILQ_INIT(&am->requestQueue);
    pthread_mutex_init(&am->mutex, NULL);
    pthread_cond_init(&am->serviceCondition, NULL);
    return am;
}

void
UA_AsyncManager_stop(UA_AsyncManager *am) {
    pthread_mutex_lock(&am->mutex);
    am->isStopping = true;
    pthread_mutex_unlock(&am->mutex);
    pthread_cond_broadcast(&am->serviceCondition);
}

void
UA_AsyncManager_clear(UA_AsyncManager *am) {
    pthread_mutex_destroy(&am->mutex);
    pthread_cond_destroy(&am->serviceCondition);
}

UA_StatusCode
UA_AsyncManager_addAsyncRequest(UA_AsyncManager *am,
                                const UA_Session *session,
                                UA_UInt32 requestId,
                                const UA_DataType *requestType,
                                const UA_RequestHeader *request,
                                const UA_DataType *responseType,
                                UA_ResponseHeader *response,
                                UA_Service service) {
    UA_AsyncRequest *asyncRequest = (UA_AsyncRequest*)UA_calloc(1, sizeof(UA_AsyncRequest));
    UA_NodeId_copy(&session->sessionId, &asyncRequest->sessionId);
    asyncRequest->requestId = requestId;
    asyncRequest->requestType = requestType;
    asyncRequest->request = request;
    asyncRequest->responseType = responseType;
    asyncRequest->response = (UA_ResponseHeader*)UA_new(responseType);
    memcpy(asyncRequest->response, response, responseType->memSize);
    asyncRequest->service = service;

    pthread_mutex_lock(&am->mutex);
    TAILQ_INSERT_TAIL(&am->requestQueue, asyncRequest, entry);
    pthread_mutex_unlock(&am->mutex);

    pthread_cond_signal(&am->serviceCondition);

    /* We can clear response struct because service's results are
       going to be sent later when async part is comleted, but we should
       restore serviceResult code (which should be equal to
       UA_STATUSCODE_GOODCOMPLETESASYNCHRONOUSLY) */
    UA_init(response, responseType);
    response->serviceResult = asyncRequest->response->serviceResult;

    return UA_STATUSCODE_GOOD;
}

/******************/
/* Server Methods */
/******************/

static UA_StatusCode
setMethodNodeAsync(UA_Server *server, UA_Session *session,
                   UA_Node *node, UA_Boolean *isAsync) {
    UA_MethodNode *method = (UA_MethodNode*)node;
    if(method->nodeClass != UA_NODECLASS_METHOD)
        return UA_STATUSCODE_BADNODECLASSINVALID;
    method->async = *isAsync;
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_setMethodNodeAsync(UA_Server *server, const UA_NodeId id,
                             UA_Boolean isAsync) {
    return UA_Server_editNode(server, &server->adminSession, &id,
                              (UA_EditNodeCallback)setMethodNodeAsync, &isAsync);
}


UA_StatusCode
UA_Server_runAsync(UA_Server *server) {
    UA_AsyncManager *am = server->asyncManager;
    UA_AsyncRequest *request;
    while(true) {
        /* Wait for a new job */
        pthread_mutex_lock(&am->mutex);
        pthread_cond_wait(&am->serviceCondition, &am->mutex);
        if(am->isStopping) {
            /* We are shutting down */
            pthread_mutex_unlock(&am->mutex);
            break;
        }
        pthread_mutex_unlock(&am->mutex);
        /* Handle the job */
        while(true) {
            /* Get a request from the job queue */
            request = NULL;
            pthread_mutex_lock(&am->mutex);
            if(!TAILQ_EMPTY(&am->requestQueue)) {
                request = TAILQ_FIRST(&am->requestQueue);
                TAILQ_REMOVE(&am->requestQueue, request, entry);
            }
            pthread_mutex_unlock(&am->mutex);
            if(!request)
                break;
            /* Process the request */
            UA_LOCK(am->server->serviceMutex);
            UA_Session *session = UA_Server_getSessionById(am->server, &request->sessionId);
            request->service(server, session, request->request, request->response);
            UA_UNLOCK(am->server->serviceMutex);
            sendResponse(session->header.channel, request->requestId, request->request->requestHandle,
                         request->response, request->responseType);
        }
    }

    return UA_STATUSCODE_GOOD;
}

void
UA_Server_stopAsync(UA_Server *server) {
    UA_AsyncManager_stop(server->asyncManager);
}

#endif
