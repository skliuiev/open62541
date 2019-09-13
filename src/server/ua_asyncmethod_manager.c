/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2019 (c) Fraunhofer IOSB (Author: Klaus Schick)
 * based on
 *    Copyright 2014-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2014, 2017 (c) Florian Palm
 *    Copyright 2015 (c) Sten Grüner
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 */

#include "ua_asyncmethod_manager.h"
#include "ua_server_internal.h"
#include "ua_subscription.h"

#if UA_MULTITHREADING >= 100

UA_StatusCode
UA_AsyncMethodManager_init(UA_AsyncMethodManager *amm, UA_Server *server) {
    LIST_INIT(&amm->asyncmethods);
    amm->currentCount = 0;
    amm->server = server;
    return UA_STATUSCODE_GOOD;
}

void UA_AsyncMethodManager_deleteMembers(UA_AsyncMethodManager *amm) {
    asyncmethod_list_entry *current, *temp;
    LIST_FOREACH_SAFE(current, &amm->asyncmethods, pointers, temp) {
        UA_AsyncMethodManager_removeEntry(amm, current);
    }
}

asyncmethod_list_entry*
UA_AsyncMethodManager_getById(UA_AsyncMethodManager *amm, const UA_UInt32 requestId, const UA_NodeId *sessionId) {
    asyncmethod_list_entry *current = NULL;
    LIST_FOREACH(current, &amm->asyncmethods, pointers) {
        if ((current->requestId == requestId) && UA_NodeId_equal(current->sessionId, sessionId))
            return current;
    }
    return NULL;
}

UA_StatusCode
UA_AsyncMethodManager_createEntry(UA_AsyncMethodManager *amm, const UA_NodeId *sessionId,
    const UA_UInt32 channelId, const UA_UInt32 requestId, const UA_UInt32 requestHandle,
    const UA_DataType *responseType, const UA_UInt32 nCountdown) {
    asyncmethod_list_entry *newentry = (asyncmethod_list_entry*)UA_calloc(1, sizeof(asyncmethod_list_entry));
    if (!newentry) {
        UA_LOG_ERROR(&amm->server->config.logger, UA_LOGCATEGORY_SERVER,
            "UA_AsyncMethodManager_createEntry: Mem alloc failed.");
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    UA_LOG_DEBUG(&amm->server->config.logger, UA_LOGCATEGORY_SERVER,
        "UA_AsyncMethodManager_createEntry: Chan: %u. Req# %u", channelId, requestId);
    UA_atomic_addUInt32(&amm->currentCount, 1);
    newentry->requestId = requestId;
    newentry->sessionId = sessionId;
    newentry->requestHandle = requestHandle;
    newentry->responseType = responseType;
    newentry->nCountdown = nCountdown;
    newentry->m_tDispatchTime = UA_DateTime_now();
    UA_CallResponse_init(&newentry->response);
    newentry->response.results = (UA_CallMethodResult*)UA_calloc(nCountdown, sizeof(UA_CallMethodResult));
    newentry->response.resultsSize = nCountdown;
    if (newentry->response.results == NULL)
    {
        UA_LOG_ERROR(&amm->server->config.logger, UA_LOGCATEGORY_SERVER,
            "UA_AsyncMethodManager_createEntry: Mem alloc failed.");
        UA_free(newentry);
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    /* Set the StatusCode to timeout by default. Will be overwritten when the
     * result is set. */
    for(size_t i = 0; i < nCountdown; i++)
        newentry->response.results[i].statusCode = UA_STATUSCODE_BADTIMEOUT;

    LIST_INSERT_HEAD(&amm->asyncmethods, newentry, pointers);
    return UA_STATUSCODE_GOOD;
}

/* remove entry and free all allocated data */
UA_StatusCode
UA_AsyncMethodManager_removeEntry(UA_AsyncMethodManager *amm, asyncmethod_list_entry *current) {
    if (current) {
        LIST_REMOVE(current, pointers);
        UA_atomic_subUInt32(&amm->currentCount, 1);
        UA_CallResponse_deleteMembers(&current->response);
        UA_free(current);
    }
    UA_LOG_DEBUG(&amm->server->config.logger, UA_LOGCATEGORY_SERVER,
                 "UA_AsyncMethodManager_removeEntry: # of open CallRequests: %u", amm->currentCount);
    return UA_STATUSCODE_GOOD;
}

/* Check if CallRequest is waiting way too long (120s) */
void
UA_AsyncMethodManager_checkTimeouts(UA_Server *server, UA_AsyncMethodManager *amm) {
    asyncmethod_list_entry* current = NULL;
    asyncmethod_list_entry* current_tmp = NULL;
    LIST_FOREACH_SAFE(current, &amm->asyncmethods, pointers, current_tmp) {
        UA_DateTime tNow = UA_DateTime_now();
        UA_DateTime tReq = current->m_tDispatchTime;
        UA_DateTime diff = tNow - tReq;

        /* The calls are all done or the timeout has not passed */
        if (current->nCountdown == 0 || server->config.asyncCallRequestTimeout <= 0.0 ||
            diff <= server->config.asyncCallRequestTimeout * (UA_DateTime)UA_DATETIME_MSEC)
            continue;

        /* We got an unfinished CallResponse waiting way too long for being finished.
         * Set the remaining StatusCodes and return. */
        UA_LOG_WARNING(&server->config.logger, UA_LOGCATEGORY_SERVER, "UA_AsyncMethodManager_checkTimeouts: "
                       "RequestCall #%u was removed due to a timeout (120s)", current->requestId);

        /* Get the session */
        UA_LOCK(server->serviceMutex);
        UA_Session* session = UA_SessionManager_getSessionById(&amm->server->sessionManager, current->sessionId);
        UA_UNLOCK(server->serviceMutex);
        if(!session) {
            UA_LOG_WARNING(&amm->server->config.logger, UA_LOGCATEGORY_SERVER,
                           "UA_AsyncMethodManager_checkTimeouts: Session is gone");
            goto remove;
        }

        /* Check the channel */
        if(!session->header.channel) {
            UA_LOG_WARNING(&server->config.logger, UA_LOGCATEGORY_SERVER,
                           "UA_Server_InsertMethodResponse: Channel is gone");
            goto remove;
        }

        /* Okay, here we go, send the UA_CallResponse */
        sendResponse(session->header.channel, current->requestId, current->requestHandle,
                     (UA_ResponseHeader*)&current->response.responseHeader, current->responseType);
        UA_LOG_DEBUG(&server->config.logger, UA_LOGCATEGORY_SERVER,
                     "UA_Server_SendResponse: Response for Req# %u sent", current->requestId);
    remove:
        UA_AsyncMethodManager_removeEntry(amm, current);
    }
}

#endif
