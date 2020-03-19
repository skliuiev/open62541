/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/.
 *
 *    Copyright 2014-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2014-2016 (c) Sten Grüner
 *    Copyright 2014, 2017 (c) Florian Palm
 *    Copyright 2016 (c) Oleksiy Vasylyev
 *    Copyright 2016-2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) frax2222
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 */

#include "ua_server_internal.h"
#include "ua_services.h"
#include "ua_services_discovery_internal.h"

void
Service_FindServers(UA_Server *server, UA_Session *session,
                    const UA_FindServersRequest *request,
                    UA_FindServersResponse *response) {
    UA_LOG_DEBUG_SESSION(&server->config.logger, session,
                         "Processing FindServersRequest");
    UA_LOCK_ASSERT(server->serviceMutex, 1);

#ifdef UA_ENABLE_DISCOVERY
    _Service_FindServers(server, session, request, response);
#else

    /* Return the server itself? */
    UA_Boolean foundSelf = false;
    if(request->serverUrisSize) {
        for(size_t i = 0; i < request->serverUrisSize; i++) {
            if(UA_String_equal(&request->serverUris[i],
                               &server->config.applicationDescription.applicationUri)) {
                foundSelf = true;
                break;
            }
        }
    } else {
        foundSelf = true;
    }

    if(!foundSelf)
        return;

    UA_ApplicationDescription *ad = UA_ApplicationDescription_new();
    if(!ad) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }

    UA_StatusCode retval = setApplicationDescriptionFromServer(ad, server);
    if(retval != UA_STATUSCODE_GOOD) {
        UA_ApplicationDescription_delete(ad);
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }

    response->servers = ad;
    response->serversSize = 1;
#endif
}

void
Service_GetEndpoints(UA_Server *server, UA_Session *session,
                     const UA_GetEndpointsRequest *request,
                     UA_GetEndpointsResponse *response) {
    UA_LOCK_ASSERT(server->serviceMutex, 1);

    /* If the client expects to see a specific endpointurl, mirror it back. If
       not, clone the endpoints with the discovery url of all networklayers. */
    const UA_String *endpointUrl = &request->endpointUrl;
    if(endpointUrl->length > 0) {
        UA_LOG_DEBUG_SESSION(
            &server->config.logger, session,
            "Processing GetEndpointsRequest with endpointUrl " UA_PRINTF_STRING_FORMAT,
            UA_PRINTF_STRING_DATA(*endpointUrl));
    } else {
        UA_LOG_DEBUG_SESSION(&server->config.logger, session,
                             "Processing GetEndpointsRequest with an empty endpointUrl");
    }

    /* test if the supported binary profile shall be returned */
    size_t reSize = sizeof(UA_Boolean) * server->config.endpointsSize;
    UA_STACKARRAY(UA_Boolean, relevant_endpoints, reSize);
    memset(relevant_endpoints, 0, reSize);
    size_t relevant_count = 0;
    if(request->profileUrisSize == 0) {
        for(size_t j = 0; j < server->config.endpointsSize; ++j)
            relevant_endpoints[j] = true;
        relevant_count = server->config.endpointsSize;
    } else {
        for(size_t j = 0; j < server->config.endpointsSize; ++j) {
            for(size_t i = 0; i < request->profileUrisSize; ++i) {
                if(!UA_String_equal(&request->profileUris[i],
                                    &server->config.endpoints[j].transportProfileUri))
                    continue;
                relevant_endpoints[j] = true;
                ++relevant_count;
                break;
            }
        }
    }

    if(relevant_count == 0) {
        response->endpointsSize = 0;
        return;
    }

    /* Clone the endpoint for each networklayer? */
    size_t clone_times = 1;
    UA_Boolean nl_endpointurl = false;
    if(endpointUrl->length == 0) {
        clone_times = server->config.networkLayersSize;
        nl_endpointurl = true;
    }

    response->endpoints = (UA_EndpointDescription *)UA_Array_new(
        relevant_count * clone_times, &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    if(!response->endpoints) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADOUTOFMEMORY;
        return;
    }
    response->endpointsSize = relevant_count * clone_times;

    size_t k = 0;
    UA_StatusCode retval;
    for(size_t i = 0; i < clone_times; ++i) {
        if(nl_endpointurl)
            endpointUrl = &server->config.networkLayers[i].discoveryUrl;
        for(size_t j = 0; j < server->config.endpointsSize; ++j) {
            if(!relevant_endpoints[j])
                continue;
            retval = UA_EndpointDescription_copy(&server->config.endpoints[j],
                                                 &response->endpoints[k]);
            if(retval != UA_STATUSCODE_GOOD)
                goto error;
            retval = UA_String_copy(endpointUrl, &response->endpoints[k].endpointUrl);
            if(retval != UA_STATUSCODE_GOOD)
                goto error;
            retval = UA_Array_copy(endpointUrl, 1,
                                   (void **)&response->endpoints[k].server.discoveryUrls,
                                   &UA_TYPES[UA_TYPES_STRING]);
            if(retval != UA_STATUSCODE_GOOD)
                goto error;
            response->endpoints[k].server.discoveryUrlsSize = 1;
            ++k;
        }
    }

    return;
error:
    response->responseHeader.serviceResult = retval;
    UA_Array_delete(response->endpoints, response->endpointsSize,
                    &UA_TYPES[UA_TYPES_ENDPOINTDESCRIPTION]);
    response->endpoints = NULL;
    response->endpointsSize = 0;
}

void
Service_RegisterServer(UA_Server *server, UA_Session *session,
                       const UA_RegisterServerRequest *request,
                       UA_RegisterServerResponse *response) {
    UA_LOG_DEBUG_SESSION(&server->config.logger, session,
                         "Processing RegisterServerRequest");
    UA_LOCK_ASSERT(server->serviceMutex, 1);
#ifdef UA_ENABLE_DISCOVERY
    _Service_RegisterServer(server, session, request, response);
#else
    response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTIMPLEMENTED;
#endif
}

void
Service_RegisterServer2(UA_Server *server, UA_Session *session,
                        const UA_RegisterServer2Request *request,
                        UA_RegisterServer2Response *response) {
    UA_LOG_DEBUG_SESSION(&server->config.logger, session,
                         "Processing RegisterServer2Request");
    UA_LOCK_ASSERT(server->serviceMutex, 1);
#ifdef UA_ENABLE_DISCOVERY
    _Service_RegisterServer2(server, session, request, response);
#else
    response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTIMPLEMENTED;
#endif
}