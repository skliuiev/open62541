/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2017 (c) Thomas Stalder, Blue Time Concept SA
 */

#include "ua_server_internal.h"
#include "ua_services.h"
#include "ua_services_discovery_internal.h"

void Service_FindServersOnNetwork(UA_Server *server, UA_Session *session,
                                  const UA_FindServersOnNetworkRequest *request,
                                  UA_FindServersOnNetworkResponse *response) {
    UA_LOG_DEBUG_SESSION(&server->config.logger, session,
                         "Processing FindServersOnNetworkRequest");
    UA_LOCK_ASSERT(server->serviceMutex, 1);
    #if defined(UA_ENABLE_DISCOVERY) && defined(UA_ENABLE_DISCOVERY_MULTICAST)
        _Service_FindServersOnNetwork(server, session, request, response);
    #else
        response->responseHeader.serviceResult = UA_STATUSCODE_BADNOTIMPLEMENTED;
    #endif                       
}
