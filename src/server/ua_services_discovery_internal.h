#ifndef UA_SERVICE_DISCOVERY_INTERNAL_H_
#define UA_SERVICE_DISCOVERY_INTERNAL_H_

#include "ua_services.h"

UA_StatusCode
setApplicationDescriptionFromServer(UA_ApplicationDescription *target,
                                    const UA_Server *server);

#ifdef UA_ENABLE_DISCOVERY

_UA_BEGIN_DECLS
void
_Service_FindServers(UA_Server *server, UA_Session *session,
                     const UA_FindServersRequest *request,
                     UA_FindServersResponse *response);

#ifdef UA_ENABLE_DISCOVERY_MULTICAST
void
_Service_FindServersOnNetwork(UA_Server *server, UA_Session *session,
                              const UA_FindServersOnNetworkRequest *request,
                              UA_FindServersOnNetworkResponse *response);
#endif

void
_Service_RegisterServer(UA_Server *server, UA_Session *session,
                        const UA_RegisterServerRequest *request,
                        UA_RegisterServerResponse *response);

void
_Service_RegisterServer2(UA_Server *server, UA_Session *session,
                         const UA_RegisterServer2Request *request,
                         UA_RegisterServer2Response *response);

_UA_END_DECLS

#endif

#endif /* UA_SERVICE_DISCOVERY_INTERNAL_H_ */