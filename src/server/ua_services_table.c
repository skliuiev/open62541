#include <open62541/server.h>
#include <open62541/types_generated_encoding_binary.h>

#include "ua_server_internal.h"
#include "ua_services_table_internal.h"

UA_StatusCode
UA_Server_AddService(UA_Server *server, UA_UInt32 requestNodeId, UA_UInt32 requestTypeId,
                     UA_UInt32 responseTypeId, UA_ServiceCallback service,
                     UA_Boolean requiresSession) {
    UA_ServiceTable *table = &server->serviceTable;

    UA_ServiceTableEntry *it = NULL;

    LIST_FOREACH(it, &table->services, pointers) {
        if (requestNodeId == it->requestNodeId) {
            return UA_STATUSCODE_BADINTERNALERROR;
        }
    }

    UA_ServiceTableEntry *entry = (UA_ServiceTableEntry *)UA_malloc(sizeof(struct UA_ServiceTableEntry));

    if (NULL == entry) {
        return UA_STATUSCODE_BADOUTOFMEMORY;
    }

    entry->requestNodeId = requestNodeId;
    entry->requestTypeId = requestTypeId;
    entry->responceTypeId = responseTypeId;
    entry->requiresSession = requiresSession;
    entry->service = service;

    LIST_INSERT_HEAD(&table->services, entry, pointers);

    return UA_STATUSCODE_GOOD;
}

void
UA_Server_DispatchService(UA_Server *server, const UA_UInt32 requestNodeId,
                          const UA_DataType **requestType,
                          const UA_DataType **responseType, UA_Service *service,
                          UA_Boolean *requiresSession) {
    UA_ServiceTable *table = &server->serviceTable;

    UA_ServiceTableEntry *it = NULL;

    LIST_FOREACH(it, &table->services, pointers) {
        if (requestNodeId == it->requestNodeId) {
            *service = (UA_Service)it->service;
            *requestType = &UA_TYPES[it->requestTypeId];
            *responseType = &UA_TYPES[it->responceTypeId];
            *requiresSession = it->requiresSession;
        }
    }
}

void
UA_ServiceTable_init(UA_ServiceTable *table) {
    if (NULL == table) {
        return;
    }

    LIST_INIT(&table->services);
}

void
UA_ServiceTable_clean(UA_ServiceTable *table) {

    if (NULL == table) {
        return;
    }

	UA_ServiceTableEntry *it_temp, *it;
	LIST_FOREACH_SAFE(it, &table->services, pointers, it_temp) {
		LIST_REMOVE(it, pointers);
		UA_free(it);
	}
}
