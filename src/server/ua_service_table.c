#include <open62541/server.h>
#include <open62541/types_generated_encoding_binary.h>

#include "ua_server_internal.h"
#include "ua_service_table_internal.h"

UA_StatusCode
UA_Server_AddService(UA_Server *server, UA_UInt32 requestNodeId, UA_UInt32 requestTypeId,
                     UA_UInt32 responseTypeId, UA_ServiceCallback service,
                     UA_Boolean requiresSession) {
    UA_ServiceTable *table = &server->serviceTable;

    if(0 == table->size || NULL == table->entries) {
        table->entries = UA_malloc(sizeof(struct UA_ServiceTableEntry));
        if(NULL == table->entries) {
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        table->entries[table->size].requestNodeId = requestNodeId;
        table->entries[table->size].requestTypeId = requestTypeId;
        table->entries[table->size].responceTypeId = responseTypeId;
        table->entries[table->size].service = service;
        table->entries[table->size].requiresSession = requiresSession;
        ++table->size;
        return UA_STATUSCODE_GOOD;
    }

    if(NULL != server->serviceTable.entries &&
       table->size == sizeof(*table->entries) / sizeof(table->entries[0])) {
        table->entries = UA_realloc(table->entries, sizeof(struct UA_ServiceTableEntry) *
                                                        (table->size + 1));
        if(NULL == table->entries) {
            return UA_STATUSCODE_BADOUTOFMEMORY;
        }
        table->entries[table->size].requestNodeId = requestNodeId;
        table->entries[table->size].requestTypeId = requestTypeId;
        table->entries[table->size].responceTypeId = responseTypeId;
        table->entries[table->size].service = service;
        table->entries[table->size].requiresSession = requiresSession;
        ++table->size;
        return UA_STATUSCODE_GOOD;
    }
    return UA_STATUSCODE_GOOD;
}

void
UA_Server_DispatchService(UA_Server *server, const UA_UInt32 requestNodeId,
                          const UA_DataType **requestType,
                          const UA_DataType **responseType, UA_Service *service,
                          UA_Boolean *requiresSession) {
    UA_ServiceTable *table = &server->serviceTable;
    for(int i = 0; i < table->size; ++i) {
        UA_ServiceTableEntry entry = table->entries[i];
        if(requestNodeId == table->entries[i].requestNodeId) {
            *service = (UA_Service)table->entries[i].service;
            *requestType = &UA_TYPES[table->entries[i].requestTypeId];
            *responseType = &UA_TYPES[table->entries[i].responceTypeId];
            *requiresSession = table->entries[i].requiresSession;
        }
    }
}

void
UA_ServiceTable_clean(UA_ServiceTable *serviceTable) {
    if(NULL != serviceTable || NULL != serviceTable->entries) {
        UA_free(serviceTable->entries);
        serviceTable->size = 0;
    }
}