#ifndef UA_SERVICES_TABLE_H_
#define UA_SERVICES_TABLE_H_

#include <open62541/config.h>
#include "ua_services.h"
#include "open62541_queue.h"

_UA_BEGIN_DECLS

struct UA_ServiceTableEntry;
typedef struct UA_ServiceTableEntry UA_ServiceTableEntry;

struct UA_ServiceTable;
typedef struct UA_ServiceTable UA_ServiceTable;

struct UA_ServiceTableEntry {
    UA_UInt32 requestNodeId;
    UA_UInt32 requestTypeId;
    UA_UInt32 responceTypeId;
    UA_ServiceCallback service;
    UA_Boolean requiresSession;
    LIST_ENTRY(UA_ServiceTableEntry) pointers;
};

struct UA_ServiceTable {
    LIST_HEAD(ServiceTable, UA_ServiceTableEntry) services;
};

void
UA_Server_DispatchService(UA_Server *server, const UA_UInt32 requestNodeId,
                          const UA_DataType **requestType,
                          const UA_DataType **responseType, UA_Service *service,
                          UA_Boolean *requiresSession);

void
UA_ServiceTable_init(UA_ServiceTable *table);

void
UA_ServiceTable_clean(UA_ServiceTable *table);

_UA_END_DECLS

#endif
