/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. 
 *
 *    Copyright 2014-2017 (c) Fraunhofer IOSB (Author: Julius Pfrommer)
 *    Copyright 2014, 2017 (c) Florian Palm
 *    Copyright 2015 (c) Oleksiy Vasylyev
 *    Copyright 2017 (c) Stefan Profanter, fortiss GmbH
 *    Copyright 2017 (c) Mark Giraud, Fraunhofer IOSB
 */

#include "ua_server_internal.h"
#include "ua_services.h"

#ifndef container_of
#define container_of(ptr, type, member) \
    (type *)((uintptr_t)ptr - offsetof(type,member))
#endif

static void
removeSecureChannelCallback(void *_, channel_entry *entry) {
    UA_SecureChannel_deleteMembers(&entry->channel);
}

static void
removeSecureChannel(UA_Server *server, channel_entry *entry,
                    UA_DiagnosticEvent event) {
    /* Close the SecureChannel */
    UA_SecureChannel_close(&entry->channel);

    /* Detach the channel */
    TAILQ_REMOVE(&server->channels, entry, pointers);

    /* Update the statistics */
    UA_SecureChannelStatistics *scs = &server->serverStats.scs;
    UA_atomic_subSize(&scs->currentChannelCount, 1);
    switch(event) {
    case UA_DIAGNOSTICEVENT_CLOSE:
        break;
    case UA_DIAGNOSTICEVENT_TIMEOUT:
        UA_atomic_addSize(&scs->channelTimeoutCount, 1);
        break;
    case UA_DIAGNOSTICEVENT_PURGE:
        UA_atomic_addSize(&scs->channelPurgeCount, 1);
        break;
    case UA_DIAGNOSTICEVENT_REJECT:
    case UA_DIAGNOSTICEVENT_SECURITYREJECT:
        UA_atomic_addSize(&scs->rejectedChannelCount, 1);
        break;
    case UA_DIAGNOSTICEVENT_ABORT:
        UA_atomic_addSize(&scs->channelAbortCount, 1);
        break;
    default:
        UA_assert(false);
        break;
    }

    /* Add a delayed callback to remove the channel when the currently
     * scheduled jobs have completed */
    entry->cleanupCallback.callback = (UA_ApplicationCallback)removeSecureChannelCallback;
    entry->cleanupCallback.application = NULL;
    entry->cleanupCallback.data = entry;
    UA_WorkQueue_enqueueDelayed(&server->workQueue, &entry->cleanupCallback);
}

void
UA_Server_deleteSecureChannels(UA_Server *server) {
    channel_entry *entry, *temp;
    TAILQ_FOREACH_SAFE(entry, &server->channels, pointers, temp)
        removeSecureChannel(server, entry, UA_DIAGNOSTICEVENT_CLOSE);
}

/* remove channels that were not renewed or who have no connection attached */
void
UA_Server_cleanupTimedOutSecureChannels(UA_Server *server,
                                        UA_DateTime nowMonotonic) {
    channel_entry *entry, *temp;
    TAILQ_FOREACH_SAFE(entry, &server->channels, pointers, temp) {
        /* The channel was closed internally */
        if(entry->channel.state == UA_SECURECHANNELSTATE_CLOSED ||
           !entry->channel.connection) {
            removeSecureChannel(server, entry, UA_DIAGNOSTICEVENT_CLOSE);
            continue;
        }

        /* The channel has timed out */
        UA_DateTime timeout =
            entry->channel.securityToken.createdAt +
            (UA_DateTime)(entry->channel.securityToken.revisedLifetime * UA_DATETIME_MSEC);
        if(timeout < nowMonotonic) {
            UA_LOG_INFO_CHANNEL(&server->config.logger, &entry->channel,
                                "SecureChannel has timed out");
            removeSecureChannel(server, entry, UA_DIAGNOSTICEVENT_TIMEOUT);
        }
    }
}

/* remove the first channel that has no session attached */
static UA_Boolean
purgeFirstChannelWithoutSession(UA_Server *server) {
    channel_entry *entry;
    TAILQ_FOREACH(entry, &server->channels, pointers) {
        if(entry->channel.session)
            continue;
        UA_LOG_INFO_CHANNEL(&server->config.logger, &entry->channel,
                            "Channel was purged since maxSecureChannels was "
                            "reached and channel had no session attached");
        removeSecureChannel(server, entry, UA_DIAGNOSTICEVENT_PURGE);
        return true;
    }
    return false;
}

UA_StatusCode
UA_Server_createSecureChannel(UA_Server *server, UA_Connection *connection) {
    /* connection already has a channel attached. */
    if(connection->channel != NULL)
        return UA_STATUSCODE_BADINTERNALERROR;

    /* Check if there exists a free SC, otherwise try to purge one SC without a
     * session the purge has been introduced to pass CTT, it is not clear what
     * strategy is expected here */
    if(server->serverStats.scs.currentChannelCount >= server->config.maxSecureChannels &&
       !purgeFirstChannelWithoutSession(server))
        return UA_STATUSCODE_BADOUTOFMEMORY;

    UA_LOG_INFO(&server->config.logger, UA_LOGCATEGORY_SECURECHANNEL,
                "Creating a new SecureChannel");

    channel_entry *entry = (channel_entry *)UA_malloc(sizeof(channel_entry));
    if(!entry)
        return UA_STATUSCODE_BADOUTOFMEMORY;

    /* Channel state is fresh (0) */
    /* TODO: Use the connection config from the correct network layer */
    UA_SecureChannel_init(&entry->channel,
                          &server->config.networkLayers[0].localConnectionConfig);
    entry->channel.securityToken.channelId = 0;
    entry->channel.securityToken.createdAt = UA_DateTime_nowMonotonic();
    entry->channel.securityToken.revisedLifetime = server->config.maxSecurityTokenLifetime;

    TAILQ_INSERT_TAIL(&server->channels, entry, pointers);
    UA_Connection_attachSecureChannel(connection, &entry->channel);
    UA_atomic_addSize(&server->serverStats.scs.currentChannelCount, 1);
    UA_atomic_addSize(&server->serverStats.scs.cumulatedChannelCount, 1);
    return UA_STATUSCODE_GOOD;
}

UA_StatusCode
UA_Server_configSecureChannel(UA_Server *server, UA_SecureChannel *channel,
                              const UA_AsymmetricAlgorithmSecurityHeader *asymHeader) {
    /* Iterate over available endpoints and choose the correct one */
    UA_SecurityPolicy *securityPolicy = NULL;
    for(size_t i = 0; i < server->config.securityPoliciesSize; ++i) {
        UA_SecurityPolicy *policy = &server->config.securityPolicies[i];
        if(!UA_ByteString_equal(&asymHeader->securityPolicyUri, &policy->policyUri))
            continue;

        UA_StatusCode retval = policy->asymmetricModule.
            compareCertificateThumbprint(policy, &asymHeader->receiverCertificateThumbprint);
        if(retval != UA_STATUSCODE_GOOD)
            continue;

        /* We found the correct policy (except for security mode). The endpoint
         * needs to be selected by the client / server to match the security
         * mode in the endpoint for the session. */
        securityPolicy = policy;
        break;
    }

    if(!securityPolicy)
        return UA_STATUSCODE_BADSECURITYPOLICYREJECTED;

    /* Create the channel context and parse the sender (remote) certificate used for the
     * secureChannel. */
    UA_StatusCode retval =
        UA_SecureChannel_setSecurityPolicy(channel, securityPolicy,
                                           &asymHeader->senderCertificate);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    channel->securityToken.tokenId = server->lastTokenId++;
    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_SecureChannelManager_open(UA_Server *server, UA_SecureChannel *channel,
                             const UA_OpenSecureChannelRequest *request,
                             UA_OpenSecureChannelResponse *response) {
    if(channel->state != UA_SECURECHANNELSTATE_FRESH) {
        UA_LOG_ERROR_CHANNEL(&server->config.logger, channel,
                             "Called open on already open or closed channel");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    if(request->securityMode != UA_MESSAGESECURITYMODE_NONE &&
       UA_ByteString_equal(&channel->securityPolicy->policyUri, &UA_SECURITY_POLICY_NONE_URI)) {
        return UA_STATUSCODE_BADSECURITYMODEREJECTED;
    }

    channel->securityMode = request->securityMode;
    channel->securityToken.channelId = server->lastChannelId++;
    channel->securityToken.createdAt = UA_DateTime_now();

    /* Set the lifetime. Lifetime 0 -> set the maximum possible */
    channel->securityToken.revisedLifetime =
        (request->requestedLifetime > server->config.maxSecurityTokenLifetime) ?
        server->config.maxSecurityTokenLifetime : request->requestedLifetime;
    if(channel->securityToken.revisedLifetime == 0)
        channel->securityToken.revisedLifetime = server->config.maxSecurityTokenLifetime;

    /* Set the nonces and generate the keys */
    UA_StatusCode retval = UA_ByteString_copy(&request->clientNonce, &channel->remoteNonce);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_SecureChannel_generateLocalNonce(channel);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_SecureChannel_generateNewKeys(channel);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Set the response */
    retval = UA_ByteString_copy(&channel->localNonce, &response->serverNonce);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_ChannelSecurityToken_copy(&channel->securityToken, &response->securityToken);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    response->responseHeader.timestamp = UA_DateTime_now();
    response->responseHeader.requestHandle = request->requestHeader.requestHandle;

    /* The channel is open */
    channel->state = UA_SECURECHANNELSTATE_OPEN;

    /* Reset the internal creation date to the monotonic clock */
    channel->securityToken.createdAt = UA_DateTime_nowMonotonic();

    return UA_STATUSCODE_GOOD;
}

static UA_StatusCode
UA_SecureChannelManager_renew(UA_Server *server, UA_SecureChannel *channel,
                              const UA_OpenSecureChannelRequest *request,
                              UA_OpenSecureChannelResponse *response) {
    if(channel->state != UA_SECURECHANNELSTATE_OPEN) {
        UA_LOG_ERROR_CHANNEL(&server->config.logger, channel,
                             "Called renew on channel which is not open");
        return UA_STATUSCODE_BADINTERNALERROR;
    }

    /* If no security token is already issued */
    if(channel->nextSecurityToken.tokenId == 0) {
        channel->nextSecurityToken.channelId = channel->securityToken.channelId;
        channel->nextSecurityToken.tokenId = server->lastTokenId++;
        channel->nextSecurityToken.createdAt = UA_DateTime_now();
        channel->nextSecurityToken.revisedLifetime =
            (request->requestedLifetime > server->config.maxSecurityTokenLifetime) ?
            server->config.maxSecurityTokenLifetime : request->requestedLifetime;
        if(channel->nextSecurityToken.revisedLifetime == 0) /* lifetime 0 -> return the max lifetime */
            channel->nextSecurityToken.revisedLifetime = server->config.maxSecurityTokenLifetime;
    }

    /* Replace the nonces */
    UA_ByteString_deleteMembers(&channel->remoteNonce);
    UA_StatusCode retval = UA_ByteString_copy(&request->clientNonce, &channel->remoteNonce);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_SecureChannel_generateLocalNonce(channel);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Set the response */
    response->responseHeader.requestHandle = request->requestHeader.requestHandle;
    retval = UA_ByteString_copy(&channel->localNonce, &response->serverNonce);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    retval = UA_ChannelSecurityToken_copy(&channel->nextSecurityToken, &response->securityToken);
    if(retval != UA_STATUSCODE_GOOD)
        return retval;

    /* Reset the internal creation date to the monotonic clock */
    channel->nextSecurityToken.createdAt = UA_DateTime_nowMonotonic();
    return UA_STATUSCODE_GOOD;
}

void
UA_Server_closeSecureChannel(UA_Server *server, UA_SecureChannel *channel,
                             UA_DiagnosticEvent event) {
    removeSecureChannel(server, container_of(channel, channel_entry, channel), event);
}

void
Service_OpenSecureChannel(UA_Server *server, UA_SecureChannel *channel,
                          const UA_OpenSecureChannelRequest *request,
                          UA_OpenSecureChannelResponse *response) {
    if(request->requestType == UA_SECURITYTOKENREQUESTTYPE_RENEW) {
        /* Renew the channel */
        response->responseHeader.serviceResult =
            UA_SecureChannelManager_renew(server, channel, request, response);

        /* Logging */
        if(response->responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
            UA_LOG_DEBUG_CHANNEL(&server->config.logger, channel,
                                 "SecureChannel renewed");
        } else {
            UA_LOG_DEBUG_CHANNEL(&server->config.logger, channel,
                                 "Renewing SecureChannel failed");
        }
        return;
    }

    /* Must be ISSUE or RENEW */
    if(request->requestType != UA_SECURITYTOKENREQUESTTYPE_ISSUE) {
        response->responseHeader.serviceResult = UA_STATUSCODE_BADINTERNALERROR;
        return;
    }

    /* Open the channel */
    response->responseHeader.serviceResult =
        UA_SecureChannelManager_open(server, channel, request, response);

    /* Logging */
    if(response->responseHeader.serviceResult == UA_STATUSCODE_GOOD) {
        UA_LOG_INFO_CHANNEL(&server->config.logger, channel,
                            "Opened SecureChannel");
    } else {
        UA_LOG_INFO_CHANNEL(&server->config.logger, channel,
                            "Opening a SecureChannel failed");
    }
}

/* The server does not send a CloseSecureChannel response */
void
Service_CloseSecureChannel(UA_Server *server, UA_SecureChannel *channel) {
    UA_LOG_INFO_CHANNEL(&server->config.logger, channel, "CloseSecureChannel");
    removeSecureChannel(server, container_of(channel, channel_entry, channel),
                        UA_DIAGNOSTICEVENT_CLOSE);
}
