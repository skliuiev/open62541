/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at http://mozilla.org/MPL/2.0/. */

#include <open62541/types.h>
#include <open62541/types_generated_handling.h>

#include "check.h"

START_TEST(parseGuid) {
    UA_Guid guid = UA_GUID("09087e75-8e5e-499b-954f-f2a9603db28a");
    ck_assert_int_eq(guid.data1, 151551605);
} END_TEST

START_TEST(parseNodeIdNumeric) {
    UA_NodeId id = UA_NODEID("i=13");
    ck_assert_int_eq(id.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.identifier.numeric, 13);
    ck_assert_int_eq(id.namespaceIndex, 0);
} END_TEST

START_TEST(parseNodeIdNumeric2) {
    UA_NodeId id = UA_NODEID("ns=10;i=1");
    ck_assert_int_eq(id.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.identifier.numeric, 1);
    ck_assert_int_eq(id.namespaceIndex, 10);
} END_TEST

START_TEST(parseNodeIdString) {
    UA_NodeId id = UA_NODEID("ns=10;s=Hello:World");
    ck_assert_int_eq(id.identifierType, UA_NODEIDTYPE_STRING);
    ck_assert_int_eq(id.namespaceIndex, 10);
    UA_String strid = UA_STRING("Hello:World");
    ck_assert(UA_String_equal(&id.identifier.string, &strid));
    UA_NodeId_clear(&id);
} END_TEST

START_TEST(parseNodeIdGuid) {
    UA_NodeId id = UA_NODEID("g=09087e75-8e5e-499b-954f-f2a9603db28a");
    ck_assert_int_eq(id.identifierType, UA_NODEIDTYPE_GUID);
    ck_assert_int_eq(id.namespaceIndex, 0);
    ck_assert_int_eq(id.identifier.guid.data1, 151551605);
} END_TEST

START_TEST(parseNodeIdGuidFail) {
    UA_NodeId id = UA_NODEID("g=09087e75=8e5e-499b-954f-f2a9603db28a");
    ck_assert_int_eq(id.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.identifier.numeric, 0);
    ck_assert_int_eq(id.namespaceIndex, 0);
} END_TEST

START_TEST(parseNodeIdByteString) {
    UA_NodeId id = UA_NODEID("ns=1;b=b3BlbjYyNTQxIQ==");
    ck_assert_int_eq(id.identifierType, UA_NODEIDTYPE_BYTESTRING);
    ck_assert_int_eq(id.namespaceIndex, 1);
    UA_ByteString bstrid = UA_BYTESTRING("open62541!");
    ck_assert(UA_ByteString_equal(&id.identifier.byteString, &bstrid));
    UA_NodeId_clear(&id);
} END_TEST

START_TEST(parseExpandedNodeIdInteger) {
    UA_ExpandedNodeId id = UA_EXPANDEDNODEID("ns=1;i=1337");
    ck_assert_int_eq(id.nodeId.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.nodeId.identifier.numeric, 1337);
    ck_assert_int_eq(id.nodeId.namespaceIndex, 1);
} END_TEST

START_TEST(parseExpandedNodeIdInteger2) {
    UA_ExpandedNodeId id = UA_EXPANDEDNODEID("svr=5;ns=1;i=1337");
    ck_assert_int_eq(id.nodeId.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.nodeId.identifier.numeric, 1337);
    ck_assert_int_eq(id.nodeId.namespaceIndex, 1);
    ck_assert_int_eq(id.serverIndex, 5);
} END_TEST

START_TEST(parseExpandedNodeIdIntegerNSU) {
    UA_ExpandedNodeId id = UA_EXPANDEDNODEID("svr=5;nsu=urn:test:1234;i=1337");
    ck_assert_int_eq(id.nodeId.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.nodeId.identifier.numeric, 1337);
    UA_String nsu = UA_STRING("urn:test:1234");
    ck_assert(UA_String_equal(&id.namespaceUri, &nsu));
    ck_assert_int_eq(id.serverIndex, 5);
    UA_ExpandedNodeId_clear(&id);
} END_TEST

START_TEST(parseExpandedNodeIdIntegerFailNSU) {
    UA_ExpandedNodeId id = UA_EXPANDEDNODEID("svr=5;nsu=urn:test:1234;;i=1337");
    ck_assert_int_eq(id.nodeId.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.nodeId.identifier.numeric, 0);
} END_TEST

START_TEST(parseExpandedNodeIdIntegerFailNSU2) {
    UA_ExpandedNodeId id = UA_EXPANDEDNODEID("svr=5;nsu=urn:test:1234;ns=1;i=1337");
    ck_assert_int_eq(id.nodeId.identifierType, UA_NODEIDTYPE_NUMERIC);
    ck_assert_int_eq(id.nodeId.identifier.numeric, 0);
} END_TEST

int main(void) {
    Suite *s  = suite_create("Test Builtin Type Parsing");
    TCase *tc = tcase_create("test cases");
    tcase_add_test(tc, parseGuid);
    tcase_add_test(tc, parseNodeIdNumeric);
    tcase_add_test(tc, parseNodeIdNumeric2);
    tcase_add_test(tc, parseNodeIdString);
    tcase_add_test(tc, parseNodeIdGuid);
    tcase_add_test(tc, parseNodeIdGuidFail);
    tcase_add_test(tc, parseNodeIdByteString);
    tcase_add_test(tc, parseExpandedNodeIdInteger);
    tcase_add_test(tc, parseExpandedNodeIdInteger2);
    tcase_add_test(tc, parseExpandedNodeIdIntegerNSU);
    tcase_add_test(tc, parseExpandedNodeIdIntegerFailNSU);
    tcase_add_test(tc, parseExpandedNodeIdIntegerFailNSU2);
    suite_add_tcase(s, tc);

    SRunner *sr = srunner_create(s);
    srunner_set_fork_status(sr, CK_NOFORK);
    srunner_run_all (sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
