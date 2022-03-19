#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <string.h>
#include <stdbool.h>
// System Headers
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Network Headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

// Regex Headers
#include <regex.h>
#include <check.h>
//Custom Headers
#include "tcp_module.h"
#include "http_module.h"
#include "ssl_example.h"
#include "tls_client.h"
#include "custom_regex.h"

START_TEST(testGetHTTPRequest){
    char reqBuffer[DEF_BUF_SIZE];
    struct sockaddr_storage clientAddr;
    socklen_t addrSize;
    char *port = "9090";

    int listenfd = initializeTcpServerConnection(port);

    // Accept incoming connection
    addrSize = sizeof clientAddr;
    int newconnfd = accept(listenfd, (struct sockaddr *)&clientAddr, &addrSize);

    // Read from new connection and get whole request header (16kb buffer)
    int retVal = getHTTPRequestFromConnection(newconnfd, reqBuffer);
    ck_assert(retVal == 0);
    TLSConnectToServer(newconnfd, reqBuffer);
    
    //httpGetRequestHeader(newconnfd, reqBuffer);
    //fprintf(stderr, "%s", reqBuffer);
    close(newconnfd);
}
END_TEST

/*
START_TEST(testGetHostName){
    char reqBuffer[DEF_BUF_SIZE];
    struct sockaddr_storage clientAddr;
    socklen_t addrSize;
    char *port = "9090";

    int listenfd = initializeTcpServerConnection(port);

    // Accept incoming connection
    addrSize = sizeof clientAddr;
    int newconnfd = accept(listenfd, (struct sockaddr *)&clientAddr, &addrSize);

    // Read from new connection and get whole request header (16kb buffer)
    int retVal = getHTTPRequestFromConnection(newconnfd, reqBuffer);
    ck_assert(retVal == 0);
    // close connection
    close(newconnfd);
    char hostNameBuffer[DEF_BUF_SIZE];
    memset(hostNameBuffer, 0, DEF_BUF_SIZE);
    getHostName(reqBuffer, hostNameBuffer);
    fprintf(stderr, "test: hostName:%s\n", hostNameBuffer);
    
    ck_assert(hostNameBuffer != NULL);
}
END_TEST
*/
Suite *httpSuite(void){
    Suite *s;
    TCase *tc_core;

    s = suite_create("Test Getting HTTP request");
    
    /* Mah Test Cases*/
    tc_core = tcase_create("Get from port 9090");

   // tcase_add_test(tc_core, testGetHostName);
    tcase_add_test(tc_core, testGetHTTPRequest);
    suite_add_tcase(s, tc_core);

    return s;
};

int main(void){
    int numberFailed = 0;
    Suite *s;
    SRunner *sr;

    s = httpSuite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    numberFailed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (numberFailed == 0) ? EXIT_SUCCESS: EXIT_FAILURE;
}