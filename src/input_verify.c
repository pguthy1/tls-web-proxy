/******************************************************************************
 * input_verify.h: 
 * This header file specifies input validation functions for user input 
 * and HTTP headers using TCP/IPv4 sockets. 
******************************************************************************/

// Standard Library Headers
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// System Headers
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// Network Headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

// Regex Headers
#include <regex.h>

//Custom Headers
#include "custom_regex.h"
#include "http_request.h"
#include "tcp_module.h"

#define RES_BUF_SIZE 1024
#define STR_TRAN_ENCODE_LEN 18
#define KILO_BUF 1024
// helper Functions
// safeMemClear: memset wrapper function with error checking
void *safeMemClear(char *buf, size_t bufSize){
    if(memset(buf, 0, bufSize) != buf){
        fprintf(stderr, "verifyURL: memset() failed\n");
        return NULL;
    }
    return buf;
};


/**
 * verifyHostName: checks that the hostname is valid using regex based on RFC 
 * 1123 Section 2.1 
 * @param hostName string buffer containing the hostname to check
 * @return true for valid Hostnames
*/
bool verifyHostname(char *hostName){
    if (hostName == NULL){
        fprintf(stderr, "NULL input arg\n");
        return false;
    }
    // RFC 1123: hostname cannot begin or end with a hyphen
    char *expression = "^([a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9]\\.)*([a-zA-Z0-9]+)+$";
    return findPattern(hostName, expression);
};


/**
 * verifyResponseHeader: verifies that the received HTTP response header isn't
 * malformed.
 * 
 * @param responseBuf: string buffer containing HTTP response header
 * @return true if the HTTP response string is correctly formatted
 */
bool verifyResponseHeader(char *responseBuf){
    char *statusCodeRegex = "[0-9]{3}";
    char *statusMsgRegex = "[a-zA-Z0-9]+";
    char *headerNameRegex = "[A-Za-z0-9-]+";

    char *exampleMsgCopy = strdup(responseBuf);
    char *statusCodeStr = NULL;
    int statusCode = 0;
    char statusMessage[KILO_BUF];
    char *statusMsgPtr = NULL;
    memset(statusMessage, 0, KILO_BUF);

    char *httpType = strtok(exampleMsgCopy, " ");
    if( strncmp("HTTP/1.1", httpType, strlen("HTTP/1.1")) != 0){
        fprintf(stderr, "couldn't find HTTP/1.1 at the beginning of header\n");
        free(exampleMsgCopy);
        return false;
    }
    statusCodeStr = strtok(NULL, " ");
    if(statusCodeStr == NULL){
        fprintf(stderr, "strtok couldn't find token on first line\n");
        free(exampleMsgCopy);
        return false;
    }
    if((statusCode = atoi(statusCodeStr)) == 0){
        fprintf(stderr, "failed to find status code:%s\n", statusCodeStr);
        free(exampleMsgCopy);
        return false;
    }
    
    if((statusMsgPtr = strtok(NULL, "\n")) == NULL){
        fprintf(stderr, "strtok couldn't find STATUS MESSAGE on first line\n");
        free(exampleMsgCopy);
        return false;
    } 

    if(!findPattern(statusCodeStr, statusCodeRegex)){
         fprintf(stderr, "failed to find valid status code:%s\n", statusCodeStr);
        free(exampleMsgCopy);
        return false;

    }
    //fprintf(stderr,"found valid status code:%s\n", statusCodeStr);

    if(!findPattern(statusMsgPtr, statusMsgRegex)){
        fprintf(stderr, "failed to find valid status msg:%s\n", statusCodeStr);
        free(exampleMsgCopy);
        return false;

    } 
    //fprintf(stderr,"found valid status msg:%s\n", statusMsgPtr);
    char *headerName = NULL;
    char *headerInfo = NULL;

    while((headerName = strtok(NULL, ":")) != NULL){
        //fprintf(stderr, "Header Field:%s\n", headerName);
        headerInfo = strtok(NULL, "\n");
        
        //fprintf(stderr, "Header Data:%s\n", headerInfo);
        if(!findPattern(headerName, headerNameRegex)){
            if(strncmp(headerName, "\r", 1) == 0){
                //fprintf(stderr, "hit end of header bc first character is CR\n");
                break;
            }
            fprintf(stderr, "invalid header name:%s\n", headerName);
            free(exampleMsgCopy);
            return false;
        }
        //fprintf(stderr, "valid Header Field:%s\n", headerName);
        if(headerInfo == NULL){
            fprintf(stderr, "verify response header: something weird happened to header info\n");
            break;
        }
        //fprintf(stderr, "valid Header info:%s\n", headerInfo);
        if(strnlen(headerInfo, KILO_BUF) == 0){
            fprintf(stderr, "empty header info field\n");
        }
    }    
    return true;
};

/**
 * checkTransferEncoding: verifies that the Transfer-Encoding header field is
 * not set to "chunked"
 * 
 * @param responseBuf: string buffer containing responseHeader
 * @return true when transfer-encoding field is not set to chunked
*/
bool checkTransferEncoding(char *responseBuf){
    char *exampleMsgCopy = strdup(responseBuf);
    char *statusCodeStr = NULL;
    int statusCode = 0;
    char statusMessage[KILO_BUF];
    char *statusMsgPtr = NULL;
    memset(statusMessage, 0, KILO_BUF);

    char *httpType = strtok(exampleMsgCopy, " ");
    if( strncmp("HTTP/1.1", httpType, strlen("HTTP/1.1")) != 0){
        fprintf(stderr, "couldn't find HTTP/1.1 at the beginning of header\n");
        free(exampleMsgCopy);
        return false;
    }
    statusCodeStr = strtok(NULL, " ");
    if(statusCodeStr == NULL){
        fprintf(stderr, "strtok couldn't find token on first line\n");
        free(exampleMsgCopy);
        return false;
    }
    if((statusCode = atoi(statusCodeStr)) == 0){
        fprintf(stderr, "failed to find status code\n");
        free(exampleMsgCopy);
        return false;
    }
    
    if((statusMsgPtr = strtok(NULL, "\n")) == NULL){
        fprintf(stderr, "strtok couldn't find STATUS MESSAGE on first line\n");
        free(exampleMsgCopy);
        return false;
    } 

    char *headerName = NULL;
    char *headerInfo = NULL;
    while((headerName = strtok(NULL, ":")) != NULL){
        //fprintf(stderr, "Header Field:%s\n", headerName);
        headerInfo = strtok(NULL, "\n");
        //fprintf(stderr, "Header Data:%s\n", headerInfo);
        if(strncmp(" Transfer-Encoding", headerName, STR_TRAN_ENCODE_LEN) == 0){
            if (strstr(headerInfo, "chunked") != NULL){
                fprintf(stderr, "transfer encoding includes: %s\n", headerInfo);
                free(exampleMsgCopy);
                return false;
            }
            free(exampleMsgCopy);
            return true;
        }
    }
    
    free(exampleMsgCopy);
    return true;// returns default value true as no transfer-encoding header was found
};

