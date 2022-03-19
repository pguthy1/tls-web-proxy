// Standard Library Headers
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

//Custom Headers
#include "tcp_module.h"
#include "input_verify.h"
#include "http_request.h"
#include "custom_regex.h"
#include "ssl_example.h"
#include "site_filter.h"
#include "http_module.h"
void sendErrorMessage(int connfd, char *msgStr, int msgLen){
    int totalBytesSent = 0;
    int bytesSent = 0;
    while(totalBytesSent < msgLen){
        bytesSent = send(connfd, msgStr, msgLen - totalBytesSent, 0);
        if(bytesSent <= 0){
            fprintf(stderr, "failed to send errormessage\n");
            return;
        }
        totalBytesSent += bytesSent;
    }
    return;
};

bool verifyHTTPRequest(int connectionfd, char *requestBuf, char *forbiddenBuffer, int logfd, struct sockaddr *clientAddr){
    char *request = strdup(requestBuf);
    char *ptr;
    char *firstLine = strtok_r(request, "\n", &ptr);
    // Check that first line of request is formatted correctly
    if(!findPattern(firstLine, "^(GET|HEAD)")){
        sendErrorMessage(connectionfd, ERROR_501, ERROR_501_LEN);
        logResult(logfd, clientAddr, requestBuf, CODE_501, ERROR_501_LEN);
        free(request);
        return false;
    }
    if(!findPattern(firstLine, "^(GET|HEAD).*HTTP/(1\\.1|2)")){
        fprintf(stderr, "invalid http request:%s\n", requestBuf);
        sendErrorMessage(connectionfd, ERROR_400, ERROR_400_LEN);
        logResult(logfd, clientAddr, requestBuf, CODE_400, ERROR_400_LEN);
        free(request);
        return false;
    }

    if(siteIsForbidden(forbiddenBuffer, firstLine)){
        fprintf(stderr, "forbidden site\n");
        sendErrorMessage(connectionfd, ERROR_403, ERROR_403_LEN);
        logResult(logfd, clientAddr, requestBuf, CODE_403, ERROR_403_LEN);
        free(request);
        return false;
    }   
/*
    char matchBuf[2048];
    if(findPattern(request, URLValidationExp)){
        findMatchingString(requestBuf, URLValidationExp, matchBuf);
        fprintf(stderr, "URL validation worked:%s", matchBuf);
    } else {
        fprintf(stderr, "URL validation failed\n");
    }
*/

/*
    // loop to check that all the request header fields are correctly formatted.
    do{
        linePtr = strtok_r(NULL, "\n", &ptr);
        if(!findPattern(linePtr, "[:alnum:-]+:[:alnum:-]")){
            fprintf(stderr, "invalid http request:%s\n", requestBuf);
            free(request);
            return false;
        }
    } while(linePtr != NULL);
*/
    free(request);
    return true;
}
/**
 * httpGetRequestHeader: receives HTTP request header from a given 
 * connected socket.
 * 
 * @param connectionfd: socket descriptor for TCP connection to server
 * @param requestBuffer: string buffer for storing the response
*/
void httpGetRequestHeader(int connectionfd, char *requestBuffer){
    if( connectionfd < 0 || requestBuffer == NULL){
        fprintf(stderr, "httpGetRequestHeader: invalid args passed\n");
        return;
    }
    ssize_t bufferSize = DEF_BUF_SIZE;
    
    int totalBytesRecvd = 0;
    while(!verifyEndOfHeader(requestBuffer) && totalBytesRecvd < bufferSize){
        int bytesRecvd = 0;
        bytesRecvd = recv(connectionfd, requestBuffer, bufferSize - totalBytesRecvd, 0);
        if(bytesRecvd < 0){
            perror("httpGetRequestHeader: recv fail-");
            return;
        };
        if(bytesRecvd == 0){
            fprintf(stderr, "getRequestHeader:EOF recv'd\n");
            break;
        }
        totalBytesRecvd += bytesRecvd;
        fprintf(stderr, "totalBytesRecvd:%d\n", totalBytesRecvd);
    }
    return;
}

