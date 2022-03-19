
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
#include <time.h>
#include <unistd.h>

// Network Headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include "ssl_example.h"
#include "http_helper.h"
#include "http_module.h"
#include "custom_regex.h"
char *trimEndingSpace(char *str);
int getHTTPRequestFromConnection(int connfd, char *requestBuf, char *forbiddenBuf, int logfd, struct sockaddr *clientAddr){
    httpGetRequestHeader(connfd, requestBuf);
    if(!verifyHTTPRequest(connfd, requestBuf, forbiddenBuf, logfd, clientAddr)){
        fprintf(stderr, "invalid http request\n");
        return -1;
    }
    return 0;
};

// extracts string from Host: header in given HTTP request
void getHostName(char *requestBuf, char *hostBuffer){
    char *ptr;
    char *requestCopy = strdup(requestBuf);
    char *linePtr = strtok_r(requestCopy, "\n", &ptr);
    do{
        if(findPattern(linePtr, "^Host:")){
            // found Hostname header
            strncpy(hostBuffer, linePtr+HOST_FIELD_SIZE, MAX_HOST_LENGTH);
            fprintf(stderr, "getHostName*():found host:%s   n\n", hostBuffer);
            free(requestCopy);
            return;
        }
        linePtr = strtok_r(NULL, "\n", &ptr);
    } while(linePtr != NULL);
    fprintf(stderr, "getHostName():didnt find host: %s\n", requestBuf);
    free(requestCopy);
    return;
};


void getFormattedTimeStr(char *timeStr, struct timespec *currTimePtr, struct tm *timeBufPtr){
    if(memset(currTimePtr, 0, sizeof(struct timespec)) != (void *)currTimePtr){
        perror("printClientPacketLog: memset() failed");
        exit(EXIT_FAILURE);
    }
    if(memset(timeBufPtr, 0, sizeof(struct tm)) != (void *)timeBufPtr){
        perror("printClientPacketLog: memset() failed");
        exit(EXIT_FAILURE);
    }
    if(memset(timeStr, 0, MAX_LOG_MSG_SIZE) != (void *)timeStr){
        perror("printClientPacketLog: memset() failed");
        exit(EXIT_FAILURE);
    }
    if(clock_gettime(CLOCK_REALTIME, currTimePtr) == -1){
        perror("printClientPacketLog: clock_gettime() failed");
        exit(EXIT_FAILURE);
    };
    if(gmtime_r(&(currTimePtr->tv_sec), timeBufPtr) != timeBufPtr){
        perror("gmtime_r() failed");
        exit(EXIT_FAILURE);
    }
    if(strftime(timeStr, MAX_LOG_MSG_SIZE, "%FT%T", timeBufPtr) == 0){
        fprintf(stderr, "strftime() failed\n");
        exit(EXIT_FAILURE);
    }
    return;
}


#define NS_TO_MS 1000000
void logResult(int logfd, struct sockaddr *clientAddr, char *requestBuf, char *errCode, int totalResponseSize){
    char msgBuf[MAX_LOG_MSG_SIZE];
    char timeStr[MAX_LOG_MSG_SIZE];
    char *ptr;
    // Get first line of request
    char *linePtr = strtok_r(requestBuf, "\r", &ptr);
    linePtr = trimEndingSpace(linePtr);
    // Get current time as a formatted string
    struct timespec currentTime;
    struct tm timeBuf;
    getFormattedTimeStr(timeStr, &currentTime, &timeBuf);
    
    // get client IP address from struct sockaddr
    char s[INET6_ADDRSTRLEN];
    const char *inetResult = inet_ntop(AF_INET, &(((struct sockaddr_in*)clientAddr)->sin_addr), s, sizeof(s));
    if(inetResult == NULL){
        perror("client: inet_ntop failed");
        exit(EXIT_FAILURE);
    }

    snprintf(msgBuf, MAX_LOG_MSG_SIZE, "%s.%03ldZ %s \"%s\" %s %d\n", timeStr, 
    (currentTime.tv_nsec / NS_TO_MS), s, linePtr, errCode, 
    totalResponseSize);
    write(logfd, msgBuf, strnlen(msgBuf, MAX_LOG_MSG_SIZE));
    return;
}
bool isNotSpace(char whiteChar){
    if(whiteChar == '\t' || whiteChar == '\r' || 
    whiteChar == '\n' || whiteChar == '\v' || whiteChar == '\t'){
        return true;
    }
    return false;
}
// trims leading and trailing whitespace in a given string;
char *trimEndingSpace(char *str){
    int j;
    for( j = 0; !isNotSpace(str[j]); j++);
    
    str[j] = '\0';
    return str;
}