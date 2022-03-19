/******************************************************************************
 * tcp_client.c: 
 * This source file implements functions for initializing the TCP/IP client 
 * connection using TCP/IPv4 sockets. There are also several helper functions 
 * included in the implementation.
******************************************************************************/

// Standard Library Headers
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// System Headers
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
// Network Headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

// Regex Headers
#include <regex.h>

// Custom headers
#include "tcp_module.h"
#include "custom_regex.h"
#include "ssl_example.h"
#define TIMEOUT 5
#define BACKLOG 20
//Debug functions

void printIpAddr(struct addrinfo *p);



/**
 * initializeTcpClientConnection: Initializes internet socket with proper
 * parameters for a TCP/IPv4 listening socket. 
 * 
 * @param portNum: string with port number for proxy server to bind to.
 * @return socket descriptor with connection to client. returns -1 on errors.
 * 
*/
int initializeTcpServerConnection(char *portNum){
    int sockfd = -1;
    struct addrinfo hints, *gai_result, *ai_ptr;
    int status;
    //char *website = hostName;
    char *port = portNum;
    configHints(&hints);

    if((status = getaddrinfo(NULL, port, &hints, &gai_result)) != 0){
        fprintf(stderr, "getaddrinfo failed: %s\n", gai_strerror(status));
        return TCP_SOCK_ERR;
    }

    for(ai_ptr = gai_result; ai_ptr != NULL; ai_ptr = ai_ptr->ai_next){

        if((sockfd = socket(ai_ptr->ai_family, ai_ptr->ai_socktype, ai_ptr->ai_protocol)) == -1){    
            perror("tcpClientConnection: socket() failed");
            printIpAddr(ai_ptr);
            continue;
        }
        /*
        struct timeval timeOut;
        timeOut.tv_sec = TIMEOUT;
        timeOut.tv_usec = 0;
        
        if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeOut, (sizeof timeOut)) < 0){
            perror("setsockopt failed:");
            printIpAddr(ai_ptr);
            close(sockfd);
            continue;
        };
        */

        if(bind(sockfd, ai_ptr->ai_addr, ai_ptr->ai_addrlen) == -1){
            int tempErrno = errno;
            perror("tcpClientConnection: connect() failed");

            close(sockfd);
            printIpAddr(ai_ptr);
            if(tempErrno == ECONNREFUSED){
                return TCP_SOCK_ERR;
            }
            continue;
        }
       //if(ai_ptr != NULL) printIpAddr(ai_ptr);
        break;
    }
    if(ai_ptr == NULL){
        fprintf(stderr, "tcp_module: failed to bind tcp server socket\n");
        return TCP_SOCK_ERR;
    } else {
        //fprintf(stderr, "myweb: connected successfully\n");
       // printIpAddr(ai_ptr);
    }
    //printIpAddr(ai_ptr);
    freeaddrinfo(gai_result);
    if(listen(sockfd, BACKLOG) == -1){
        perror("failed to listen()\n");
        exit(EXIT_FAILURE);
    }
    return sockfd;
};

/**
 * configHints: configures hints for getaddrinfo() function.
 * 
 * @param hintsPtr: pointer to struct addrinfo that will be populated.
*/
void configHints(struct addrinfo *hints_ptr){
    struct addrinfo hints = *hints_ptr;

    if(memset(hints_ptr, 0, sizeof hints) != (void*) hints_ptr){
        fprintf(stderr, "memset failed\n");
        exit(EXIT_FAILURE);
    }

    hints_ptr->ai_family = AF_INET;// IPv4
    hints_ptr->ai_socktype = SOCK_STREAM;// UDP
    hints_ptr->ai_flags = AI_PASSIVE;
    return;
}

/**
 * getAddrFromURL: extracts and validates IP address from provided URL.
 * 
 * @param addrURL: string containing the IP address.
 * @param addrBuf: character string buffer that will contain the IP address string.
 * @return string buffer with the IP address. Returns NULL on error.
*/
void getAddrFromURL(char *addrURL, char *addrBuf){
    
    char addrMatchBuf[MAX_IPSTR_LEN+1];
    //INPUT VERIFICATION FUNCTION HERE
    char *expression = "^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}\
(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)([:/]|$)";
    if(findPattern(addrURL, expression)){
        findMatchingString(addrURL, expression, addrMatchBuf);
        size_t matchLength = strnlen(addrMatchBuf, MAX_IPSTR_LEN);
        if(findPattern(addrMatchBuf,"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}\
(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\\D)")){
            //fprintf(stderr, "new address match: %s\n", addrMatchBuf);
            snprintf(addrBuf, matchLength, "%s", addrMatchBuf);
            return;
        }
        //fprintf(stderr, "new address match: %s\n", addrMatchBuf);
        snprintf(addrBuf, matchLength, "%s", addrMatchBuf);
    }
    return;
};


#define MAX_PORT_MATCH_LEN (MAX_PORTSTR_LEN + 2)
/**
 * getPortFromURL: extracts and validates the provided portnumber, if it
 * was given in the URL.
 * 
 * @param portURL: string containing URL to be parsed.
 * @param portBuf: string that will contain the port number.
 * @return string buffer with port number. Returns NULL on error.
*/
void getPortFromURL(char *portURL, char *portBuf){
    char portMatchBuffer[MAX_PORT_MATCH_LEN];
    memset(portMatchBuffer, 0, MAX_PORT_MATCH_LEN);
    //Insert input verifiaction function here
    if(!findPattern(portURL, ":")){//no port specified
        
        snprintf(portBuf, 3, DEF_PORT);
        return;
    }
    if(strstr(portURL, ":/") != NULL){
        snprintf(portBuf, 3, DEF_PORT);
        return;
    }
    //Portnums can range from 1024 to 65535 (also port 80 for http)
    char *portExpression = ":(80|443|6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9]{3}\
    |[1-5][0-9]{4}|102[4-9]|10[3-9][0-9]|1[1-9][0-9]{2}|[2-9][0-9]{3})([\\b/]|$)";
    if(findPattern(portURL, portExpression)){
        findMatchingString(portURL, portExpression, portMatchBuffer);
        if(findPattern(portURL, ":(80|443|6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9]{3}\
    |[1-5][0-9]{4}|102[4-9]|10[3-9][0-9]|1[1-9][0-9]{2}|[2-9][0-9]{3})$")){
            size_t portMatchLen = strnlen(portMatchBuffer, MAX_PORT_MATCH_LEN);
            snprintf(portBuf, MAX_PORTSTR_LEN, "%.*s", (int)(portMatchLen - 1), portMatchBuffer + 1);
            return;
        }
        // Trim the colon from the regex match string
        size_t portMatchLen = strnlen(portMatchBuffer, MAX_PORT_MATCH_LEN);
        snprintf(portBuf, MAX_PORTSTR_LEN, "%.*s", (int)(portMatchLen - 1), portMatchBuffer + 1);
        return;
    }
};

void getPortFromStr(char *portURL, char *portBuf){
    if(portURL == NULL || portBuf == NULL){
        fprintf(stderr, "getPortFromStr\n");
        return;
    }
    char *portExpression = "^(80|443|6553[0-5]|655[0-2][0-9]|65[0-4][0-9][0-9]|6[0-4][0-9]{3}\
    |[1-5][0-9]{4}|102[4-9]|10[3-9][0-9]|1[1-9][0-9]{2}|[2-9][0-9]{3})$";
    
    findMatchingString(portURL, portExpression, portBuf);
    return;
};

void getHostNameFromURL(char *URLBuffer, char *domainNameBuf){
    char matchBuffer[MAX_HOST_LENGTH];
    memset(matchBuffer, 0, MAX_HOST_LENGTH);
    char *hostnameExp = "([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,}";
    if(findPattern(URLBuffer, hostnameExp)){
        findMatchingString(URLBuffer, hostnameExp, matchBuffer);
        //size_t matchLen = strnlen(matchBuffer, MAX_HOST_LENGTH);
        snprintf(domainNameBuf, MAX_HOST_LENGTH, "%s", matchBuffer);
    }
    return;
};


void *get_in_addr(struct sockaddr *sa){
    // Use generic sockaddr to pass in IPv4 or IPv6 sockaddrs
    if(sa->sa_family == AF_INET){
        // IPv4 case:
        // cast sockaddr object to sockaddr_in
        // then, return the pointer to the IPv4 address
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }

    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

void printIpAddr(struct addrinfo *p){
    char s[INET6_ADDRSTRLEN];
    const char *inetResult = inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof(s));

    if(inetResult == NULL){
        perror("client: inet_ntop failed");
        exit(EXIT_FAILURE);
    }
    printf("address:%s\n", s);
    return;
}

