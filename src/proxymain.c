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
#include <signal.h>
// Network Headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

//Threads
#include <pthread.h>
// Regex Headers
#include <regex.h>

//Custom Headers
#include "tcp_module.h"
#include "http_module.h"
#include "ssl_example.h"
#include "tls_client.h"
#include "custom_regex.h"
#include "site_filter.h"

typedef struct RequestArgsObj{
    int connectionfd;
    int logfd;
    struct sockaddr *clientAddr;
    char *requestBuffer;
    char *forbiddenSiteFileName;
    char *forbiddenSiteBuffer;
    int *totalSiteBufSize;
    int *sitesReloadedFlag;
}RequestArgs;

void *handleRequest(void *args);

int sitesReloadedFlag = 0;
char *forbiddenSiteFname = NULL;
char forbiddenSiteBuf[DEF_BUF_SIZE];
void handleSigInt(int sig){
    if(sig == SIGINT){
    if(getForbiddenSiteList(forbiddenSiteFname, forbiddenSiteBuf) != forbiddenSiteBuf){
        write(STDERR_FILENO, "couldn't retrieve forbidden sites list\n", 41);
        return;
    };
    sitesReloadedFlag = 1;
    }
    return;
}
void mainTLSServerConnect(char *portStr, char *accessLogFname){
    //char reqBuffer[DEF_BUF_SIZE];
    
    struct sockaddr_storage clientAddr;
    socklen_t addrSize;
    char port[MAX_PORTSTR_LEN];
    memset(port, 0, MAX_PORTSTR_LEN);
    getPortFromStr(portStr, port);
    if(strnlen(port, MAX_PORTSTR_LEN) == 0){
        fprintf(stderr, "invalid port passed\n");
        return;
    };
    

    //flags
    //int sitesNeedReloadFlag = 0;
    
    //mutexes
    //pthread_mutex_t accessLogMutex = PTHREAD_MUTEX_INITIALIZER;
    //pthread_mutex_t reloadMutex = PTHREAD_MUTEX_INITIALIZER;
    
    // Set up access log function
    int accessfd = open(accessLogFname, (O_CREAT | O_APPEND | O_WRONLY), S_IRWXU);
    if(accessfd < 0){
        fprintf(stderr, "failed to open access log file\n");
        return;
    }
    //int siteBufSize;
    if(getForbiddenSiteList(forbiddenSiteFname, forbiddenSiteBuf) != forbiddenSiteBuf){
        fprintf(stderr, "couldn't retrieve forbidden sites list\n");
        return;
    };
    int listenfd = initializeTcpServerConnection(port);

    if(listenfd < 0){
        fprintf(stderr, "couldn't initialize TCP listen socket.\n");
        return;
    }

    if(signal(SIGINT, handleSigInt) == SIG_ERR){
        fprintf(stderr, "sigint handler failed\n");
        return;
    }
    // Accept incoming connection
    addrSize = sizeof clientAddr;
    //fprintf(stderr, "before accept\n");
    for(;;){
        int newconnfd = accept(listenfd, (struct sockaddr *)&clientAddr, &addrSize);
        
        // Enqueue

        // Start of Thread:
        //fprintf(stderr, "start of thread\n");
        pthread_t thread;
        RequestArgs reqArgs;
        reqArgs.clientAddr = (struct sockaddr *)&clientAddr;
        //memcpy(reqArgs.clientAddr, (struct sockaddr *)&clientAddr, addrSize);
        reqArgs.connectionfd = newconnfd;
        reqArgs.logfd = accessfd;
        reqArgs.forbiddenSiteBuffer = forbiddenSiteBuf;
        reqArgs.forbiddenSiteFileName = forbiddenSiteFname;
        reqArgs.sitesReloadedFlag = &sitesReloadedFlag;
        //reqArgs.requestBuffer = strdup(reqBuffer);
        if(pthread_create(&thread, NULL, handleRequest, (void*)(&reqArgs)) < 0){
            fprintf(stderr, "thread create error\n");
            return;
        };
    }
    
    //pthread_join(thread, NULL);
}
int main(int argc, char **argv){
    if(argc != 4){
        fprintf(stderr, "invalid number of args passed\n");
        exit(EXIT_FAILURE);
    }
    forbiddenSiteFname = argv[2];

    mainTLSServerConnect(argv[1], argv[3]);
    return 0;
}

void *handleRequest(void *args){
    RequestArgs *reqArgPtr = (RequestArgs *)args;
    RequestArgs reqArgs = *reqArgPtr;
    int newconnfd = reqArgs.connectionfd;
    int accessfd = reqArgs.logfd;
    char reqBuffer[DEF_BUF_SIZE];
    char *forbiddenSiteBuffer = reqArgs.forbiddenSiteBuffer;
    char *forbiddenSiteFilename = reqArgs.forbiddenSiteFileName;
    int *reloadedFlag = reqArgs.sitesReloadedFlag;    
    struct sockaddr *clientAddr = reqArgs.clientAddr;

    //clear request buffer
    memset(reqBuffer, 0, DEF_BUF_SIZE);
    // Read from new connection and get whole request header (16kb buffer)
    int retVal = getHTTPRequestFromConnection(newconnfd, reqBuffer, forbiddenSiteBuffer, accessfd, clientAddr);
    if(retVal != 0){
        close(newconnfd);
        pthread_exit(NULL);
    }
    TLSArgs tlsArgs;
    tlsArgs.connectionfd = newconnfd;
    tlsArgs.logfd = accessfd;
    tlsArgs.forbiddenSiteFileName = forbiddenSiteFilename;
    tlsArgs.forbiddenSiteBuffer = forbiddenSiteBuffer;
    tlsArgs.clientAddr = clientAddr;
    //tlsArgs.totalSiteBufSize = &siteBufSize;
    tlsArgs.requestBuffer = reqBuffer;
    tlsArgs.sitesReloadedFlag = reloadedFlag;
    //tlsArgs.accessLogMutexPtr = &accessLogMutex;
    TLSConnectToServer(&tlsArgs);
    fprintf(stderr, "TLS connect finished\n");
    close(newconnfd);
    close(accessfd);
    //free(reqBuffer);
    //free(clientAddr);
    pthread_exit(NULL);
}