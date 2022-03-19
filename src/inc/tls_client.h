#ifndef __TLS_CLIENT_H__
#define __TLS_CLIENT_H__
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <pthread.h>
typedef struct TLSArgsObj{
    SSL_CTX *ctx;
    int connectionfd;
    int logfd;
    struct sockaddr *clientAddr;
    char *requestBuffer;

    char *forbiddenSiteFileName;
    char *forbiddenSiteBuffer;
    int *totalSiteBufSize;
    int *sitesReloadedFlag;
    pthread_mutex_t *accessLogMutexPtr;
}TLSArgs;

int TLSConnectToServer(TLSArgs *argPtr);
#endif