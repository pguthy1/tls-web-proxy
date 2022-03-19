#ifndef __HTTP_MODULE_H__
#define __HTTP_MODULE_H__
#include <sys/socket.h>
#include <sys/types.h>
int getHTTPRequestFromConnection(int connfd, char *requestBuf, char *forbiddenBuf, int logfd, struct sockaddr *clientAddr);
void getHostName(char *requestBuf, char *hostBuffer);
void logResult(int logfd, struct sockaddr *clientAddr, char *requestBuf, char *errCode, int totalResponseSize);
#define MAX_LOG_MSG_SIZE 512
#endif