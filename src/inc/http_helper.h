#ifndef __HTTP_HELPER_H__
#define __HTTP_HELPER_H__
/**
 * httpGetRequestHeader: receives HTTP request header from a given 
 * connected socket.
 * 
 * @param connectionfd: socket descriptor for TCP connection to server
 * @param requestBuffer: string buffer for storing the response
*/
void httpGetRequestHeader(int connectionfd, char *requestBuffer);

bool verifyHTTPRequest(int connectionfd, char *requestBuf, char *forbiddenBuffer, int logfd, struct sockaddr *clientAddr);
void sendErrorMessage(int connfd, char *msgStr, int msgLen);

#endif