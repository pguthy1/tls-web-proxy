/******************************************************************************
 * http_request.h: 
 * This header file specifies the HTTP GET request and HTTP HEAD request 
 * functions using TCP/IPv4 sockets. There are also several helper functions
 * included in this header file.
******************************************************************************/

#ifndef __HTTP_REQUEST_H__
#define __HTTP_REQUEST_H__

#include <sys/types.h>

/**
 * processResponse: processes server response to HTTP request. 
 * 
 * @param connectionfd: socket descriptor for TCP connection
 * @param requestType: string that describes HTTP request type: GET or HEAD
*/
void processResponse(int connectionfd, const char *requestType);

/**
 * httpGetRequestHeader: receives HTTP request header from a given 
 * connected socket.
 * 
 * @param connectionfd: socket descriptor for TCP connection to server
 * @param requestBuffer: string buffer for storing the response
*/
void httpGetRequestHeader(int connectionfd, char *requestBuffer);

/**
 * httpGetResponseBody: receives body of an HTTP response and writes to an
 * output file.
 * 
 * @param connectionfd: socket descriptor for TCP connection to server
 * @param responseBuffer: string buffer for managing received data
 * @param contentLength: number of bytes that need to be received
*/
void httpGetResponseBody(int connectionfd, char *responseBuffer, int contentLength);
/**
 * writeErrorResponseToFile: writes the given HTTP response to the output file
 * in the case of a unsuccessful request.(non-200 status code) 
 * 
 * @param errorfd: file descriptor for the file to write the response to.
 * @param responseBuffer: string buffer containing the response header.
 * @param responseSize: number of bytes to write from Response buffer.
*/
void writeErrorResponseToFile(int errorfd, char *responseBuffer, size_t responseSize);


/**
 * getResourceFromURL: fills the given buffer with the name of the requested
 * resource found in the resource URL.
 * 
 * @param resourceBuf: string buffer to place resource name inside
 * @param resourceURL: string to search for resource name.
*/
void getResourceFromURL(char *resourceBuf, char *resourceURL);


/**
 * sendHTTPClear: sends the request in the string buffer to given socket
 * descriptor.
 * 
 * @param connfd: connected socket dexcriptor to send to.
 * @param requestBuf: buffer containing request.
 * @param requestLength: length of buffer to send.
*/
void sendHTTPClear(int connfd, char *requestBuf, size_t requestLength);

#endif
