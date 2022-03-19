/******************************************************************************
 * http_request.c: 
 * This source file implements the HTTP GET request and HTTP HEAD request using
 * TCP/IPv4 sockets. There are also several helper functions included in the 
 * implementation.
******************************************************************************/

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
// Macros
#define MAX_REQ_STR_LEN 5
#define STR_CONTENT_LEN 14
#define BUF_SIZE 4096

// Helper function prototype

bool checkForErrorCode(char *headerBuf);

void mockGetResponseHeader(char *responseBuf);


/**
 * processResponse: processes server response to HTTP request. 
 * 
 * @param connectionfd: socket descriptor for TCP connection
 * @param requestType: string that describes HTTP request type: GET or HEAD
*/
void processResponse(int connectionfd, const char *requestType){
    int connfd = connectionfd;
    int outfd = -1;
    char responseBuffer[BUF_SIZE];
   //int bufSize = BUF_SIZE;
    //char *outFileName = "output.dat";

    if(memset(responseBuffer, 0, BUF_SIZE) != responseBuffer){
        fprintf(stderr, "processResponse: memset fail \n");
        return;
    };

    //mockGetResponseHeader(responseBuffer);
    httpGetResponseHeader(connfd, responseBuffer);
    char headerBuffer[BUF_SIZE];
    memset(headerBuffer, 0, BUF_SIZE);

    regmatch_t endOfHeaderOffset = findPatternOffset(responseBuffer, "\r\n\r\n");
    strncpy(headerBuffer, responseBuffer, endOfHeaderOffset.rm_eo);
    //fprintf(stderr, "double CRLF rm_eo:%d rm_so:%d \n", endOfHeaderOffset.rm_eo, endOfHeaderOffset.rm_so);
    if(!verifyResponseHeader(headerBuffer)){
        fprintf(stderr, "GetResponseHeader: badresponse header\n");
    } 
    //fprintf(stderr, "response header:\n%s\nEND OF HEADER\n", headerBuffer);

    if(strnlen(headerBuffer, BUF_SIZE) == 0){
        fprintf(stderr, "processResponse: failed to get response header\n");
        return;
    }

    int bytesRecvdWithHeader = strnlen(responseBuffer, BUF_SIZE);
    int bodyBytesAlreadyRecvd = bytesRecvdWithHeader - endOfHeaderOffset.rm_eo;

    if(strncmp(requestType, "HEAD", MAX_REQ_STR_LEN - 1) == 0){
        outfd = STDOUT_FILENO;
        //fprintf(stderr, "outfd set to stdout\n");
    }
    // IMPLEMENT ERROR CHECKER HERE FOR ERROR STATUS CODES
    if(checkForErrorCode(headerBuffer)){//checkForError code returns true on non 200 responses
        //fprintf(stderr, "error code found\n");
        if(strncmp(requestType, "GET", MAX_REQ_STR_LEN - 2) == 0){
            /*
            if((outfd = open(outFileName, O_WRONLY|O_CREAT)) == -1){
                perror("processResponse:open() failed:");
                return;
            }
            fprintf(stderr, "processResponse: errorfile open() success\n");
            */
           fprintf(stderr, "processResponse:GET got a non-200 status code\n");
            char *errHeader  = strdup(headerBuffer);
            errHeader = strtok(errHeader, "\r");
           fprintf(stderr, "%s\n", errHeader);
            free(errHeader);
        }
        
        if(strncmp(requestType, "HEAD", MAX_REQ_STR_LEN - 1) == 0){
            fprintf(stderr, "HEAD request got error response header\n");
            outfd = STDERR_FILENO;
            writeErrorResponseToFile(outfd, headerBuffer, strnlen(headerBuffer, BUF_SIZE));
            return;
        }
        //size_t responseSize = strnlen(responseBuffer, bufSize);
        //writeErrorResponseToFile(outfd, responseBuffer, responseSize);
        if(outfd > 2) close(outfd);
    }
    
    if(strncmp(requestType, "HEAD", MAX_REQ_STR_LEN - 1) == 0){
        outfd = STDOUT_FILENO;
        fprintf(stdout, "%s",  headerBuffer);
        //writeErrorResponseToFile(outfd, headerBuffer, strnlen(headerBuffer, BUF_SIZE));
        return;
    };
    if(strncmp(requestType, "GET", MAX_REQ_STR_LEN - 2) == 0){
        if(!checkTransferEncoding(headerBuffer)){
            fprintf(stderr, "processResponse: This program doesn't support chunked encoding\n");
            return;
        }
        ssize_t contentLength = getContentLength(headerBuffer);
        if(contentLength < 0){
            fprintf(stderr, "process GET response: no content-length header value found\n");
            // need to recv until EOF received.
        }
        if(contentLength == 0){
            fprintf(stderr, "content length is 0\n");
            return;
        }
        //fprintf(stderr, "contentLength%zd\n", contentLength);
        // Trim header out of response buffer and leave in bytes from the body
        char *bodyBuffer = strdup(responseBuffer+endOfHeaderOffset.rm_eo);
        memset(responseBuffer, 0, BUF_SIZE);
        strncpy(responseBuffer, bodyBuffer, bodyBytesAlreadyRecvd);
        free(bodyBuffer);
        //contentLength = contentLength - bodyBytesAlreadyRecvd;
        httpGetResponseBody(connfd, responseBuffer, contentLength);  
    }
   // fprintf(stderr, "connfd: %d\nresponse header: %s\n",connfd, responseBuffer);
    return;
};

/**
 * httpGetRequestHeader: receives HTTP request header from a given 
 * connected socket.
 * 
 * @param connectionfd: socket descriptor for TCP connection to server
 * @param requestBuffer: string buffer for storing the response
*/
void httpGetRequestHeader(int connectionfd, char *requestBuffer){
    if( connectionfd < 0 || requestBuffer == NULL){
        fprintf(stderr, "httpGetResponseHeader: invalid args passed\n");
        return;
    }
    ssize_t bufferSize = BUF_SIZE;
    
    int totalBytesRecvd = 0;
    while(!verifyEndOfHeader(requestBuffer) && totalBytesRecvd < bufferSize){
        int bytesRecvd = 0;
        bytesRecvd = recv(connectionfd, requestBuffer, bufferSize - totalBytesRecvd, 0);
        if(bytesRecvd < 0){
            perror("httpGetResponseHeader: recv fail-");
            return;
        };
        if(bytesRecvd == 0){
            //fprintf(stderr, "getResponseHeader:EOF recv'd\n");
            break;
        }
        totalBytesRecvd += bytesRecvd;
        //fprintf(stderr, "totalBytesRecvd:%d\n", totalBytesRecvd);
    }
    return;
};

#define READ_TO_EOF 1
/**
 * httpGetResponseBody: receives body of an HTTP response and writes to an
 * output file.
 * 
 * @param connectionfd: socket descriptor for TCP connection to server
 * @param responseBuffer: string buffer for managing received data
 * @param contentLength: number of bytes that need to be received
*/
void httpGetResponseBody(int connectionfd, char *responseBuffer, int contentLength){
    char *filename = "output.dat";
    int readUntilEOF = 0;
    int exitFlag = 0;
    int contentLen = contentLength;
    if(connectionfd < 0 || responseBuffer == NULL){
        fprintf(stderr, "getResponseBody: invalid args passed\n");
        return;
    }

    if(contentLength < 0){
        readUntilEOF = READ_TO_EOF;
    }

    int outfd = open(filename, O_CREAT | O_WRONLY);

    if(outfd < 0){
        perror("getResponseBody:open() failed");
        //fprintf(stderr, "getResponseBody:open() failed\n");
        return;
    }

    int bytesAlreadyRecvd = strnlen(responseBuffer, BUF_SIZE);
    contentLen -= bytesAlreadyRecvd;
    int bytesWritten = 0;
    while (bytesAlreadyRecvd > 0){
        bytesWritten = write(outfd, responseBuffer, strnlen(responseBuffer, BUF_SIZE));
        if(bytesWritten < 0){
            perror("getBody: write() failed");
            close(outfd);
            return;
        };
        if(bytesWritten == 0){
            
        }
        //fprintf(stderr, "bytesAlreadyRecvd: wrote %d bytes\n", bytesWritten);
        bytesAlreadyRecvd -= bytesWritten;
    }
    exitFlag = (contentLen <= 0) ? 1 : 0;
    //
    int totalBytesRecvd = 0;
    int totalBytesWritten = 0;
    int bytesRecvd = 0;
    int recvDone = 0;
    int writeDone = 0;
    memset(responseBuffer, 0, BUF_SIZE);
    while(!exitFlag){
        bytesWritten = 0;
        bytesRecvd = 0;

        if(!recvDone){
            bytesRecvd = recv(connectionfd, responseBuffer, BUF_SIZE, 0);
            if(bytesRecvd < 0){
                perror("recv() fail");
                close(outfd);
                return;
            }
            if(bytesRecvd == 0){
                // EOF
                recvDone = 1;
                //no more bytes to write out either
                writeDone = 1;
                break;
            }
 
                totalBytesRecvd += bytesRecvd;
            if(totalBytesRecvd >= contentLen){
                recvDone = 1;
            };
        }

        if(!writeDone){
            bytesWritten = write(outfd, responseBuffer, bytesRecvd);
            if(bytesWritten < 0){
                perror("getResponseBody: write() failed");
                close(outfd);
                return;
            }
            if(bytesWritten == 0){
                if(totalBytesWritten >= totalBytesRecvd){
                    writeDone = 1;
                    break;
                }
            }
            while( bytesWritten < bytesRecvd){
                int leftoverBytesWritten = write(outfd, responseBuffer+bytesWritten, bytesRecvd - bytesWritten);
                if(leftoverBytesWritten < 0){
                    perror("getResponseBody: write() failed");
                    close(outfd);
                    return;
                }
                if(leftoverBytesWritten == 0){
                    perror("no leftover bytes were written");
                    break;
                }
                bytesWritten += leftoverBytesWritten;
            }
            totalBytesWritten += bytesWritten;
        }
        if(recvDone && writeDone){
            exitFlag = 1;
        }
    }
    if(totalBytesRecvd > totalBytesWritten){
       fprintf(stderr, "total bytes recvd > totalBytesWritten\n");
    }
    if(totalBytesWritten != contentLen){
        fprintf(stderr, "getBody: totalBytesWritten != contentLen\n");
    }
    close(outfd);
    return;
};

/**
 * writeErrorResponseToFile: writes the given HTTP response to the output file
 * in the case of a unsuccessful request.(non-200 status code) 
 * 
 * @param errorfd: file descriptor for the file to write the response to.
 * @param responseBuffer: string buffer containing the response header.
 * @param responseSize: number of bytes to write from Response buffer.
*/
void writeErrorResponseToFile(int errorfd, char *responseBuffer, size_t responseSize){
    if(errorfd < 0){
        fprintf(stderr, "writeErrResponse: invalid error file descriptor\n");
        return;
    }
    if(responseSize == 0){
        fprintf(stderr, "writeErrResponse: responseBuffer size parameter is 0 bytes\n");
        return;
    }
    if(responseBuffer == NULL){
        fprintf(stderr, "writeerrResponse: invalid buffer pointer\n");
        return;
    }
    size_t bytes_written = 0;
    int write_amt = 0;
    while(bytes_written < responseSize){
        write_amt =  write(errorfd, responseBuffer, (responseSize - bytes_written));
        if(write_amt == - 1){
           perror("errResponseToFile:write()");
           return; 
        }
        bytes_written += write_amt;
    }
    return;
};

/**
 * getResourceFromURL: fills the given buffer with the name of the requested
 * resource found in the resource URL.
 * 
 * @param resourceBuf: string buffer to place resource name inside
 * @param resourceURL: string to search for resource name.
*/
void getResourceFromURL(char *resourceBuf, char *resourceURL){
    char *expression = "/([^/][[:alnum:]]+(\\.)?[[:alnum:]]+)*$";
    //char *expression = "/(.+)?";
    if(findPattern(resourceURL, "/")){
        if(strstr(resourceURL, "//") != NULL){
            fprintf(stderr, "invalid resource name in URL:%s\n", resourceURL);
            return;
        }
        findMatchingString(resourceURL, expression, resourceBuf);
        
        if(strnlen(resourceBuf, BUF_SIZE) == 0){
            if(!findPattern(resourceURL, "/.+$")){
                //fprintf(stderr, "found pattern /.+ match\n");
                snprintf(resourceBuf, 2, "/");
            } else {
                //invalid characters in resource name after "/"
                fprintf(stderr, "invalid resource name in URL:%s\n", resourceURL);
            };
        }
    } else{
        //fprintf(stderr, "didn't find /\n");

        snprintf(resourceBuf, 2, "/");
    }
    return;
};


#define STATUS_CODE_LEN 4

/**
 * sendHTTPClear: sends the request in the string buffer to given socket
 * descriptor.
 * 
 * @param connfd: connected socket dexcriptor to send to.
 * @param requestBuf: buffer containing request.
 * @param requestLength: length of buffer to send.
*/
void sendHTTPClear(int connfd, char *requestBuf, size_t requestLength){
    if(connfd < 0 || requestBuf == NULL || requestLength == 0){
        fprintf(stderr, "sendHTTPRequest: invalid args passed\n");
        return;
    }

    int headerSize = requestLength;
    int totalBytesSent = 0;
    int bytesSent = 0;
    while(totalBytesSent < headerSize){
        if((bytesSent = send(connfd, requestBuf, headerSize - totalBytesSent, 0)) < 0){
            perror("sendHTTPRequest: send():");
            return;
        }
        totalBytesSent += bytesSent;
    }
    //fprintf(stderr, "successfully sent whole request\n");
    return;
};

/**
 * checkErrorCode: checks whether given response header is a 200
 * status code or not
 * @param headerBuf: string buffer with response header
 * @return: true when the status code is not 200
*/
bool checkForErrorCode(char *headerBuf){
    char *replica = strdup(headerBuf);
    char *firstLine = strtok(replica, "\n");
    if(strstr(firstLine, "200") == NULL){
        free(replica);
        return true;
    }
    free(replica);
    return false;
};
