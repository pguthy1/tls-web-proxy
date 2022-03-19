/******************************************************************************
 * tcp_client.h: 
 * This header file specifies the TCP wrapper functions for setting up a TCP
 * client connection with a server functions using TCP/IPv4 sockets. 
 * There are also several helper functions included in this header file for 
 * input processing.
******************************************************************************/
#ifndef __TCP_CLIENT_H__
#define __TCP_CLIENT_H__

#include <sys/socket.h>
#include <sys/types.h>
// Network Headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
//Macros for Size limits
#define MAX_IPSTR_LEN 16
#define MAX_PORTSTR_LEN 6//max number of digits + '\0'
#define TCP_SOCK_ERR -1
/**
 * initializeTcpClientConnection: Initializes internet socket with proper
 * parameters for a TCP/IPv4 listening socket. 
 * 
 * @param portNum: string with port number for proxy server to bind to.
 * @return socket descriptor with connection to client. returns -1 on errors.
 * 
*/
int initializeTcpServerConnection(char *portNum);

/**
 * configHints: configures hints for getaddrinfo() function.
 * 
 * @param hintsPtr: pointer to struct addrinfo that will be populated.
*/
void configHints(struct addrinfo *hintsPtr);


/**
 * getAddrFromURL: extracts and validates IP address from provided URL.
 * 
 * @param addrURL: string containing the IP address.
 * @param addrBuf: character string buffer that will contain the IP address string.
 * @return string buffer with the IP address. Returns NULL on error.
*/
void getAddrFromURL(char *addrURL, char *addrBuf);


/**
 * getPortFromURL: extracts and validates the provided portnumber, if it
 * was given in the URL.Default value is port 443.
 * 
 * @param portURL: string containing URL to be parsed.
 * @param portBuf: string that will contain the port number.
 * @return string buffer with port number. Returns NULL on error.
*/
void getPortFromURL(char *portURL, char *portBuf);
void getPortFromStr(char *portURL, char *portBuf);
void getHostNameFromURL(char *URLBuffer, char *domainNameBuf);
void *get_in_addr(struct sockaddr *sa);
#endif
