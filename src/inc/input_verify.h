/******************************************************************************
 * input_verify.h: 
 * This header file specifies input validation functions for user input 
 * and HTTP headers using TCP/IPv4 sockets. 
******************************************************************************/
#ifndef __INPUT_VERIFY_H__
#define __INPUT_VERIFY_H__
#include <stdbool.h>
/**
 * verifyURL: checks that the URL is valid. Specifically checks that the IPv4 
 * address is valid, the port number given(if, any) is valid and if the 
 * resource name is valid.
 * 
 * @param urlBuffer string buffer with the URL.
 * @return true if IPv4 address, port number, and resource name are all valid,
 *          false otherwise.
*/
bool verifyURL(char *urlBuffer);

/**
 * verifyHostName: checks that the hostname is valid using regex based on RFC 
 * 1123 Section 2.1 .
 * @param hostName string buffer containing the hostname to check
 * @return true for valid Hostnames
*/
bool verifyHostname(char *hostName);

/**
 * checkHostnameURLMatch: checks that the IP address in the given URL
 * and the hostname's IP address match
 * 
 * @param hostName: string buffer containing hostname
 * @param urlBuffer: string buffer containing IP address
 * @return true if hostname and provided IP address match
*/
bool checkHostnameURLMatch(char *hostname, char *urlBuffer);

/**
 * verifyResponseHeader: verifies that the received HTTP response header isn't
 * malformed.
 * 
 * @param responseBuf: string buffer containing HTTP response header
 * @return true if the HTTP response string is correctly formatted
 */
bool verifyResponseHeader(char *responseBuf);

/**
 * checkTransferEncoding: verifies that the Transfer-Encoding header field is
 * not set to "chunked"
 * 
 * @param responseBuf: string buffer containing responseHeader
 * @return true when transfer-encoding field is not set to chunked
*/
bool checkTransferEncoding(char *responseBuf);
#endif
