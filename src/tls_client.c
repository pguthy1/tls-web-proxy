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

//Thread Headers
//#include <pthread.h>

// OpenSSL Headers
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>

// Custom Headers
#include "tls_client.h"
#include "tcp_module.h"
#include "ssl_example.h"
#include "site_filter.h"
#include "http_module.h"
#include "custom_regex.h"
//#define HOST_NAME "www.google.com"
//#define HOST_PORT "443"
//#define HOST_RESOURCE "/"

#define DEBUG 1
int TCPConnect(char *port, char *address);

// returns a concatenated string of given hostname and port
char *createTLSConnHostname(char *hostname, char *port){
    // determine size of new hostname string: hostname + : + port + \0
    size_t newStrLength = strlen(hostname)+strnlen(port, MAX_PORTSTR_LEN) + 1;
    char *newHostName = calloc(1, newStrLength + 1);
    snprintf(newHostName, MAX_HOST_LENGTH+MAX_PORTSTR_LEN+1+1, "%s:%s", hostname, port );
    return newHostName;
}
bool isWhiteSpace(char whiteChar){
    if(whiteChar == ' ' || whiteChar == '\t' || whiteChar == '\r' || 
    whiteChar == '\n' || whiteChar == '\v' || whiteChar == '\t'){
        return true;
    }
    return false;
}
// trims leading and trailing whitespace in a given string;
char *trimWhiteSpace(char *str){
    int index;
    int i;
    int j;
    index = 0;
    /* Find last index of whitespace character */
    while(isWhiteSpace(str[index])){
        index += 1;
    }
    if(index != 0){
        /* Shift all trailing characters to its left */
        i = 0;
        while(str[i + index] != '\0'){
            str[i] = str[i + index];
            i += 1;
        }
        //str[i] ='\0'; // Make sure that string is NULL terminated
    }
    //memset()
    //fprintf(stderr, "lead trimmed str:%s\n", str);
    for( j = 0; !isWhiteSpace(str[j]); j++);
    
    str[j] = '\0';
    //fprintf(stderr, "trailing trimmed:%s12341\n", str);
    return str;
}
void init_openssl_library(void)
{
  (void)SSL_library_init();

  SSL_load_error_strings();

  /* ERR_load_crypto_strings(); */
  
  //OPENSSL_config(NULL);
    
  /* Include <openssl/opensslconf.h> to get this define */
#if defined (OPENSSL_THREADS)
  fprintf(stdout, "Warning: thread locking is not implemented\n");
#endif
}

int verify_callback(int preverify, X509_STORE_CTX* x509_ctx)
{
    int depth = X509_STORE_CTX_get_error_depth(x509_ctx);
    //int err = X509_STORE_CTX_get_error(x509_ctx);
    
    X509* cert = X509_STORE_CTX_get_current_cert(x509_ctx);
    X509_NAME* iname = cert ? X509_get_issuer_name(cert) : NULL;
    X509_NAME* sname = cert ? X509_get_subject_name(cert) : NULL;
    
    fprintf(stderr, "Issuer:\n");
    X509_NAME_print_ex_fp(stderr, iname, 4, XN_FLAG_ONELINE | ~ASN1_STRFLGS_ESC_MSB);
    fprintf(stderr, "Subject:\n");
    X509_NAME_print_ex_fp(stderr, sname, 4, XN_FLAG_ONELINE | ~ASN1_STRFLGS_ESC_MSB);
    
    if(depth == 0) {
        /* If depth is 0, its the server's certificate. Print the SANs too */
        //print_san_name("Subject (san)", cert);
        fprintf(stderr, "depth 0\n");
    }

    return preverify;
}

void handleFailure(char *errString){
    fprintf(stderr,"error so I quit:%s\n", errString);
    //ERR_print_errors(bio_err);
    exit(EXIT_FAILURE);
}

int TLSConnectToServer(TLSArgs *argPtr){
    // args to pass this function
    
    SSL_CTX *ctx = NULL;
    int connfd = argPtr->connectionfd;
    int logfd = argPtr->logfd;
    struct sockaddr *clientAddr = argPtr->clientAddr;
    char *requestBuf = argPtr->requestBuffer ;
    //char *forbiddenSiteFileName = argPtr->forbiddenSiteFileName;
    char *forbiddenSiteBuffer = argPtr->forbiddenSiteBuffer;
    //int *totalSiteBufSize = argPtr->totalSiteBufSize;
    int *sitesReloadedFlag = argPtr->sitesReloadedFlag;
    //pthread_mutex_t *accessLogMutexPtr;

    
    long res = 1;
    BIO *web = NULL; 
    BIO *out = NULL;
    SSL *ssl = NULL;
    char hostname[MAX_HOST_LENGTH];
    char address[MAX_HOST_LENGTH];
    char port[MAX_PORTSTR_LEN];
    char *bio_hostname;
    
    memset(hostname, 0, MAX_HOST_LENGTH);
    memset(address, 0, MAX_HOST_LENGTH);
    memset(port, 0, MAX_PORTSTR_LEN);
    
    init_openssl_library();
    const SSL_METHOD* method = SSLv23_method();
    if(!(NULL != method)) handleFailure("SSLv23_method failed");

    ctx = SSL_CTX_new(method);
    if(!(ctx != NULL)) handleFailure("failed to create new context");

    /* Cannot fail ??? */
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);

    /* Cannot fail ??? */
    //SSL_CTX_set_verify_depth(ctx, 4);

    /* Cannot fail ??? */
    //const long flags = SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION;
   // SSL_CTX_set_options(ctx, flags);
    #ifdef DEBUG
    fprintf(stderr, "set options succesffuly\n");
    #endif

    res = SSL_CTX_load_verify_locations(ctx, "/usr/local/etc/ca-certificates/cert.pem", NULL);
    if(!(1 == res)) handleFailure("failed to load verify_locations");
    #ifdef DEBUG
    fprintf(stderr, "loaded verify locations success\n");
    #endif

    const char* const PREFERRED_CIPHERS = "HIGH:!aNULL:!kRSA:!PSK:!SRP:!MD5:!RC4";
    res = SSL_CTX_set_cipher_list(ctx, PREFERRED_CIPHERS);
    if(!(1 == res)) handleFailure("failed to set_cipher_list for CTX");

    web = BIO_new_ssl_connect(ctx);
    if(!(web != NULL)) handleFailure("failed to BIO_new_ssl_connect");

    //Set TLS Connection hostname
    getHostName(requestBuf, hostname);
    trimWhiteSpace(hostname);
    //char hostNameBuffer[MAX_HOST_LENGTH+MAX_PORTSTR_LEN+2];
    if(!findPattern(hostname, ":[1-9]+")){
        //HTTP Host header has NO PORT SPECIFIED
        setlinebuf(stderr);
        bio_hostname = createTLSConnHostname(hostname, DEF_PORT);
        strncpy(address, hostname, MAX_HOST_LENGTH);
        // Set Port to 443
        strncpy(port, DEF_PORT, MAX_PORTSTR_LEN);
        
        #ifdef DEBUG
        fprintf(stderr, "port:%s\naddress:%s\n", port, address);
        //fprintf(stderr, "ran createTLSConnHostname\n");
        //fprintf(stderr, "old host:%s\nnew host:%s\n", hostname, bio_hostname);
        #endif
        //defer free(bio_hostname);
    } else {
        // Found a port in the retrieved hostname
        bio_hostname = strndup(hostname, MAX_HOST_LENGTH);
        getPortFromURL(bio_hostname, port);
        char *colonPtr = strchr(hostname, ':');
        strncpy(address, hostname,(colonPtr - hostname));
        #ifdef DEBUG
        fprintf(stderr, "port:%s\naddress:%s\n", port, address);
        #endif
    }

    res = BIO_set_conn_hostname(web, bio_hostname);
    if(!(1 == res)) handleFailure("failed to set bio_hostname");

    BIO_get_ssl(web, &ssl);
    if(!(ssl != NULL)) handleFailure("failed to BIO_get_ssl");

    // Enable SNI
    res = SSL_set_tlsext_host_name(ssl, hostname+1);
    if(!(1 == res)) handleFailure("failed SSL_set_tlsext_host_name");

    out = BIO_new_socket(connfd, BIO_CLOSE);
    if(!(NULL != out)) handleFailure("failed BIO_new_socket");
    
    
    // set timeout for BIO
    //int biofd;
    int websocketd = TCPConnect(port, address);
    fprintf(stderr, "websocketd:%d\n", websocketd);
    if(!(SSL_set_fd(ssl, websocketd))){
        handleFailure("SSL_set_fd failed");
        return 0;
    }
    struct timeval timeout;
    timeout.tv_sec = SSL_TIMEOUT;
    timeout.tv_usec = 0;
    if(setsockopt(websocketd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0){
        perror("setsockopt");
    };
    
    // Connect and Do Handshake
    //BIO_set_nbio(web, (long)1);
   // while(BIO_should_retry(web)){
    res = BIO_do_connect(web);
    //}
    
    if(!(1 == res)) {
        handleFailure("failed BIO_do_connect");
    }
   // while(BIO_should_retry(web)){
        res = BIO_do_handshake(web);
   // }
    if(!(1 == res)) handleFailure("failed BIO_do_handshake");

    /* Step 1: verify a server certificate was presented during the negotiation */
    X509* cert = SSL_get_peer_certificate(ssl);
    if(cert) { X509_free(cert); } /* Free immediately */
    if(NULL == cert) handleFailure("failed SSL_get_peer_cert");

    /* Step 2: verify the result of chain verification */
    /* Verification performed according to RFC 4158    */
    res = SSL_get_verify_result(ssl);
    if(!(X509_V_OK == res)) handleFailure("failed SSL_get_verify_result");

    /* Step 3: hostname verification */
    /* An exercise left to the reader */

    BIO_puts(web, requestBuf);
    //BIO_puts(out, "\n");
    char errCode[CODE_STR_LEN];
    memset(errCode, 0, CODE_STR_LEN);
    int len = 0;
    int totalResponseSize = 0;
    // Get first line of request
    char *ptr;
    char *requestCopy = strdup(requestBuf);
    char *firstLine = strtok_r(requestCopy, "\n", &ptr);
    do
    {
        if(*sitesReloadedFlag){
            if(siteIsForbidden(forbiddenSiteBuffer, firstLine) ||
            siteIsForbidden(forbiddenSiteBuffer, hostname)){
                strncpy(errCode, CODE_403, CODE_STR_LEN);
                #ifdef DEBUG
                fprintf(stderr, "site reloaded now forbidden\n");
                #endif
                break;
            } else {
                #ifdef DEBUG
                fprintf(stderr, "site still allowed\n");
                #endif
            }
            *sitesReloadedFlag = 0;
        }
        char buff[1536] = {};
        //fprintf(stderr, "entering bio_read\n");
        len = BIO_read(web, buff, sizeof(buff));
        if(BIO_should_retry(web)){
            fprintf(stderr, "read:should_retry is true\n");
        }
        //fprintf(stderr, "exiting bio_read\n");        
        if(len > 0){
            totalResponseSize += len;
            int writeRetVal = BIO_write(out, buff, len);//writes to given connection descriptor
            if(writeRetVal <= 0){
                if(out){
                    BIO_free(out);
                }
                if(web != NULL){
                    BIO_free_all(web);
                }
                free(bio_hostname);
                if(NULL != ctx){
                    SSL_CTX_free(ctx);
                }
                return 0;
            }
        }
        fprintf(stderr, "len:%d\n", len);
        
        if(BIO_should_retry(web)){
            fprintf(stderr, "write:should_retry is true\n");
        }
    } while (len > 0);
    free(requestCopy);
    #ifdef DEBUG
    fprintf(stderr, "broke out of while loop\n");
    #endif
    if(strnlen(errCode, CODE_STR_LEN) == 0){// error code hasn't already been set
         #ifdef DEBUG
        fprintf(stderr, "setting 200 code\n");
        #endif
        strncpy(errCode, CODE_200, CODE_STR_LEN);
    }
    
    // Write result of HTTP request into access log
    //pthread_mutex_lock(accessLogMutexPtr);
    logResult(logfd, clientAddr, requestBuf, errCode, totalResponseSize);
    //pthread_mutex_unlock(accessLogMutexPtr);
    
    // Clean up
    if(out)
    BIO_free(out);

    if(web != NULL)
    BIO_free_all(web);

    free(bio_hostname);

    if(NULL != ctx)
    SSL_CTX_free(ctx);
    return 0;
}

int TCPConnect(char *port, char *address){
    int sockfd;
    struct addrinfo hints, *res, *p;
    int status;
    char s[INET6_ADDRSTRLEN];

    if(memset(&hints, 0, sizeof hints) != (void*) &hints){
        fprintf(stderr, "memset failed\n");
        exit(EXIT_FAILURE);
    }

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if((status = getaddrinfo(address, port, &hints, &res)) != 0){
        fprintf(stderr, "getaddrinfo failed : %s", gai_strerror(status));
        exit(EXIT_FAILURE);
    }

    for(p = res; p != NULL; p = p->ai_next){
        if((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1){
            perror("server: socket");
            continue;
        }

        if(connect(sockfd, p->ai_addr, p->ai_addrlen) == -1){
            close(sockfd);
            perror("server: connect");
            continue;
        }
        break;
    }

    if(p == NULL){
        fprintf(stderr, "client: failed to connect\n");
        exit(EXIT_FAILURE);
    }

    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof(s));
    printf("client: connecting to %s\n", s);

    freeaddrinfo(res);
    return sockfd;
}

