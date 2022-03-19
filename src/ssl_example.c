/**
 * ssl_example.c: minimal example of using libssl and libcrypto to access
 * https website.
*/

#include <openssl/bio.h>
#include <openssl/err.h>
//#include <openssl/pem.h>
#include <openssl/ssl.h>
//#include <openssl/x509.h>
//#include <openssl/x509_vfy.h>

//#include <pthread.h>

#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/types.h>


#include <arpa/inet.h>
#include <netinet/in.h>
#include <netdb.h>
#include "ssl_example.h"
int OSSLErrorHandler(const char * string);
int TCPConnect(char *port, char *address);
int SendRequestTLS(SSL *ssl, char *request);
int ReceiveMessageTLS(SSL *ssl, char *recvBuffer);
int ReceiveSizeOfIncomingMessageTLS(SSL *ssl);
void *get_in_addr(struct sockaddr *sa);

int main(){
    char *hostname = "www.google.com";
    char *request = "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n";
    char recvBuffer[DEF_BUF_SIZE];
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    SSL *ssl;
    int server = -1;
    int ret = 0;

    

    (void)SSL_library_init();

    // Setting up error messages
    bio_err = BIO_new_fp(stderr, BIO_NOCLOSE);
    SSL_load_error_strings();

    //Set SSLv2 client hello, also announce SSLv3 and TLSv1
    ///method = SSLv23_client_method();
    method = TLS_client_method();

    // Create SSL Context with method
    if( (ctx = SSL_CTX_new(method)) == NULL){
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    //Set Context minimum protocol version to accept TLS v1.2
    ret = SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    if(ret == 0){
        OSSLErrorHandler("Can't set min proto version to TLS 1.2");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    //Set context cipher list to all the ciphers (bc I don't care which one I use)
    ret = SSL_CTX_set_cipher_list(ctx, FULL_CIPHER_LIST);
    if(ret == 0){
        OSSLErrorHandler("Can't set full cipher list in context");
        SSL_CTX_free(ctx);
        return 0;
    }

    //Set peer verify to default OSSL verification method
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    
    //Set certificate file for context
    SSL_CTX_use_certificate_chain_file(ctx, TRUSTED_CA_CERTS_FILE);

    //Load Locations where CA certs are located
    SSL_CTX_load_verify_locations(ctx, TRUSTED_CA_CERTS_FILE, NULL);

    



    // Initialize TCP socket to web server
    server = TCPConnect(DEF_PORT, hostname);

    // Create SSL object
    if((ssl = SSL_new(ctx)) == NULL){
        OSSLErrorHandler("SSL_new(): failed to create new SSL from ctx");
        close(server);
        return 0;
    }

    // Associate TCP socket with SSL object
    if(!(SSL_set_fd(ssl, server))){
        OSSLErrorHandler("SSL_set_fd() failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server);
        return 0;
    }

    // Associate desired hostname to SSL object
    SSL_set_tlsext_host_name(ssl, hostname);


    // Connect and do handshake
    SSL_set_connect_state(ssl);
    ret = SSL_do_handshake(ssl);
    if(ret < 0){
        SSL_get_error(ssl, ret);
        OSSLErrorHandler("SSL_do_handshake() failed");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server);
        return 0;
    };
    fprintf(stderr, "-->handshake ok\n");
    //Send request over SSL/TLS connection
    ret = SendRequestTLS(ssl, request);
    if(ret == -1){
        perror("main(): SendRequestTLS()");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server); 
        return 0;
    }

    // Receive response over TLS connection
    ret = ReceiveMessageTLS(ssl, recvBuffer);
    if(ret == -1){
        fprintf(stderr, "main():ReceiveMessageTLS()\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(server); 
        return 0;
    }
    // Cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(server);
    return EXIT_SUCCESS;
}

int OSSLErrorHandler(const char * string){
    BIO_printf(bio_err, "%s\n", string);
    ERR_print_errors(bio_err);
    //perror(string);
    return(0);
}

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

int SendRequestTLS(SSL *ssl, char *request){
    int r = 0;
    size_t length = 0;

    if(!request){
        fprintf(stderr, "SendRequestTLS():!request\n");
    }
    if(!ssl){
        fprintf(stderr, "SendRequestTLS():!ssl\n");
    }

    length = strlen(request);
    //check that the request length isn't too long

    r = SSL_write(ssl, request, length);
    if(r != (int)(length)){
        OSSLErrorHandler("SendRequestTLS(): SSL_write");
        return -1;
    }

    #ifdef DEBUG
        fprintf(stderr, "-->SendRequestTLS(): ok!\n");
    #endif
    return 0;
}

int ReceiveMessageTLS(SSL *ssl, char *recvBuffer){
    int bytesRecvd = 0;
    int retVal = 0;
    int stringlength;
    //retVal = ReceiveSizeOfIncomingMessageTLS(ssl);
    //if(retVal == -1){
    //    perror("ReceiveMessageTLS: int ReceiveMessageTLS()");
    //    return -1;
    //}
    stringlength = retVal;

    // Check that stringLength is the right size

    retVal = SSL_read(ssl, recvBuffer, DEF_BUF_SIZE);
    if(retVal <= 0){
        fprintf(stderr, "retVal:%d\n", retVal);
        OSSLErrorHandler("ReceiveMessageTLS: SSL_read()");
        return -1;
    }
    bytesRecvd = retVal;
    #ifdef DEBUG
        fprintf(stderr, "-->ReceiveMessageTLS(): bytes received %d\n",bytesRecvd);
        fprintf(stderr, "message:\n%s\n\n", recvBuffer);
    #endif

    return 0;
};

int ReceiveSizeOfIncomingMessageTLS(SSL *ssl){
    uint16_t msg_length_network_order = 0;
    uint16_t msg_length_host_order = 0;
    int r = 0;
    r = SSL_read(ssl, &msg_length_network_order, 2);
    if(r < 2){
        OSSLErrorHandler("ReceiveSizeOfIncomingMessageTLS");
        return -1;
    }
    msg_length_host_order = ntohs(msg_length_network_order);
    #ifdef DEBUG
        fprintf(stderr, "ReceiveSizeOfIncomingMessageTLS: %hu\n", msg_length_host_order);
    #endif
    return msg_length_host_order;
};