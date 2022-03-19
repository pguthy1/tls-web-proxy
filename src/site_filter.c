// Standard Library Headers
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
// System Headers
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
// Network Headers
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>


#include "site_filter.h"
#include "tcp_module.h"
#include "ssl_example.h"
#include "tls_client.h"
#include "custom_regex.h"

bool forbiddenSitesValid(char *siteBuffer){
    char *siteCopy = strndup(siteBuffer, DEF_BUF_SIZE);
    char *ptr;
    char *linePtr = strtok_r(siteCopy, "\n", &ptr);
    char addrBuf[MAX_IPSTR_LEN];
    char domainNameBuf[MAX_HOST_LENGTH];
    memset(addrBuf, 0, MAX_IPSTR_LEN);
    memset(domainNameBuf, 0, MAX_HOST_LENGTH);
    do{
        getAddrFromURL(linePtr, addrBuf);
        if(strnlen(addrBuf, MAX_IPSTR_LEN) == 0){
            //didn't find IP address
            // check for hostname
            getHostNameFromURL(linePtr, domainNameBuf);
            if(strnlen(domainNameBuf, MAX_HOST_LENGTH) == 0){
                // didn't find valid hostname or IP on this line
                fprintf(stderr, "invalid line:<<%s>>\n", linePtr);
                free(siteCopy);
                return false;
            } else {
                //fprintf(stderr, "HOSTNAME CHECK: %s\n", domainNameBuf);
            }
        } else {
            //fprintf(stderr, "IP ADDRESS CHECK:%s\n", addrBuf);
        }
        linePtr = strtok_r(NULL, "\n", &ptr);
    } while(linePtr != NULL);
    free(siteCopy);
    return true;
}
// returns NULL on error, forbiddenSiteBuf on success
char *getForbiddenSiteList(char *forbiddenSiteFname, char *forbiddenSiteBuf){
    int forbidfd = open(forbiddenSiteFname, O_RDONLY);
    if(forbidfd < 0){
        fprintf(stderr, "couldn't open forbidden sites file\n");
        return NULL;
    }
    memset(forbiddenSiteBuf, 0, DEF_BUF_SIZE);
    int totalBytesRead = 0;
    int bytesRead = 0;
    while(totalBytesRead < DEF_BUF_SIZE){
        bytesRead = read(forbidfd, forbiddenSiteBuf, DEF_BUF_SIZE);
        if(bytesRead < 0 ){
            perror("getForbiddenSiteList: read()");
            close(forbidfd);
            return NULL;
        }
        if(bytesRead == 0){
            #ifdef DEBUG
            //fprintf(stderr, "EOF reached\n");
            #endif
            break;
        }
        totalBytesRead += bytesRead;
    }
    if(!forbiddenSitesValid(forbiddenSiteBuf)){
        //fprintf(stderr, "site buffer not valid\n");
        close(forbidfd);
        return NULL;
    }
    #ifdef DEBUG
    //fprintf(stderr, "forbidden buffer:\n%s\n", forbiddenSiteBuf);
    #endif
    close(forbidfd);
    return forbiddenSiteBuf;
};

// returns true if matching IP or domain name found in request URL, false otherwise
bool siteIsForbidden(char *forbiddenBuffer, char *firstLine){
    char *ptr;
    char *forbidCopy = strndup(forbiddenBuffer, DEF_BUF_SIZE);
    char *linePtr = strtok_r(forbidCopy, "\n", &ptr);

    do{
        if(findPattern(firstLine, linePtr)){
            //fprintf(stderr, "fobidden site <<%s>> is found in <<%s>>", linePtr, firstLine);
            free(forbidCopy);
            return true;
        }
        linePtr = strtok_r(NULL, "\n", &ptr);
    } while(linePtr != NULL);
    free(forbidCopy);
    return false;
};
