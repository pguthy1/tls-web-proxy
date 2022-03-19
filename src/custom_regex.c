#include "custom_regex.h"
#include <stdbool.h>
#include <regex.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h> // has the memset() function for some reason.
#define BUF_SIZ 4096
#define MATCH_NUM 1
// verifyEndOfHeader: Returns true when the double CRLF
// regex pattern is found in the string buffer passed to the
// function.
// buf: string buffer that will be searched using the regex.
bool verifyEndOfHeader(char *buf){
    if (findPattern(buf, "(\r\n){2}")){
        return true;
    }
    return false;
}

bool findPattern(char *buf, char *pattern){
    if(buf == NULL || pattern == NULL){
        fprintf(stderr, "FINDPATTERN: NULL arg(s) passed\n");
        return false;
    }

    char *expression = pattern;
    regex_t regex;
    char errbuf[BUF_SIZ];
    int regexCompStatus = regcomp(&regex, expression, REG_EXTENDED);
    int reMatchStatus = 0;
    if(regexCompStatus != 0){
        regerror(regexCompStatus, &regex, errbuf, sizeof errbuf);
        fprintf(stderr, "regerror:%s\n", errbuf);
        return false;
    }
    else {
        //fprintf(stderr, "regex compilation successful\n");
    }
    size_t desiredMatches = MATCH_NUM;
    regmatch_t matchOffsetArray[desiredMatches];
    memset(matchOffsetArray, 0, sizeof matchOffsetArray);
    reMatchStatus = regexec(&regex, buf, desiredMatches, matchOffsetArray, 0);

    if(reMatchStatus != 0){
        regerror(reMatchStatus, &regex, errbuf, sizeof errbuf);
        //fprintf(stderr, "regerror:%s\n", errbuf);
        regfree(&regex);
        return false;
    } else {
        //regmatch_t match = matchOffsetArray[0];
        //fprintf(stderr, "found a match at positions: start:%d end:%d\n", match.rm_so, match.rm_eo);
        regfree(&regex);
        return true;
    }
    return false;
}

void findMatchingString(char *srcBuf, char *pattern, char *dstBuf){
    char *expression = pattern;
    regex_t regex;
    char errbuf[BUF_SIZ];
    int regexCompStatus = regcomp(&regex, expression, REG_EXTENDED);
    int reMatchStatus = 0;
    if(regexCompStatus != 0){
        regerror(regexCompStatus, &regex, errbuf, sizeof errbuf);
        fprintf(stderr, "regerror:%s\n", errbuf);
        return;
    }
    else {
        //fprintf(stderr, "regex compilation successful\n");
    }
    size_t desiredMatches = MATCH_NUM;
    regmatch_t matchOffsetArray[desiredMatches];
    reMatchStatus = regexec(&regex, srcBuf, desiredMatches, matchOffsetArray, 0);

    if(reMatchStatus != 0){
        regerror(reMatchStatus, &regex, errbuf, sizeof errbuf);
        //fprintf(stderr, "regerror:%s\n", errbuf);
        regfree(&regex);
        return;
    } else {
        regoff_t matchStart = matchOffsetArray[0].rm_so;
        regoff_t matchEnd = matchOffsetArray[0].rm_eo;
        //fprintf(stderr, "found a match at positions: start:%d end:%d\n", matchStart, matchEnd);
        if((matchStart - matchEnd) > (long long)sizeof dstBuf){
            fprintf(stderr, "dstBuffer not big enough to write pattern match\n");
            regfree(&regex);
            return;
        }
        sprintf(dstBuf, "%.*s",(int)(matchEnd - matchStart), srcBuf+matchStart );
        regfree(&regex);
        return;
    }
    return ;
};

regmatch_t findPatternOffset(char *srcBuf, char *pattern){
    char *expression = pattern;
    regex_t regex;
    size_t desiredMatches = MATCH_NUM;
    regmatch_t matchOffsetArray[desiredMatches];
    regmatch_t errorVal;
    errorVal.rm_so = 0;
    errorVal.rm_eo = 0;
    char errbuf[BUF_SIZ];
    int regexCompStatus = regcomp(&regex, expression, REG_EXTENDED);
    int reMatchStatus = 0;
    if(regexCompStatus != 0){
        regerror(regexCompStatus, &regex, errbuf, sizeof errbuf);
        fprintf(stderr, "regerror:%s\n", errbuf);
        return errorVal;
    }
    else {
        //fprintf(stderr, "regex compilation successful\n");
    }
    
    memset(matchOffsetArray, 0, sizeof matchOffsetArray);
    reMatchStatus = regexec(&regex, srcBuf, desiredMatches, matchOffsetArray, 0);

    if(reMatchStatus != 0){
        regerror(reMatchStatus, &regex, errbuf, sizeof errbuf);
        //fprintf(stderr, "regerror:%s\n", errbuf);
        regfree(&regex);
        return errorVal;
    }
    //regoff_t matchStart = matchOffsetArray[0].rm_so;
    //regoff_t matchEnd = matchOffsetArray[0].rm_eo;
    //fprintf(stderr, "found a match at positions: start:%d end:%d\n", matchStart, matchEnd);
    
    regfree(&regex);
    return matchOffsetArray[0];
}


