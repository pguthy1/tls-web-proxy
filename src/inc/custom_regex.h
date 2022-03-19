#ifndef __CUSTOM_REGEX_H__
#define __CUSTOM_REGEX_H__
#include <stdbool.h>
#include <regex.h>
#define MAX_IP_LEN 16
bool verifyEndOfHeader(char *buf);
bool findPattern(char *buf, char *pattern);
void findMatchingString(char *srcBuf, char *pattern, char *dstBuf);
regmatch_t findPatternOffset(char *srcBuf, char *pattern);
#endif