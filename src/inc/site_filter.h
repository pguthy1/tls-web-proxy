#ifndef __SITE_FILTER_H__
#define __SITE_FILTER_H__
#include <stdbool.h>
// returns NULL on error, forbiddenSiteBuf on success
char *getForbiddenSiteList(char *forbiddenSiteFname, char *forbiddenSiteBuf);
// returns true if matching IP or domain name found in request URL, false otherwise
bool siteIsForbidden(char *forbiddenBuffer, char *firstLine);
#endif
