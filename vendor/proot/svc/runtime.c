/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Small freestanding string runtime. Compile with -fno-builtin. */
#include <stddef.h>
#include <stdint.h>
void *memcpy(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char *b=s;for(size_t i=0;i<n;i++)a[i]=b[i];return d;}
void *memset(void *d,int c,size_t n){unsigned char *a=d;for(size_t i=0;i<n;i++)a[i]=(unsigned char)c;return d;}
void *memmove(void *d,const void *s,size_t n){unsigned char *a=d;const unsigned char *b=s;if((uintptr_t)a<(uintptr_t)b){for(size_t i=0;i<n;i++)a[i]=b[i];}else{while(n){n--;a[n]=b[n];}}return d;}
size_t strlen(const char *s){size_t n=0;while(s[n])n++;return n;}
size_t strnlen(const char *s,size_t m){size_t n=0;while(n<m&&s[n])n++;return n;}
int strcmp(const char *a,const char *b){while(*a&&*a==*b){a++;b++;}return (unsigned char)*a-(unsigned char)*b;}
int strncmp(const char *a,const char *b,size_t n){for(size_t i=0;i<n;i++){int d=(unsigned char)a[i]-(unsigned char)b[i];if(d||!a[i])return d;}return 0;}
char *strcpy(char *d,const char *s){size_t i=0;do{d[i]=s[i];}while(s[i++]);return d;}
char *strncpy(char *d,const char *s,size_t n){size_t i=0;for(;i<n&&s[i];i++)d[i]=s[i];for(;i<n;i++)d[i]=0;return d;}
char *strcat(char *d,const char *s){strcpy(d+strlen(d),s);return d;}
char *strchr(const char *s,int c){for(;;s++){if(*s==(char)c)return (char*)s;if(!*s)return NULL;}}
