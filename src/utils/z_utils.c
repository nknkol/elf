#include "z_utils.h"

void *z_memset(void *s, int c, size_t n)
{
	unsigned char *p = s, *e = p + n;
	while (p < e)
		*p++ = c;
	return s;
}

void *z_memcpy(void *dest, const void *src, size_t n)
{
	unsigned char *d = dest;
	const unsigned char *p = src, *e = p + n;
	while (p < e)
		*d++ = *p++;
	return dest;
}

int z_strncmp(const char *s1, const char *s2, size_t n)
{
	for (size_t i = 0; i < n; i++) {
		if (s1[i] != s2[i])
			return s1[i] - s2[i];
		if (s1[i] == '\0')
			return 0;
	}
	return 0;
}

int z_atoi(const char *s)
{
	int res = 0;
	int sign = 1;
	if (*s == '-') {
		sign = -1;
		s++;
	} else if (*s == '+') {
		s++;
	}
	while (*s >= '0' && *s <= '9')
		res = res * 10 + (*s++ - '0');
	return res * sign;
}

char *z_strchr(const char *s, int c)
{
	while (*s != (char)c) {
		if (!*s++)
			return 0;
	}
	return (char *)s;
}

size_t z_strlen(const char *s)
{
	size_t n = 0;
	while (s && s[n])
		n++;
	return n;
}
