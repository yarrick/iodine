
#ifndef __FIX_ANDROID_H__
#define __FIX_ANDROID_H__

typedef struct {
	unsigned id :16;
	unsigned rd :1;
	unsigned tc :1;
	unsigned aa :1;
	unsigned opcode :4;
	unsigned qr :1;
	unsigned rcode :4;
	unsigned cd: 1;
	unsigned ad: 1;
	unsigned unused :1;
	unsigned ra :1;
	unsigned qdcount :16;
	unsigned ancount :16;
	unsigned nscount :16;
	unsigned arcount :16;
} HEADER;

#define NOERROR		0
#define FORMERR		1
#define SERVFAIL	2
#define NXDOMAIN	3
#define NOTIMP		4
#define REFUSED		5

#define C_IN		1

#define T_A			1
#define T_CNAME		5
#define T_NULL		10
#define T_MX		15
#define T_TXT		16
#define T_SRV		33

#endif
