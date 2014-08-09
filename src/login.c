/*
 * Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
 * 2006-2009 Bjorn Andersson <flex@kryo.se>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <string.h>
#include <sys/types.h>

#ifdef WINDOWS32
#include "windows.h"
#else
#include <netinet/in.h>
#include <arpa/inet.h>
#endif

#if defined( __APPLE__ )

    #include <CommonCrypto/CommonDigest.h>

    #ifdef MD5_DIGEST_LENGTH

        #undef MD5_DIGEST_LENGTH

    #endif

    #define MD5_Init            CC_MD5_Init
    #define MD5_Update          CC_MD5_Update
    #define MD5_Final           CC_MD5_Final
    #define MD5_DIGEST_LENGTH   CC_MD5_DIGEST_LENGTH
    #define MD5_CTX             CC_MD5_CTX

#else

    #include <openssl/md5.h>

#endif

/*
 * Needs a 16byte array for output, and 32 bytes password
 */
void
login_calculate(char *buf, int buflen, const char *pass, int seed)
{
        unsigned char temp[32];
        int *ix;
        int i;
        int k;

        if (buflen < 16)
                return;

        memcpy(temp, pass, 32);
        ix = (int*) temp;

        for (i = 0; i < 8; i++) {
                k = ntohl(*ix);
                k ^= seed;
                *ix++ = htonl(k);
        }

        MD5_CTX md5;
        MD5_Init(&md5);
        MD5_Update(&md5, temp, sizeof(temp));
        MD5_Final((unsigned char *)buf, &md5);
}

