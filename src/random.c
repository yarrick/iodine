/* Copyright (c) 2006-2014 Erik Ekman <yarrick@kryo.se>,
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

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "config.h"

#if HAVE_GETRANDOM
#include <sys/random.h>
#endif

#ifdef WINDOWS
#include <windows.h>
#include <wincrypt.h>
#endif

#include "random.h"

/* Fill a buffer with random bytes.
 *
 * Prefer a CSPRNG: getrandom() (Linux >= 3.17 / glibc 2.25), arc4random()
 * (BSDs, and glibc 2.36+), /dev/urandom, and on Windows the CryptoAPI.
 * Fall back to rand() only if none of those are available at all.
 */
void
secure_random(void *buf, size_t len)
{
	unsigned char *p = (unsigned char *) buf;

#ifdef WINDOWS
	{
		HCRYPTPROV prov = 0;
		if (CryptAcquireContext(&prov, NULL, NULL,
			    PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
			if (CryptGenRandom(prov, len, (BYTE *) p)) {
				CryptReleaseContext(prov, 0);
				return;
			}
			CryptReleaseContext(prov, 0);
		}
	}
	while (len > 0) {
		unsigned int v = rand();
		size_t n = len < sizeof(v) ? len : sizeof(v);
		memcpy(p, &v, n);
		p += n;
		len -= n;
	}
	return;
#else
#if HAVE_GETRANDOM
	{
		ssize_t r;
		do {
			r = getrandom(p, len, 0);
		} while (r < 0 && errno == EINTR);
		if (r > 0) {
			p += r;
			len -= r;
		}
	}
	if (len == 0)
		return;
#endif

#if HAVE_ARC4RANDOM_BUF
	arc4random_buf(p, len);
	return;
#endif

	{
		int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
		if (fd >= 0) {
			while (len > 0) {
				ssize_t r = read(fd, p, len);
				if (r < 0) {
					if (errno == EINTR)
						continue;
					break;
				}
				if (r == 0)
					break;
				p += r;
				len -= r;
			}
			close(fd);
			if (len == 0)
				return;
		}
	}

	while (len > 0) {
		unsigned int v = rand();
		size_t n = len < sizeof(v) ? len : sizeof(v);
		memcpy(p, &v, n);
		p += n;
		len -= n;
	}
#endif
}
