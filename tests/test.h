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

#ifndef __TEST_H__
#define __TEST_H__

TCase *test_base32_create_tests();
TCase *test_base64_create_tests();
TCase *test_common_create_tests();
TCase *test_dns_create_tests();
TCase *test_encoding_create_tests();
TCase *test_read_create_tests();
TCase *test_login_create_tests();
TCase *test_user_create_tests();
TCase *test_fw_query_create_tests();

char *va_str(const char *, ...);

#if (CHECK_MAJOR_VERSION == 0 && \
	((CHECK_MINOR_VERSION == 9 && CHECK_MICRO_VERSION < 2) || \
	 (CHECK_MINOR_VERSION < 9)))
#define tcase_set_timeout(...)
#endif

#endif
