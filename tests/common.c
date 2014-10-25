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

#include <check.h>
#include <common.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>

START_TEST(test_topdomain_ok)
{
        char *error;

        fail_if(check_topdomain("foo.0123456789.qwertyuiop.asdfghjkl.zxcvbnm.com", &error));

        /* Not allowed to start with dot */
        fail_unless(check_topdomain(".foo.0123456789.qwertyuiop.asdfghjkl.zxcvbnm.com", &error));
        fail_if(strcmp("Starts with a dot", error));

        /* Test missing error msg ptr */
        fail_unless(check_topdomain(".foo", NULL));
}
END_TEST

START_TEST(test_topdomain_length)
{
        char *error;

        /* Test empty and too short */
        fail_unless(check_topdomain("", &error));
        fail_if(strcmp("Too short (< 3)", error));
        fail_unless(check_topdomain("a", &error));
        fail_if(strcmp("Too short (< 3)", error));
        fail_unless(check_topdomain(".a", &error));
        fail_if(strcmp("Too short (< 3)", error));
        fail_unless(check_topdomain("a.", &error));
        fail_if(strcmp("Too short (< 3)", error));
        fail_unless(check_topdomain("ab", &error));
        fail_if(strcmp("Too short (< 3)", error));
        fail_if(check_topdomain("a.b", &error));
        fail_if(strcmp("Too short (< 3)", error));

        /* Test too long (over 128, need rest of space for data) */
        fail_unless(check_topdomain(
                "abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
                "abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
                "abcd12345.abcd12345.foo129xxx", &error));
        fail_if(strcmp("Too long (> 128)", error));
        fail_if(check_topdomain(
                "abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
                "abcd12345.abcd12345.abcd12345.abcd12345.abcd12345."
                "abcd12345.abcd12345.foo128xx", &error));
}
END_TEST

START_TEST(test_topdomain_chunks)
{
        char *error;

        /* Must have at least one dot */
        fail_if(check_topdomain("abcde.gh", &error));
        fail_unless(check_topdomain("abcdefgh", &error));
        fail_if(strcmp("No dots", error));

        /* Not two consecutive dots */
        fail_unless(check_topdomain("abc..defgh", &error));
        fail_if(strcmp("Consecutive dots", error));

        /* Not end with a dots */
        fail_unless(check_topdomain("abc.defgh.", &error));
        fail_if(strcmp("Ends with a dot", error));

        /* No chunk longer than 63 chars */
        fail_if(check_topdomain("123456789012345678901234567890"
                "123456789012345678901234567890333.com", &error));
        fail_unless(check_topdomain("123456789012345678901234567890"
                "1234567890123456789012345678904444.com", &error));
        fail_if(strcmp("Too long domain part (> 63)", error));

        fail_if(check_topdomain("abc.123456789012345678901234567890"
                "123456789012345678901234567890333.com", &error));
        fail_unless(check_topdomain("abc.123456789012345678901234567890"
                "1234567890123456789012345678904444.com", &error));
        fail_if(strcmp("Too long domain part (> 63)", error));

        fail_if(check_topdomain("abc.123456789012345678901234567890"
                "123456789012345678901234567890333", &error));
        fail_unless(check_topdomain("abc.123456789012345678901234567890"
                "1234567890123456789012345678904444", &error));
        fail_if(strcmp("Too long domain part (> 63)", error));
}
END_TEST

START_TEST(test_parse_format_ipv4)
{
        char *host = "192.168.2.10";
        char *formatted;
        struct sockaddr_storage addr;
        struct sockaddr_in *v4addr;
        int addr_len;

        addr_len = get_addr(host, 53, AF_INET, 0, &addr);
        fail_unless(addr_len == sizeof(struct sockaddr_in));

        v4addr = (struct sockaddr_in *) &addr;
        fail_unless(v4addr->sin_addr.s_addr == htonl(0xc0a8020a));
        fail_unless(v4addr->sin_port == htons(53));

        formatted = format_addr(&addr, addr_len);
        fail_if(strcmp(host, formatted));
}
END_TEST

START_TEST(test_parse_format_ipv4_listen_all)
{
        char *host = "0.0.0.0";
        char *formatted;
        struct sockaddr_storage addr;
        struct sockaddr_in *v4addr;
        int addr_len;

        addr_len = get_addr(NULL, 53, AF_INET, AI_PASSIVE, &addr);
        fail_unless(addr_len == sizeof(struct sockaddr_in));

        v4addr = (struct sockaddr_in *) &addr;
        fail_unless(v4addr->sin_addr.s_addr == htonl(0x00000000));
        fail_unless(v4addr->sin_port == htons(53));

        formatted = format_addr(&addr, addr_len);
        fail_if(strcmp(host, formatted));
}
END_TEST

START_TEST(test_parse_format_ipv6)
{
        char *host = "2001:0db8:0505:0::123:0abc";
        char *compact = "2001:db8:505::123:abc";
        unsigned char v6_bits[] = {
                0x20, 0x01, 0x0d, 0xb8, 0x05, 0x05, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x01, 0x23, 0x0a, 0xbc,
        };
        char *formatted;
        struct sockaddr_storage addr;
        struct sockaddr_in6 *v6addr;
        int addr_len;

        addr_len = get_addr(host, 53, AF_UNSPEC, 0, &addr);
        fail_unless(addr_len == sizeof(struct sockaddr_in6));

        v6addr = (struct sockaddr_in6 *) &addr;
        fail_if(memcmp(&v6addr->sin6_addr, v6_bits, sizeof(v6_bits)));
        fail_unless(v6addr->sin6_port == htons(53));

        formatted = format_addr(&addr, addr_len);
        fail_if(strcmp(compact, formatted));
}
END_TEST

START_TEST(test_parse_format_ipv4_mapped_ipv6)
{
        char *v4mapped = "::FFFF:192.168.2.10";
        char *host = "192.168.2.10";
        unsigned char v6_bits[] = {
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0xff, 0xff, 0xc0, 0xa8, 0x02, 0x0a,
        };
        char *formatted;
        struct sockaddr_storage addr;
        struct sockaddr_in6 *v6addr;
        int addr_len;

        addr_len = get_addr(v4mapped, 53, AF_INET6, 0, &addr);
        fail_unless(addr_len == sizeof(struct sockaddr_in6));

        v6addr = (struct sockaddr_in6 *) &addr;
        fail_if(memcmp(&v6addr->sin6_addr, v6_bits, sizeof(v6_bits)));
        fail_unless(v6addr->sin6_port == htons(53));

        /* Format as IPv4 address */
        formatted = format_addr(&addr, addr_len);
        fail_if(strcmp(host, formatted));
}
END_TEST

TCase *
test_common_create_tests()
{
        TCase *tc;
        int sock;

        tc = tcase_create("Common");
        tcase_add_test(tc, test_topdomain_ok);
        tcase_add_test(tc, test_topdomain_length);
        tcase_add_test(tc, test_topdomain_chunks);
        tcase_add_test(tc, test_parse_format_ipv4);
        tcase_add_test(tc, test_parse_format_ipv4_listen_all);

        /* Tests require IPv6 support */
        sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
        if (sock >= 0) {
                close(sock);
                tcase_add_test(tc, test_parse_format_ipv6);
                tcase_add_test(tc, test_parse_format_ipv4_mapped_ipv6);
        }
        return tc;
}
