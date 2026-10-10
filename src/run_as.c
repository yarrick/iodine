/*
 * Copyright (c) 2006-2015 Erik Ekman <yarrick@kryo.se>,
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

#include "config.h"
#include "run_as.h"
#include "compat.h"

#include <unistd.h>
#if HAVE_SETGROUPS
#include <grp.h>
#endif
#if HAVE_LIBCAPNG
#include <cap-ng.h>
#endif
#if HAVE_CHECKTOKENMEMBERSHIP
#include <windows.h>
#endif

/* Only used once to switch user the program is running as */
static struct run_as_user run_as;

struct run_as_user *
run_as_user_lookup(char *username)
{
#if HAVE_GETPWNAM
       run_as.pw = getpwnam(username);
       if (!run_as.pw)
               return NULL;
#endif
       return &run_as;
}

/* Returns non-zero on failure */
int
run_as_user_switch(struct run_as_user *runas)
{
#if HAVE_GETPWNAM && HAVE_LIBCAPNG
	return capng_change_id(runas->pw->pw_uid, runas->pw->pw_gid,
			       CAPNG_DROP_SUPP_GRP);
#elif HAVE_GETPWNAM
#if HAVE_SETGROUPS
       int result;
       gid_t gids[1];
       gids[0] = runas->pw->pw_gid;
       result = setgroups(1, gids);
       if (result < 0)
               return result;
#endif
       return (setgid(runas->pw->pw_gid) < 0 ||
               setuid(runas->pw->pw_uid) < 0);
#else
       warnx("switching user not supported");
       return 0;
#endif
}

void
run_thread_as_restricted_privilege_user(void)
{
#if HAVE_CHECKTOKENMEMBERSHIP
	HANDLE hProcessToken = NULL;
	HANDLE hRestrictedToken = NULL;
	HANDLE hImpersonationToken = NULL;
	PSID pEveryoneSid = NULL;
	SID_IDENTIFIER_AUTHORITY SidWorldAuthority = SECURITY_WORLD_SID_AUTHORITY;
	SID_AND_ATTRIBUTES sidToRestrict = { 0 };
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY, &hProcessToken)) {
		warnx("Failed to open process token, err %lu", GetLastError());
		return;
	}

	AllocateAndInitializeSid(&SidWorldAuthority, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &pEveryoneSid);
	sidToRestrict.Sid = pEveryoneSid;
	sidToRestrict.Attributes = 0;

	/* Strips all elevated privileges and disables Admin SIDs */
	if (CreateRestrictedToken(hProcessToken, DISABLE_MAX_PRIVILEGE,
				  0, NULL, 0, NULL, 1, &sidToRestrict, &hRestrictedToken)) {
		if (DuplicateToken(hRestrictedToken, SecurityImpersonation, &hImpersonationToken)) {
			if (!SetThreadToken(NULL, hImpersonationToken)) {
				warnx("Failed to set thread token, err %lu", GetLastError());
			}
			CloseHandle(hImpersonationToken);
		} else {
			warnx("Failed to duplicate token, err %lu", GetLastError());
		}
		CloseHandle(hRestrictedToken);
	} else {
		warnx("Failed to create restricted token, err %d", GetLastError());
	}
	FreeSid(pEveryoneSid);
	CloseHandle(hProcessToken);
#endif
}
