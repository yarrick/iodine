# Process this file with autoconf to produce a configure script.

# Prologue

AC_PREREQ([2.69])
AC_INIT([iodine],[0.7.0],[erik@kryo.se],[],[http://dev.kryo.se/iodine/])
AC_CONFIG_SRCDIR([src/iodine.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([autotools])
AC_CONFIG_AUX_DIR([autotools])
AM_INIT_AUTOMAKE([subdir-objects foreign -Wall])

# Misc

# Define OS to upcased "uname --kernel-name", i.e., LINUX, DARWIN, etc.
# Used by Makefile.am as cpp symbol to define.
# We use autotools canonical designation to allow cross compilation.
# It would be reasonable to, at some point, update the C sources to
# use these more canonical designations.
# But for now, we must adjust some of them.

AC_MSG_CHECKING([environment to compile for])
AC_CANONICAL_HOST

# No need to adjust these: FREEBSD, NETBSD, OPENBSD, BEOS
AS_CASE([${host_os}],
 [linux-gnu],        [OS=LINUX],
 [mingw32],          [OS=WINDOWS32],
 [macos],            [OS=DARWIN],
 [linux-android],    [OS=ANDROID],
 [OS="$(echo ${host_os}|tr "a-z" "A-Z_")"])

uname_os="$(uname | tr "a-z" "A-Z")"

AC_MSG_NOTICE([host_os: ${host_os}])
AC_MSG_NOTICE([uname_os: ${uname_os}])
AC_MSG_NOTICE([adjusted OS: ${OS}])

AC_SUBST([OS])

AS_CASE([${OS}],
  [WINDOWS32],
    AC_DEFINE([WINVER],[0x0501],
      [Define appropriately on MS Windows 32]))

# The AC_SUBST for GITREVISION is used only in legacy stanza; remove
# when unused in Makefile.am, leaving only the config.h #define.

AC_SUBST([GITREVISION],[$(git describe --tags --always --dirty || echo not-in-git)])
AC_DEFINE_UNQUOTED([GITREVISION],["${GITREVISION}"],
  [Precise git commit checked out when building])

# Checks for programs

AC_PROG_CC
AC_PROG_CC_STDC
AS_IF([test "x${ac_cv_prog_cc_stdc}" = xno],
      [AC_MSG_WARN([Unable to engage Standard C (C99) option])],)
# This is to avoid
#    error: invalid application of ‘sizeof’ to incomplete type ‘struct in6_pktinfo’
# whose definition is guarded by _GNU_SOURCE
AC_USE_SYSTEM_EXTENSIONS
AX_CFLAGS_WARN_ALL
AC_PROG_INSTALL

# Process options

AC_ARG_ENABLE([systemd],
  [AS_HELP_STRING([--enable-systemd],
    [enable systemd support @<:@default=check@:>@])],,
  [enable_systemd=check])

AC_ARG_ENABLE([selinux],
  [AS_HELP_STRING([--enable-selinux],
    [enable selinux support @<:@default=check@:>@])],,
  [enable_selinux=check])

# Checks for libraries

# Unclear why pthread is needed.
# Uncomment and replace ? by called procedure requiring -lpthread.
#AC_SEARCH_LIBS([?], [pthread])

AC_SEARCH_LIBS([uncompress], [z])

# Enable systemd per option by setting HAVE_SYSTEMD

AS_CASE([${enable_systemd}],
  [yes|check],
    [AC_MSG_CHECKING([systemd])
     AC_SEARCH_LIBS([sd_listen_fds], [systemd-daemon])
     AC_CHECK_FUNC([sd_listen_fds],
       [AC_MSG_RESULT([enabled: systemd])
        AC_DEFINE([HAVE_SYSTEMD],[1],
          [Define to 1 to enable systemd support])],
       AS_CASE([${enable_systemd}],
         [yes],
           AC_MSG_ERROR([systemd support not available]),
	 AC_MSG_RESULT([disabled: systemd])))],
  [no],,
  [AC_MSG_ERROR([invalid argument, --enable-systemd=${enable_systemd}])])

# Enable selinux per option by setting HAVE_SETCON

AS_CASE([${enable_selinux}],
  [yes|check],
    [AC_SEARCH_LIBS([setcon], [selinux])
     AC_CHECK_FUNCS([setcon],
       AC_MSG_RESULT([enabled: selinux]),
       AS_CASE([${enable_selinux}],
         [yes],
           AC_MSG_ERROR([selinux support not available]),
         [check],
           AC_MSG_RESULT([disabled: selinux])))],
  [no],
    AC_MSG_RESULT([disabled: selinux]),
  [AC_MSG_ERROR([invalid argument, --enable-selinux=${enable_selinux}])])

# The check library is used for the unit testing.  Not bothering to
# implement an --enable-tests option, as they are only run by "make
# check" so there is no user-level difference.  If the unit tests
# won't even *compile* there is probably a better solution than just
# turning them off, and build time is minimal.

PKG_CHECK_MODULES(CHECK,[check],
  AC_MSG_RESULT([enabled: unit testing]),
  AC_MSG_RESULT([disabled: unit testing]))

AM_CONDITIONAL([HAVE_CHECK],[test -z "${CHECK_PKG_ERRORS}"])

# For each commented AC_SEARCH_LIBS below, uncomment and replace ? by
# called procedure provided only by that library on the platform(s) in
# question.

# for SunOS / solaris:
#AC_SEARCH_LIBS([?], [nsl])

# for BeOS:
#AC_SEARCH_LIBS([?], [bind])
#AC_SEARCH_LIBS([?], [bsd])

# for SunOS / solaris / BeOS:
#AC_SEARCH_LIBS([?], [socket])

# for Haiku:
#AC_SEARCH_LIBS([?], [network])

# for MS windows32:
#AC_SEARCH_LIBS([?], [ws2_32])
#AC_SEARCH_LIBS([?], [iphlpapi])

# Checks for headers

AC_CHECK_HEADERS([arpa/inet.h fcntl.h netdb.h netinet/in.h stdint.h stdlib.h string.h sys/ioctl.h sys/param.h sys/socket.h sys/time.h syslog.h termios.h unistd.h systemd/sd-daemon.h selinux/selinux.h])

# Checks for typedefs, structures, and compiler characteristics

AC_CHECK_TYPES([socklen_t],,
  AC_DEFINE([socklen_t],[int],
    [define to int if type socklen_t not found]))

AC_TYPE_UID_T
AC_C_INLINE
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions

AC_FUNC_FORK
AC_FUNC_MALLOC
AC_CHECK_FUNCS([alarm dup2 inet_ntoa memset select socket strcasecmp strchr strdup strerror strrchr strstr])

# Epilogue

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
