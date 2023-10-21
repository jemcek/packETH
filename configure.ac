#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([packETH], [3.0], [https://github.com/jemcek/packETH/issues], [], [https://packeth.sourceforge.net/])
AC_CONFIG_SRCDIR([src/main.c])
AM_INIT_AUTOMAKE([subdir-objects])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CC
AM_PROG_CC_C_O
AC_PROG_INSTALL

# Checks for libraries.
AC_CHECK_LIB([m], [pow])
AC_CHECK_LIB([pthread], [pthread_create])

# Checks for header files.
AC_CHECK_HEADERS([libintl.h netdb.h netinet/in.h stdlib.h string.h sys/ioctl.h sys/socket.h sys/time.h sys/timeb.h unistd.h])

# We need GTK
pkg_modules="gtk+-3.0 >= 3.16 glib-2.0 >= 2.4 gthread-2.0 >= 2.4 gmodule-export-2.0 >= 2.4"
PKG_CHECK_MODULES(DEPS, [$pkg_modules])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([bzero ftime gettimeofday isascii memset socket strchr strtol strtoul strtoull])

AC_CONFIG_FILES([Makefile])

# Option to define a larger (or smaller) maximum MTU
AC_ARG_WITH([mtu], [AS_HELP_STRING([--with-mtu], [change the maximum MTU, default: 9000])])
AS_IF([test "x$with_mtu" != "x"],
	[AC_DEFINE_UNQUOTED([MAX_MTU], [${with_mtu}], ["..."])],
	[AC_DEFINE_UNQUOTED([MAX_MTU], [9000], ["..."])])
AS_IF([test "x$with_mtu" != "x"],
	[AC_DEFINE_UNQUOTED([MAX_MTU_STR], ["${with_mtu}"], ["..."])],
	[AC_DEFINE_UNQUOTED([MAX_MTU_STR], ["9000"], ["..."])])

AC_OUTPUT
