#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.63])
AC_INIT([packETH], [1.7], [jemcek@gmail.com])
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
pkg_modules="gtk+-2.0 >= 2.4 glib-2.0 >= 2.4 gthread-2.0 >= 2.4"
PKG_CHECK_MODULES(DEPS, [$pkg_modules])

# Checks for library functions.
AC_FUNC_ERROR_AT_LINE
AC_FUNC_MALLOC
AC_FUNC_STRTOD
AC_CHECK_FUNCS([bzero ftime gettimeofday isascii memset socket strchr strtol strtoul strtoull])

AC_CONFIG_FILES([Makefile])
AC_OUTPUT
