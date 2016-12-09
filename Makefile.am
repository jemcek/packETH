bin_PROGRAMS=packETH 
packETH_SOURCES= \
	src/main.c \
	src/support.c src/support.h \
	src/interface.c src/interface.h \
	src/callbacks.c src/callbacks.h \
	src/function.c src/function.h \
	src/function_send.c src/function_send.h \
	src/loadpacket.c src/loadpacket.h \
	src/savepacket.c src/savepacket.h \
	src/headers.h

pixmaps= \
  src/pixmaps/Build.xpm  \
  src/pixmaps/donate.xpm  \
  src/pixmaps/future.xpm  \
  src/pixmaps/Gen.xpm   \
  src/pixmaps/interface.xpm  \
  src/pixmaps/load.xpm \
  src/pixmaps/preference.xpm  \
  src/pixmaps/reset.xpm \
  src/pixmaps/save.xpm \
  src/pixmaps/save16.xpm  \
  src/pixmaps/send.xpm \
  src/pixmaps/X.xpm

pixmapdir=$(pkgdatadir)/pixmaps
pixmap_DATA=$(pixmaps)

DEFS= \
  -DPKGDATADIR=\"$(pkgdatadir)/\"

LIBS=$(DEPS_LIBS)

AM_CPPFLAGS = \
  -g \
  -O2 \
  -Wall \
  -Wmissing-prototypes \
  -Wmissing-declarations \
  -Wunused \
  $(DEPS_CFLAGS)

# Include the dev and pixmaps in the distribution (make dist)
EXTRA_DIST=dev src/pixmaps
