bin_PROGRAMS=packETH 

packETH_built_sources = \
	src/pixmaps.c src/pixmaps.h \
	src/ui.c src/ui.h

packETH_SOURCES= \
	$(packETH_built_sources) \
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
  src/pixmaps/pixmaps.gresource.xml \
  src/pixmaps/Build.xpm  \
  src/pixmaps/interface.xpm  \
  src/pixmaps/load.xpm \
  src/pixmaps/preference.xpm  \
  src/pixmaps/reset.xpm \
  src/pixmaps/save.xpm \
  src/pixmaps/send.xpm \
  src/pixmaps/X.xpm

ui= \
  ui/ui.gresource.xml \
  ui/about_dialog.ui \
  ui/error_dialog.ui \
  ui/fileselection1.ui \
  ui/fileselection2.ui \
  ui/fileselection3.ui \
  ui/fragmentation_dialog.ui \
  ui/interface_dialog.ui \
  ui/sel1_dialog.ui \
  ui/tos_dialog.ui \
  ui/udp_payload_dialog.ui \
  ui/window1.ui

DEFS= \
  -DPKGDATADIR=\"$(pkgdatadir)/\"

LIBS=$(DEPS_LIBS) -lm

AM_CPPFLAGS = \
  -g \
  -O2 \
  -Wall \
  -Wmissing-prototypes \
  -Wmissing-declarations \
  -Wunused \
  -Wl,--export-dynamic \
  $(DEPS_CFLAGS)

# Include the pixmaps and ui in the distribution (make dist)
EXTRA_DIST=$(pixmaps) $(ui)

BUILT_SOURCES = \
	$(packETH_built_sources)

CLEANFILES = \
	$(packETH_built_sources)

src/pixmaps.c: $(pixmaps)
	$(AM_V_GEN) glib-compile-resources --generate-source --sourcedir=src/pixmaps --target=$@ src/pixmaps/pixmaps.gresource.xml

src/pixmaps.h: $(pixmaps)
	$(AM_V_GEN) glib-compile-resources --generate-header --sourcedir=src/pixmaps --target=$@ src/pixmaps/pixmaps.gresource.xml

src/ui.c: $(ui)
	$(AM_V_GEN) glib-compile-resources --generate-source --sourcedir=ui --target=$@ ui/ui.gresource.xml

src/ui.h: $(ui)
	$(AM_V_GEN) glib-compile-resources --generate-header --sourcedir=ui --target=$@ ui/ui.gresource.xml
