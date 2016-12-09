# packETHcli - ethernet packet generator
# By Miha Jemec <jemcek@gmail.com>
# Copyright 2014 Miha Jemec, 

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 3
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.

# Makefile for building packETHcli

SHELL = /bin/sh
prefix = /usr
includedir = /usr/src/include

INSTALL = /usr/bin/install -c
INSTALL_DATA = ${INSTALL} -m 644
INSTALL_PREFIX = /usr

CC = gcc
CPPFLAGS =  

LDFLAGS = 
CFLAGS = -g -O2 -Wall -Wunused -Wmissing-prototypes -Wmissing-declarations 
LIBS =  -lm  -lpthread

SOURCES = cli_send.c 

OBJECTS =  cli_send.o  

PROGRAM = packETHcli

COMPILE = $(CC) $(CFLAGS) $(CPPFLAGS)

all: $(PROGRAM)

$(PROGRAM): $(OBJECTS)
	$(CC) $(CFLAGS) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

%.o: %.c
	$(COMPILE) -c $<

install: $(PROGRAM)
	$(INSTALL) $(PROGRAM) $(DESTDIR)/$(INSTALL_PREFIX)/bin/$(PROGRAM)
	if [ ! -d $(DESTDIR)/$(INSTALL_PREFIX)/share/pixmaps/$(PROGRAM) ]; then mkdir -p $(DESTDIR)/$(INSTALL_PREFIX)/share/pixmaps/$(PROGRAM); fi
	$(INSTALL_DATA) pixmaps/* $(DESTDIR)/$(INSTALL_PREFIX)/share/pixmaps/$(PROGRAM)

clean:
	rm -f $(OBJECTS) $(PROGRAM)

