/*
 * packETH - ethernet packet generator
 * By Miha Jemec <jemcek@gmail.com>
 * Copyright 2003-2014 Miha Jemec
 *
 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation, either version 3 of the License, or
 (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

#ifndef __LOADPACKET_H__
#define __LOADPACKET_H__

#include <stdio.h>

#include "headers.h"

int load_packet_disector(char *, int whocalled, struct clist_hdr *clptr, int);



int load_data(FILE *file_p, int whocalled, int howmanypackets);
int load_gen_b_data(FILE *file_p);
int load_gen_s_data(FILE *file_p);

#endif /* __LOADPACKET_H__ */
