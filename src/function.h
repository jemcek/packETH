/*
 * packETH - ethernet packet generator
 * By Miha Jemec <jemcek@gmail.com>
 * Copyright 2003-2018 Miha Jemec
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
 * function.h - all routines except callbacks and routines for sending
 *
 */

#ifndef __FUNCTION_H__
#define __FUNCTION_H__

#include <gtk/gtk.h>

extern char iftext[20];

signed int char2x(const char *p);
char c4(int value);
guint32 get_checksum32(int start, int stop);
guint16 get_checksum16(int start, int stop);
char *c8(char *s, unsigned char x);
int insert_frequency(int codec, int frequency, int length, GtkWidget *payload_entry, gint amp_index);
int check_mac_address(const gchar *ptr);
int check_ip_address(const gchar *ptr);
int check_ipv6_address(const gchar *ptr, int insert);
int send_packet(void);
int make_packet(void);
int check_digit(const char *field, int length, const char *text);
int check_if_file_is_packet(FILE *file_p);
int check_hex(const char *field, int length, const char *text);
void statusbar_text(const char *text);
unsigned long get_crc32(const unsigned char *p, int len);

#endif /* __FUNCTION_H__ */
