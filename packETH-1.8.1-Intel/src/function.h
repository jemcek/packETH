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
 * function.c - all routines except callbacks and routines for sending
 *
 */

#include <gtk/gtk.h>

signed int char2x(char *p);
char c4(int value);
guint32 get_checksum32(int start, int stop);	
guint16 get_checksum16(int start, int stop);	
char *c8(char *s, unsigned char x);
unsigned char linear2alaw(int pcm_val);
unsigned char linear2ulaw(short pcm_val);
short search(int val, short *table, int size);
int insert_frequency(int codec, int frequency, int length, GtkWidget *payload_entry, gint amp_index);
int check_mac_address(gchar *ptr);
int check_ip_address(gchar *ptr);
int check_ipv6_address(gchar *ptr, int insert);
int send_packet(GtkButton *button, gpointer user_data);
int make_packet(GtkButton *button, gpointer user_data);
int link_level_get(GtkButton *button, gpointer user_data);
int get_network_payload(GtkButton *button, gpointer user_data, int length, int max, gchar *entry);
int get_mac_from_string(GtkButton *button);
int get_8021q(GtkButton *button);
int get_8023(GtkButton *button);
int arp_get(GtkButton *button, gpointer user_data);
int ipv4_get(GtkButton *button, gpointer user_data);
int ipv6_get(GtkButton *button, gpointer user_data);
int udp_get(GtkButton *button, gpointer user_data, guint32 pseudo_header_sum);
int tcp_get(GtkButton *button, gpointer user_data, guint32 pseudo_header_sum);
int icmp_get(GtkButton *button, gpointer user_data);
int icmpv6_get(GtkButton *button, gpointer user_data, guint32 pseudo_header_sum);
int igmp_get(GtkButton *button, gpointer user_data);
int check_digit(char *field, int length, char *text);
int check_if_file_is_packet(FILE *file_p);
int check_hex(char *field, int length, char *text);
void statusbar_text(GtkButton *button, char *text);
void gen_crc32_table(void);
unsigned long get_crc32(unsigned char *p, int len);
int gtk_timer (GtkButton *button);

