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

#include "headers.h"

int load_gen_p_data(GtkButton *button, GtkWidget *clis, char *, struct pcaprec_hdr *, int, struct clist_hdr *clptri,
                                                               double timediff, double timebeg);
int load_packet_disector(GtkButton *button, char *, int whocalled, struct clist_hdr *clptr, int);
int ipv4_header(GtkButton *button, int whocalled, struct clist_hdr *clptr);
int ipv6_header(GtkButton *button, int whocalled, struct clist_hdr *clptr);



int load_data(GtkButton *button, FILE *file_p, int whocalled, int howmanypackets);
//int load_packet_disector(GtkButton *button, FILE *);
int load_gen_b_data(GtkButton *button, FILE *);
int load_gen_s_data(GtkButton *button, FILE *);
//int load_gen_p_data(GtkButton *button, char *, pcaprec_hdr *);
int ethernet_8023(GtkButton *button, int whocalled);
int ethernet_verII(GtkButton *button, int whocalled);
//int ipv4_header(GtkButton *button, int whocalled);
int arp_header(GtkButton *button, int whocalled);
int userdef2_field(GtkButton *button, int whocalled);
void inspar(GtkButton *button, char *entry, char *from, int length);
void insint(GtkButton *button, char *entry, char *from, int length);
signed int retint(char *ch);
unsigned long retint2(char *ch, int length);
int tcp_header(GtkButton *button, int whocalled);
int udp_header(GtkButton *button, int whocalled);
int igmp_header(GtkButton *button, int whocalled);
int icmp_header(GtkButton *button, int whocalled);
int icmpv6_header(GtkButton *button, int whocalled);
int usedef_insert(GtkButton *button, char *entry, int whocalled);
void convert8field(char *to, char *from);
