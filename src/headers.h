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

/*----------------------------------------------------------------------
 * Stuff for writing a PCap file
 */
#define PCAP_MAGIC                      0xa1b2c3d4

/* "libpcap" file header (minus magic number). */
struct pcap_hdr {
    guint32     magic;          /* magic */
    guint16     version_major;  /* major version number */
    guint16     version_minor;  /* minor version number */
    guint32     thiszone;       /* GMT to local correction */
    guint32     sigfigs;        /* accuracy of timestamps */
    guint32     snaplen;        /* max length of captured packets, in octets */
    guint32     network;        /* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
    gint32      ts_sec;         /* timestamp seconds */
    guint32     ts_usec;        /* timestamp microseconds */
    guint32     incl_len;       /* number of octets of packet saved in file */
    guint32     orig_len;       /* actual length of packet */
};

/* Link-layer type; */
static unsigned long pcap_link_type = 1;   /* Default is DLT-EN10MB */

/* struct for clist */
struct clist_hdr {
	gint16 pnrb;	/* packet number */
	gint32 time;	/* delay since previous packet */
	gint16 plen; 	/* packet length */
	char src[40];
	char dst[40];
	gchar info[21];
};
	

typedef enum {
        ETH_II,
	ETH_802_3,
	ARP,
	IPv4,
	IPv6,
	UDP,
	TCP,
	IGMP,
	ICMP,
	ICMPv6
} protocol_type;

	
