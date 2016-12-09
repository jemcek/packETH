/*
 * packETH - ethernet packet generator
 * By Miha Jemec <jemcek@gmail.com>
 * Copyright 2014 Miha Jemec
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 *
 */


#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include <unistd.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>

#define PCAP_MAGIC   0xa1b2c3d4

/* "libpcap" file header (minus magic number). */
struct pcap_hdr {
    uint32_t     magic;          /* magic */
    uint16_t     version_major;  /* major version number */
    uint16_t     version_minor;  /* minor version number */
    uint32_t     thiszone;       /* GMT to local correction */
    uint32_t     sigfigs;        /* accuracy of timestamps */
    uint32_t     snaplen;        /* max length of captured packets, in octets */
    uint32_t     network;        /* data link type */
};

/* "libpcap" record header. */
struct pcaprec_hdr {
    int32_t      ts_sec;         /* timestamp seconds */
    uint32_t     ts_usec;        /* timestamp microseconds */
    uint32_t     incl_len;       /* number of octets of packet saved in file */
    uint32_t     orig_len;       /* actual length of packet */
};


/* Link-layer type; */
//static unsigned long pcap_link_type = 1;   /* Default is DLT-EN10MB */

int one(char *interface, char *filename);
int two(char *interface, long delay, long pkt2send, char *filename, char *sizetmp, int period);
void usage(void);

int main(int argc, char *argv[])
{
        char iftext[20];
        char sizetmp[20];
        char filename[100];
        long mode=0, delay=100000, number=1;
        int c, period = 0;
        char *p;

	sizetmp[0]='\0';

        /* Scan CLI parameters */
        while ((c = getopt(argc, argv, "hi:m:d:n:s:p:f:")) != -1) {
                switch(c) {
                case 'h': usage(); break;
                case 'i': strcpy(iftext, optarg); break;
                case 'm': {
                        mode = strtol(optarg, &p, 10);
                        break;
                }
                case 'd': {
                        delay = strtol(optarg, &p, 10);
                        break;
                }
                case 'n': {
                        number = strtol(optarg, &p, 10);
                        break;
                }
                case 's': {
                        strncpy(sizetmp, optarg, 20);
                        break;
                }
                case 'p': {
                        period = strtol(optarg, &p, 10);
                        break;
                }
                case 'f': {
                        strncpy(filename, optarg, 99);
                        break;
                }
                default:
                        usage();
                }
        }

        if ( (mode!=1) && (mode!=2) && (mode!=3) )
                usage();

        switch (mode) {
                case 1: {
                        one(iftext, filename);
                        break;
                }
                case 2: {
                        two(iftext, delay, number, filename, sizetmp, period);
                        break;
                }
                case 3: {
			printf("Not yet implemented...\n");
			exit(8);
                        break;
                }
        }
	return 0;
}

void usage(void)
{
        printf("Usage: packETHcli -i <interface> -m <mode> [-d <delay> -n <number of packets> [-s <startsize stopsize stepsize] -p period] -f <file>\n");
        printf(" \n");
        printf(" -m <1,2,3>  - 1: send one packet (builder mode), no further options\n");
        printf("             - 2: send sequence of one packet (Gen-b mode)\n");
        printf("                        -d <us, 0> - delay between packets in micro seconds (-1 for maximum speed without counters, 0 for max speed with counters)\n");
        printf("                        -n <number, 0> - number of packets to send or 0 for infinite\n");
        printf("                        -s \"<startsize stopsize stepsize> (please note that checksum in not recalculated for shorter lengths!!!)\" \n");
        printf("                        -p <period between steps> \n");
        printf("             - 3: send sequence packets (Gen-s mode) - not yet done...\n");
        printf("                                                                                                     \n");
        printf(" -f <file name> - file name where packet is stored in pcap format\n");
        printf("                                                                                                     \n");
        printf("Examples:                                                                                            \n");
        printf("                                                                                                     \n");
        printf("  ./packETHcli -i lo -m 1 -f packet1.pcap                   			 - send packet1.pcap once on lo \n");
        printf("  ./packETHcli -i eth0 -m 2 -d 1000 -n 300 -f packet2.pcap   			 - send packet2.pcap 300 times with 1000 us (1ms) between them  \n");
        printf("  ./packETHcli -i eth0 -m 2 -d -1 -n 0 -f packet2.pcap   			 - send packet2.pcap at max speed, infinite times, no counters\n");
        printf("  ./packETHcli -i eth0 -m 2 -d 0 -n 0 -f packet2.pcap   			 - send packet2.pcap at max speed, infinite times, with counters\n");
        printf("  ./packETHcli -i eth1 -m 2 -d 0 -n 0 -s \"1000 1500 100\" -p 10 -f packet3.pcap   - send packet2.pcap at max speed, start with packet length of 1000 bytes \n");
        printf("                                                                             	 - send 10 packets with this packet length, increase packet length by 100 bytes till 1500 \n");
        printf("  ./packETHcli -i eth0 -m 2 -d 100 -n 0 -s \"8500 8500\" -f packet2.pcap     	 - send packet2.pcap infinite times with 300us between them\n");
        printf("                                                                           	 - with the size of 8500 bytes (even if packet2 is longer)\n\n\n");
        exit (8);
}

//send the packet once, and that is...
int one(char *iftext, char *filename)
{
        int c, fd;
        struct sockaddr_ll sa;
        struct ifreq ifr;
	FILE *file_p;
	char *ptr; 

	struct pcap_hdr fh;
        struct pcaprec_hdr ph;
        int freads;
        char pkt_temp[10000];

        /* do we have the rights to do that? */
        if (getuid() && geteuid()) {
                //printf("Sorry but need the su rights!\n");
                printf("Sorry but need the su rights!\n");
                return -2;
        }

        /* open socket in raw mode */
        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd == -1) {
                //printf("Error: Could not open socket!\n");
                printf("Error: Could not open socket!\n");
                return -2;
        }

        /* which interface would you like to use? */
        memset(&ifr, 0, sizeof(ifr));
        strncpy (ifr.ifr_name, iftext, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
                //printf("No such interface: %s\n", iftext);
                printf("No such interface: %s\n", iftext);
                close(fd);
                return -2;
        }

        /* is the interface up? */
        ioctl(fd, SIOCGIFFLAGS, &ifr);
        if ( (ifr.ifr_flags & IFF_UP) == 0) {
                //printf("Interface %s is down\n", iftext);
                printf("Interface %s is down\n", iftext);
                close(fd);
                return -2;
	}

      /* just write in the structure again */
        ioctl(fd, SIOCGIFINDEX, &ifr);

        /* well we need this to work */
        memset(&sa, 0, sizeof (sa));
        sa.sll_family    = AF_PACKET;
        sa.sll_ifindex   = ifr.ifr_ifindex;
        sa.sll_protocol  = htons(ETH_P_ALL);

	if((file_p = fopen(filename, "r")) == NULL) {
                printf("can not open file for reading\n");
                return -2;
        }
	
	/* first we read the pcap file header */
        freads = fread(pkt_temp, sizeof(fh), 1, file_p);
        /* if EOF, exit */
        if (freads == 0)
                return 1;

        memcpy(&fh, pkt_temp, 24);

        /* if magic number in NOK, exit */
        if (fh.magic != PCAP_MAGIC)
                return -2;

	/* next the  pcap packet header */
        freads = fread(pkt_temp, sizeof(ph), 1, file_p);

        /* if EOF, exit */
        if (freads == 0)
                return -2;

        /* copy the 16 bytes into ph structure */
        memcpy(&ph, pkt_temp, 16);

	ptr = pkt_temp + sizeof(ph);

        /* and the packet itself, but only up to the capture length */
        freads = fread(ptr, ph.incl_len, 1, file_p);

        /* if EOF, exit */
        if (freads == 0)
                return -2;

	fclose(file_p);

        c = sendto(fd, ptr, ph.incl_len, 0, (struct sockaddr *)&sa, sizeof (sa));

        printf("There were %d bytes sent on the wire on the interface %s\n", c, iftext);

        if (close(fd) == 0) {
                return (c);
        }
        else {
                printf("Warning! close(fd) returned -1!\n");
                return (c);
        }
	return 1;
}

                           

/* send one packet more than once */
int two(char *iftext, long delay, long pkt2send, char* filename, char *sizetmp, int period) {

        int c, fd, count, flag = 0;
        struct sockaddr_ll sa;
        struct ifreq ifr;

        long li, gap = 0, gap2 = 0, sentnumber = 0, lastnumber = 0, seconds = 0;
        struct timeval nowstr, first, last;
        unsigned int mbps, pkts, link;
	int size, period2=0;
	int startsize = 60;
	int stopsize = 1500;
	int stepsize = 10;
	int wordcount = 0;

	FILE *file_p;
	char *ptr; 
        char *p;
	struct pcap_hdr fh;
        struct pcaprec_hdr ph;
        int freads;
        char pkt_temp[10000];
	char tmp7[10];
	char ch;

        /* do we have the rights to do that? */
        if (getuid() && geteuid()) {
                //printf("Sorry but need the su rights!\n");
                printf("Sorry but need the su rights!\n");
                return -2;
        }

        /* open socket in raw mode */
        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd == -1) {
                //printf("Error: Could not open socket!\n");
                printf("Error: Could not open socket!\n");
                return -2;
        }

        /* which interface would you like to use? */
        memset(&ifr, 0, sizeof(ifr));
        strncpy (ifr.ifr_name, iftext, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
                //printf("No such interface: %s\n", iftext);
                printf("No such interface: %s\n", iftext);
                close(fd);
                return -2;
        }

        /* is the interface up? */
        ioctl(fd, SIOCGIFFLAGS, &ifr);
        if ( (ifr.ifr_flags & IFF_UP) == 0) {
                //printf("Interface %s is down\n", iftext);
                printf("Interface %s is down\n", iftext);
                close(fd);
                return -2;
	}

      /* just write in the structure again */
        ioctl(fd, SIOCGIFINDEX, &ifr);

        /* well we need this to work */
        memset(&sa, 0, sizeof (sa));
        sa.sll_family    = AF_PACKET;
        sa.sll_ifindex   = ifr.ifr_ifindex;
        sa.sll_protocol  = htons(ETH_P_ALL);

	if((file_p = fopen(filename, "r")) == NULL) {
                printf("can not open file for reading\n");
                return -2;
        }
	
	/* first we read the pcap file header */
        freads = fread(pkt_temp, sizeof(fh), 1, file_p);
        /* if EOF, exit */
        if (freads == 0)
                return 1;

        memcpy(&fh, pkt_temp, 24);

        /* if magic number in NOK, exit */
        if (fh.magic != PCAP_MAGIC)
                return -2;

	/* next the  pcap packet header */
        freads = fread(pkt_temp, sizeof(ph), 1, file_p);

        /* if EOF, exit */
        if (freads == 0)
                return -2;

        /* copy the 16 bytes into ph structure */
        memcpy(&ph, pkt_temp, 16);

	ptr = pkt_temp + sizeof(ph);

        /* and the packet itself, but only up to the capture length */
        freads = fread(ptr, ph.incl_len, 1, file_p);

        /* if EOF, exit */
        if (freads == 0)
                return -2;

	fclose(file_p);

	if (strlen(sizetmp) > 0 ) {
		for (count = 0; count <= strlen(sizetmp); count ++){
        		ch = sizetmp[count];
       			if((isblank(ch)) || (sizetmp[count] == '\0')){ 
				strncpy(tmp7, &sizetmp[flag],count-flag); 
				tmp7[count-flag]='\0';
				if (wordcount==0) 
					startsize = strtol(tmp7, &p, 10);
				else if (wordcount ==1)						
					stopsize = strtol(tmp7, &p, 10);
				else if (wordcount ==2)						
					stepsize = strtol(tmp7, &p, 10);

            			wordcount += 1;
				flag = count;
        		}
			
    		}
		if (startsize > stopsize) {
			printf("\nstartsize is greater than stopzize\n\n");
			return 1;
		}
		if (startsize < 60) {
			printf("\nstartsize must be >60\n\n");
			return 1;
		}
		if (stopsize > 9000) {
			printf("\nstopsize must be <9000\n\n");
			return 1;
		}
		size = startsize;
	}
	else
		size = ph.incl_len;

		

        /* this is the time we started */
        gettimeofday(&first, NULL);
        gettimeofday(&last, NULL);
        gettimeofday(&nowstr, NULL);

        /* to send first packet immedialtelly */
        gap = delay;

	/*-----------------------------------------------------------------------------------------------*/

	//if the -1 for delay was choosed, just send as fast as possible, no output, no counters, nothing
	if ((delay==-1) && (pkt2send==0)) {
		for(;;)
        		c = sendto(fd, ptr, ph.incl_len, 0, (struct sockaddr *)&sa, sizeof (sa));
	}

	/* else if delay == 0 and infinite packets, send as fast as possible with counters... */
	else if (delay==0) {
            	for(li = 0; pkt2send == 0 ? : li < pkt2send; li++) {
			gettimeofday(&nowstr, NULL);
			gap2 = nowstr.tv_sec - first.tv_sec;
			c = sendto(fd, ptr, size, 0, (struct sockaddr *)&sa, sizeof (sa));
			last.tv_sec = nowstr.tv_sec;
                	last.tv_usec = nowstr.tv_usec;

                	if (c > 0)
                	        sentnumber++;
			  /* every second display number of sent packets */
                	if (gap2 > seconds) {
                	        pkts = sentnumber - lastnumber;
                	        mbps = pkts * size / 125; // 8 bits per byte / 1024 for kbit
                	        /* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                	        link = pkts * (size + 24) / 125;
                	        lastnumber = sentnumber;

                	        printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %d kbit/s data rate;, %d kbit/s link utilization\n", sentnumber, iftext, size, pkts, mbps, link);
                	        seconds++;

				if ( (period2 > (period-2)) && (period>0) ) {
					size = size + stepsize;
					if (size > stopsize) {
						printf("  Sent %ld packets on %s \n", sentnumber, iftext);
						return 1;
					}
					period2 = 0;
				}
				else
					period2++;
                	}
        	}
	printf("  Sent %ld packets on %s \n", sentnumber, iftext);
	}

	else {
            for(li = 0; pkt2send == 0 ? : li < pkt2send; li++) {
                while (gap < delay) {
                        gettimeofday(&nowstr, NULL);
                        gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (last.tv_sec*1000000 + last.tv_usec);
                        gap2 = nowstr.tv_sec - first.tv_sec;
                }

        	c = sendto(fd, ptr, ph.incl_len, 0, (struct sockaddr *)&sa, sizeof (sa));

                last.tv_sec = nowstr.tv_sec;
                last.tv_usec = nowstr.tv_usec;
                gap = 0;

                if (c > 0)
                        sentnumber++;

		 /* every second display number of sent packets */
                if (gap2 > seconds) {
			pkts = sentnumber - lastnumber;
			mbps = pkts * ph.incl_len / 125; // 8 bits per byte / 1024 for kbit
			/* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                        link = pkts * (ph.incl_len + 24) / 125;
			lastnumber = sentnumber;

                	printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %d kbit/s data rate;, %d kbit/s link utilization\n", sentnumber, iftext, size, pkts, mbps, link);
                        seconds++;

			if ( (period2 > (period-2)) && (period>0) ) {
				size = size + stepsize;
				if (size > stopsize) {
					printf("  Sent %ld packets on %s \n", sentnumber, iftext);
					return 1;
				}
				period2 = 0;
			}
			else
				period2++;
                }
	}
	printf("  Sent %ld packets on %s \n", sentnumber, iftext);
	return 1;
	}
	return 1;
}

