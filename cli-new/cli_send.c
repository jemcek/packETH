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
#include <assert.h>
#include <sys/types.h>
#include <sys/time.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

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

/* for mode 4, please change them accordingly */
#define MAC_DST_ADDR	{0x00, 0x04, 0x23, 0xB7, 0x29, 0xC4}
#define MAC_SRC_ADDR	{0x00, 0x04, 0x23, 0xB7, 0x21, 0xD8}
#define IP_SRC_ADDR	0x0A0A0A0A
#define IP_DST_ADDR	0x0B0B0B0B
#define TCP_SRC_PORT	htons(80)
#define TCP_DST_PORT	(MyRandom(seed)>>16)

extern char **g_content;
extern char *null_payload;
uint16_t
TCPChecksum(uint16_t* buf1, int buf1len, uint16_t* buf2, int buf2len);
uint32_t
MyRandom(uint64_t *seed);
__sum16
ip_fast_csum(const void *iph, unsigned int ihl);
char *
build_packet(char *buffer, int pktsize, int tot_rules, int *rule_idx, uint64_t *seed, int attack);
int readSnortRules(const char *filename);
void cleanupRules(int);
int one(char *interface, char *filename);
int two(char *interface, long delay, long pkt2send, char *filename, char *sizetmp, int period);
int four(char *interface, long delay, long pkt2send, char *filename, char *sizetmp, int period, int attack);
void usage(void);

int main(int argc, char *argv[])
{
        char iftext[20];
        char sizetmp[20];
        char filename[100];
        long mode=0, delay=100000, number=1, attack=4;
        int c, period = 0;
        char *p;

	sizetmp[0]='\0';

        /* Scan CLI parameters */
        while ((c = getopt(argc, argv, "hi:m:d:n:s:p:f:a:r:")) != -1) {
                switch(c) {
		case 'a': {
			attack = strtol(optarg, &p, 10);
			attack = (attack < 0 || attack > 4) ? 4 : attack;
			break;
		}
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

        if ( (mode!=1) && (mode!=2) && (mode!=3) && (mode!=4))
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
		case 4: {
		  	four(iftext, delay, number, filename, sizetmp, period, attack);
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
	printf("	     - 4: send sequence of packets (Gen-b mode)\n");
        printf("                        -d <us, 0> - delay between packets in micro seconds (-1 for maximum speed without counters, 0 for max speed with counters)\n");
        printf("                        -n <number, 0> - number of packets to send or 0 for infinite\n");
        printf("                        -s \"<startsize stopsize stepsize>\" \n");
        printf("                        -p <period between steps> \n");
        printf("                        -f <attack definitions file in Snort rule format> \n");	
        printf("                        -a <numbers from 0 to 4> - innocent traffic for 0, 25%% attack for 1, 50%% attack for 2, 75%% attack for 3, 100%% attack for 4> \n");
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
	  	for(li = 0; (pkt2send == 0) ? 1 : li < pkt2send; li++) {
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
            for(li = 0; pkt2send == 0 ? 1 : li < pkt2send; li++) {
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
/*------------------------------------------------------------------------------*/
inline __sum16
ip_fast_csum(const void *iph, unsigned int ihl)
{
	unsigned int sum;
	
	asm("  movl (%1), %0\n"
	    "  subl $4, %2\n"
	    "  jbe 2f\n"
	    "  addl 4(%1), %0\n"
	    "  adcl 8(%1), %0\n"
	    "  adcl 12(%1), %0\n"
	    "1: adcl 16(%1), %0\n"
	    "  lea 4(%1), %1\n"
	    "  decl %2\n"
	    "  jne      1b\n"
	    "  adcl $0, %0\n"
	    "  movl %0, %2\n"
	    "  shrl $16, %0\n"
	    "  addw %w2, %w0\n"
	    "  adcl $0, %0\n"
	    "  notl %0\n"
	    "2:"
	    /* Since the input registers which are loaded with iph and ih
	       are modified, we must also specify them as outputs, or gcc
	       will assume they contain their original values. */
	    : "=r" (sum), "=r" (iph), "=r" (ihl)
	    : "1" (iph), "2" (ihl)
	    : "memory");
	return (__sum16)sum;
}
/*------------------------------------------------------------------------------*/
uint16_t
TCPChecksum(uint16_t* buf1, int buf1len, uint16_t* buf2, int buf2len)
{
	uint32_t sum = 0;
	uint16_t tmp = 0;
	
	assert(buf2 == NULL || buf1len % 2 == 0);
	
	while (buf1len > 1) {
		sum += *buf1++;
		buf1len -= 2;
	}
	
	/*  Add left-over byte, if any */
	if (buf1len > 0) {
		tmp = 0;
		*(uint8_t *) &tmp = *(uint8_t *) buf1;
		sum += tmp;
	}
	
	if (buf2) {
		while (buf2len > 1) {
			sum += *buf2++;
			buf2len -= 2;
		}
		
		/*  Add left-over byte, if any */
		if (buf2len > 0) {
			tmp = 0;
			*(uint8_t *) &tmp = *(uint8_t *) buf2;
			sum += tmp;
		}
	}
	
	/* fold 32-bit sum to 16 bits */
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	
	return (uint16_t)~sum;
}
/*------------------------------------------------------------------------------*/
inline uint32_t
MyRandom(uint64_t *seed)
{
	*seed = *seed * 1103515245 + 12345;
	return (uint32_t)(*seed >> 32);	
}
/*------------------------------------------------------------------------------*/
char *
build_packet(char *buffer, int pktsize, int tot_rules, int *rule_idx, uint64_t *seed, int attack)
{
	struct ether_header *ethh;
	struct iphdr *iph;
	struct tcphdr *tcph;
	uint16_t tot_len;
	static struct
	{
		uint32_t src_addr;
		uint32_t dst_addr;
		uint8_t zero;
		uint8_t protocol;
		uint16_t len;
	} __attribute__ ((aligned (__WORDSIZE))) pseudo_header = {
		IP_SRC_ADDR, IP_DST_ADDR, 0, IPPROTO_TCP, 0,
	};
	static u_int8_t ether_dhost[ETH_ALEN] = MAC_DST_ADDR;
	static u_int8_t ether_shost[ETH_ALEN] = MAC_SRC_ADDR;
	static uint64_t attack_meter = 0;
	uint64_t attack_index;
	uint8_t attack_packet = 0;
	
	/* build ether header (14B) */
	ethh = (struct ether_header *)buffer;
	memcpy(ethh->ether_dhost, ether_dhost, ETH_ALEN);
	memcpy(ethh->ether_shost, ether_shost, ETH_ALEN);
	ethh->ether_type = htons(ETHERTYPE_IP);

	tot_len = pktsize - sizeof(struct ether_header);
	
	/* build ip header (20B) */
	iph = (struct iphdr *)(ethh + 1);
	memset(iph, 0, sizeof (struct iphdr));		
	iph->ihl = (unsigned int)(sizeof(struct iphdr)>>2);
	iph->version = 4;
	iph->ttl = 32;
	iph->protocol = IPPROTO_TCP;
	/* in nbo */
	iph->saddr = IP_SRC_ADDR;
	iph->daddr = IP_DST_ADDR;
	iph->tot_len = htons(tot_len);
	iph->check = ip_fast_csum(iph, iph->ihl);

	/* build tcp header (20B) */
	tcph = (struct tcphdr *)((char *)buffer + sizeof(struct ether_header) +
				 sizeof(struct iphdr));
	memset(tcph, 0, sizeof (struct tcphdr));	
	tcph->source = TCP_SRC_PORT;
	tcph->dest = TCP_DST_PORT;
	tcph->seq = MyRandom(seed);
	tcph->ack_seq = MyRandom(seed);
	tcph->doff = (sizeof(struct tcphdr)>>2);
	tcph->res1 = 0;
	tcph->res2 = 0;
	tcph->urg = 0;
	tcph->ack = 1;
	tcph->psh = 0;
	tcph->rst = 0;
	tcph->syn = 0;
	tcph->fin = 0;
	tcph->window = htons(5840);

	attack_index = attack_meter & (4 - 1);
	switch (attack) {
	case 0:
		memcpy((char *)buffer + sizeof(struct ether_header) +
		       sizeof(struct iphdr) + sizeof(struct tcphdr),
		       null_payload, tot_len + sizeof(struct ether_header));
		break;
	case 1:
		if (attack_index == 0) {
			memcpy((char *)buffer + sizeof(struct ether_header) +
			       sizeof(struct iphdr) + sizeof(struct tcphdr),
			       g_content[*rule_idx], tot_len + sizeof(struct ether_header));
			attack_packet = 1;
		}
		else
			memcpy((char *)buffer + sizeof(struct ether_header) +
			       sizeof(struct iphdr) + sizeof(struct tcphdr),
			       null_payload, tot_len + sizeof(struct ether_header));
		break;
	case 2:
		if (attack_index == 0 || attack_index == 2) {
			memcpy((char *)buffer + sizeof(struct ether_header) +
			       sizeof(struct iphdr) + sizeof(struct tcphdr),
			       g_content[*rule_idx], tot_len + sizeof(struct ether_header));
			attack_packet = 1;			
		}
		else
			memcpy((char *)buffer + sizeof(struct ether_header) +
			       sizeof(struct iphdr) + sizeof(struct tcphdr),
			       null_payload, tot_len + sizeof(struct ether_header));
		break;
	case 3:
		if (attack_index != 0) {
			memcpy((char *)buffer + sizeof(struct ether_header) +
			       sizeof(struct iphdr) + sizeof(struct tcphdr),
			       g_content[*rule_idx], tot_len + sizeof(struct ether_header));
			attack_packet = 1;
		}
		else
			memcpy((char *)buffer + sizeof(struct ether_header) +
			       sizeof(struct iphdr) + sizeof(struct tcphdr),
			       null_payload, tot_len + sizeof(struct ether_header));
		break;
	case 4:
		/* build payload */
		memcpy((char *)buffer + sizeof(struct ether_header) +
		       sizeof(struct iphdr) + sizeof(struct tcphdr),
		       g_content[*rule_idx], tot_len + sizeof(struct ether_header));
		attack_packet = 1;
		break;
	default:
		fprintf(stderr, "Control can never come here!\n");
		exit(EXIT_FAILURE);
	}

	/* update rule offset */
	if (attack_packet)
		*rule_idx = (*rule_idx + 1) % tot_rules;

	/* update checksum */
	tot_len -= sizeof(struct iphdr);
	pseudo_header.len = htons(tot_len);
	tcph->check = TCPChecksum((uint16_t *) &pseudo_header,
				  sizeof(pseudo_header), (uint16_t *)tcph,
				  tot_len);

	attack_meter++;
	
	return buffer;
}
/*------------------------------------------------------------------------------*/
/* send one packet more than once */
int
four(char *iftext, long delay, long pkt2send, char* filename, char *sizetmp, int period, int attack)
{
        int c, fd, count, flag = 0;
        struct sockaddr_ll sa;
        struct ifreq ifr;
	
        long li, gap = 0, gap2 = 0, sentnumber = 0, lastnumber = 0, seconds = 0;
        struct timeval nowstr, first, last;
        unsigned int mbps, pkts, link;
	int size, period2 = 0;
	int startsize = 60;
	int stopsize = 1500;
	int stepsize = 10;
	int wordcount = 0;
	int num_rules, rules_idx = 0;
	char *ptr; 
        char *p;
        char pkt_temp[10000];
	char tmp7[10];
	char ch;
	uint64_t seed;
	
        /* do we have the rights to do that? */
        if (getuid() && geteuid()) {
                printf("Sorry but need the su rights!\n");
                return -2;
        }
	
	/* read snort rule file */
	num_rules = readSnortRules(filename);
	if (num_rules == 0) {
		/* if there are no rules, then die! */
		fprintf(stderr, "Rules file is empty!\n");
		exit(EXIT_FAILURE);
	}
	
        /* open socket in raw mode */
        fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
        if (fd == -1) {
                printf("Error: Could not open socket!\n");
		cleanupRules(num_rules);
                return -2;
        }
	
        /* which interface would you like to use? */
        memset(&ifr, 0, sizeof(ifr));
        strncpy (ifr.ifr_name, iftext, sizeof(ifr.ifr_name) - 1);
        ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';
	
        if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
                printf("No such interface: %s\n", iftext);
                close(fd);
		cleanupRules(num_rules);
                return -2;
        }
	
        /* is the interface up? */
        ioctl(fd, SIOCGIFFLAGS, &ifr);
        if ( (ifr.ifr_flags & IFF_UP) == 0) {
                printf("Interface %s is down\n", iftext);
                close(fd);
		cleanupRules(num_rules);
                return -2;
	}
	
	/* just write in the structure again */
        ioctl(fd, SIOCGIFINDEX, &ifr);
	
        /* well we need this to work */
        memset(&sa, 0, sizeof (sa));
        sa.sll_family    = AF_PACKET;
        sa.sll_ifindex   = ifr.ifr_ifindex;
        sa.sll_protocol  = htons(ETH_P_ALL);
	
	if (strlen(sizetmp) > 0 ) {
		for (count = 0; count <= strlen(sizetmp); count ++){
        		ch = sizetmp[count];
       			if((isblank(ch)) || (sizetmp[count] == '\0')){ 
				strncpy(tmp7, &sizetmp[flag],count-flag); 
				tmp7[count-flag]='\0';
				if (wordcount==0) 
					startsize = strtol(tmp7, &p, 10);
				else if (wordcount == 1)
					stopsize = strtol(tmp7, &p, 10);
				else if (wordcount == 2)
					stepsize = strtol(tmp7, &p, 10);
				
            			wordcount += 1;
				flag = count;
        		}
			
    		}
		if (startsize > stopsize) {
			printf("\nstartsize is greater than stopzize\n\n");
			close(fd);
			cleanupRules(num_rules);
			return 1;
		}
		if (startsize < 60) {
			printf("\nstartsize must be >60\n\n");
			close(fd);
			cleanupRules(num_rules);			
			return 1;
		}
		if (stopsize > 9000) {
			printf("\nstopsize must be <9000\n\n");
			close(fd);
			cleanupRules(num_rules);			
			return 1;
		}
		size = startsize;
	}
	else
		size = startsize;
	
		

        /* this is the time we started */
        gettimeofday(&first, NULL);
        gettimeofday(&last, NULL);
        gettimeofday(&nowstr, NULL);
	
	/* generate seed for random number generator */
	seed = first.tv_usec;
	
        /* to send first packet immedialtelly */
        gap = delay;
	

	
	//if the -1 for delay was choosed, just send as fast as possible, no output, no counters, nothing
	if ((delay==-1) && (pkt2send==0)) {
		for(;;) {
			ptr = build_packet(pkt_temp, size, num_rules, &rules_idx, &seed, attack);
        		c = sendto(fd, ptr, size, 0, (struct sockaddr *)&sa, sizeof (sa));
		}
	}
	
	/* else if delay == 0 and infinite packets, send as fast as possible with counters... */
	else if (delay==0) {
            	for(li = 0; pkt2send == 0 ? 1 : li < pkt2send; li++) {
			gettimeofday(&nowstr, NULL);
			gap2 = nowstr.tv_sec - first.tv_sec;
			ptr = build_packet(pkt_temp, size, num_rules, &rules_idx, &seed, attack);
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
				
                	        printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %d kbit/s "
				       "data rate;, %d kbit/s link utilization\n", sentnumber, iftext, size,
				       pkts, mbps, link);
                	        seconds++;
				
				if ( (period2 > (period-2)) && (period>0) ) {
					size = size + stepsize;
					if (size > stopsize) {
						printf("  Sent %ld packets on %s \n", sentnumber, iftext);
						close(fd);
						cleanupRules(num_rules);			
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
            for(li = 0; pkt2send == 0 ? 1 : li < pkt2send; li++) {
                while (gap < delay) {
                        gettimeofday(&nowstr, NULL);
                        gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) - (last.tv_sec*1000000 + last.tv_usec);
                        gap2 = nowstr.tv_sec - first.tv_sec;
                }

		ptr = build_packet(pkt_temp, size, num_rules, &rules_idx, &seed, attack);
        	c = sendto(fd, ptr, size, 0, (struct sockaddr *)&sa, sizeof (sa));

                last.tv_sec = nowstr.tv_sec;
                last.tv_usec = nowstr.tv_usec;
                gap = 0;

                if (c > 0)
                        sentnumber++;

		 /* every second display number of sent packets */
                if (gap2 > seconds) {
			pkts = sentnumber - lastnumber;
			mbps = pkts * size / 125; // 8 bits per byte / 1024 for kbit
			/* +12 bytes for interframe gap time and 12 for preamble, sfd and checksum */
                        link = pkts * (size + 24) / 125;
			lastnumber = sentnumber;

                	printf("  Sent %ld packets on %s; %d packet length; %d packets/s; %d kbit/s "
			       "data rate;, %d kbit/s link utilization\n", sentnumber, iftext, size,
			       pkts, mbps, link);
                        seconds++;

			if ( (period2 > (period-2)) && (period>0) ) {
				size = size + stepsize;
				if (size > stopsize) {
					printf("  Sent %ld packets on %s \n", sentnumber, iftext);
					close(fd);
					cleanupRules(num_rules);
					return 1;
				}
				period2 = 0;
			}
			else
				period2++;
                }
	    }
	    printf("  Sent %ld packets on %s \n", sentnumber, iftext);
	    close(fd);
	    cleanupRules(num_rules);	    
	    return 1;
	}

	close(fd);
	cleanupRules(num_rules);
	
	return 1;
}
/*------------------------------------------------------------------------------*/
