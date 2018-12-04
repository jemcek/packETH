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
 * function_send.c - all routines except callbacks and routines for sending
 *
 */


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <gtk/gtk.h>

#include <unistd.h>
#include <sys/types.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include "callbacks.h"
#include "function_send.h"
#include "function.h"

#include <sys/time.h>
#include <time.h>

//#define 1 1.0
//#define 128 

extern int number;
extern unsigned char packet[10000];
extern gboolean stop_flag;
extern long li_sentbytes;
extern long li_packets_sent;
extern long li_last_packets_sent;
extern long li_packets_sent_lastsec;
extern long sentstream[10];
extern long sendtime;
char iftext[20];

struct params  {
	long long del;
	double count;
	long inc;
	int type;
	gint timeflag;
	gint random;
	int udpstart;
	int tcpstart;
	int ipv4start;
	int ipv6start;
	int icmpstart;
	int icmpstop;
	int icmpv6start;
	int icmpv6stop;
	int ethstart;
	int xbyte;
	int ybyte;
	int xchange;
	int ychange;
	unsigned long xrange;
	unsigned long yrange;
	char xstart[4];
	char ystart[4];
	unsigned char pkttable[10][10000];
	long long int partable[10][6];
	int ipv4mask;
	int ipv6mask;
	int ip_proto_in_use;
	int l4_proto_in_use;
	struct sockaddr_ll sa;
	int fd;
	struct ifreq ifr;
	long duration;
	long long ramp_start;
	long long ramp_stop;
	long long ramp_step;
	int ramp_interval;
	int ramp_mode;
	int ramp_multiplier;
	long long ramp_speed;
};
/* end */


/* when you press Send inside the builder, one packet is sent  */
int packet_go_on_the_link(unsigned char *pkt, int nr)
{
	int c, fd;
	struct sockaddr_ll sa;
	struct ifreq ifr;
	char buff[100];
	
	/* do we have the rights to do that? */
	if (getuid() && geteuid()) {
		//printf("Sorry but need the su rights!\n");
		error("Sorry but need the su rights!");
		return -2;
	}
	
	/* open socket in raw mode */
	fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (fd == -1) {
		//printf("Error: Could not open socket!\n");
		error("Error: Could not open socket!");
		return -2;
	}

	/* which interface would you like to use? */
	memset(&ifr, 0, sizeof(ifr));
	strncpy (ifr.ifr_name, iftext, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_name[sizeof(ifr.ifr_name)-1] = '\0';

	if (ioctl(fd, SIOCGIFINDEX, &ifr) == -1) {
		//printf("No such interface: %s\n", iftext);
		snprintf(buff, 100, "No such interface: %s", iftext);
		error(buff);
		close(fd);
		return -2;
	}       

	/* is the interface up? */
	ioctl(fd, SIOCGIFFLAGS, &ifr);
	if ( (ifr.ifr_flags & IFF_UP) == 0) {
		//printf("Interface %s is down\n", iftext);
		snprintf(buff, 100, "Interface %s is down", iftext);
		error(buff);
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

	c = sendto(fd, pkt, nr, 0, (struct sockaddr *)&sa, sizeof (sa));

	//printf("There were %d bytes sent on the wire (in case of an error we get -1)\n", c);

	if (close(fd) == 0) {
		return (c);
	}
	else {
		//printf("Warning! close(fd) returned -1!\n");
		error("Warning! close(fd) returned -1!");
		return (c);
	}
}

  
/* thread for sending packets
   here we send one packet multiple times
   packet contest, size, rate may be changed while sending this packet
 */
void* sendbuilt (void *parameters)
{
	/* YYY check if li,... are long enough if inifinite number will be sent. Maybe put them into double */
	long li, sentnumber = 0, test = 0, shouldbesent = 0, li_packets_sent_interval = 0;
	long long gap = 0, gap1s = 0, gap2s = 0, gap3s = 0, correction = 0, last_correction = 0;
	struct timeval nowstr, first, last;
	struct timespec first_ns, now_ns, last_ns, now1s_ns, last1s_ns;
	int i, c, odd=0, actualnumber/*, correctcks = 0*/, step_counter = 0;
	//unsigned int mbps, pkts, link;
	unsigned long xc=0, yc=0;
	//struct sockaddr_ll sa;
	//struct ifreq ifr;
	//int fd;
	guint32 ipcks, pseudo_header=0, udpcksum, tcpcksum, icmpcksum;
	guint32 *stevec32;
	int maskv4[4];
	int maskv6[16];

	struct params* p = (struct params*) parameters;

	/* this is the time we started */
	gettimeofday(&first, NULL);
	gettimeofday(&last, NULL);
	gettimeofday(&nowstr, NULL);

	clock_gettime(CLOCK_MONOTONIC, &first_ns);
	clock_gettime(CLOCK_MONOTONIC, &now_ns);
	clock_gettime(CLOCK_MONOTONIC, &last_ns);
	clock_gettime(CLOCK_MONOTONIC, &now1s_ns);
	clock_gettime(CLOCK_MONOTONIC, &last1s_ns);

	/* to send first packet immediatelly */
	gap = p->del;
	//printf("toklej p->del %lld in tokle p->count %f\n", gap, p->count);

	/* if packet is shorter than 60 bytes, we need real packet length for calculating checksum,
	 * we use actualnumber for this */
	actualnumber = number;
	if (number < 60)
		number = 60;


	// in case of size ramp, start size is corrected
	if ( ( p->ramp_mode >= 2) ) {
		number = p->ramp_start;
	}
	if ( ( p->ramp_mode == 2) ) {
		p->del = (long long)(1000000 * (long long)number * 8) / p->ramp_speed;
	}

	// in case we use correction mode
	// this adjustment is due to the fact that at high speeds packETH is slighty slower then desired packet rate
	// to correct this, we measure the packet rate at first second od sending, calcalute the ratio between actual
	// and desired and correct the delta between packets with the same ratio
	// the problem is, that because of jitter, we sometimes than get higher results than what was entered by the user
	// to correct this again, I have two options
	// 1) first idea is to count the number of packets sent in 1s interval and in case, there
	//    were already enough packets sent (enough means the exact calculated pps), to stop sending 
	//    until the interval of 1s is over. This might bring some more jitter into the sending rate
	// 2) second idea is, to correct the sending interval with slighly less than the ratio between desired and actual
	//    pps rate. This ratio could be 75%. 
	// 
	// if you wan't to diaable this adjustment, follow XYZ comments below
	correction = p->del;
	shouldbesent = 1000000000 / p->del;

	// here we do some math and convert the mask value, user entered inside the adjust paramters field
	// into per byte value: so if user entered /24 for ipv4 mask, then first (lsb byte) is 0, and other 3 are 8
	// for mask /18, first byte is 0, second is == 2, and third and forth are 8
	// for ipv6 we just expend this 
	for (i=3; i>=0; i--) {
		if ((p->ipv4mask - (i*8)) > 8) 
			maskv4[i] = 8;
		else if ((p->ipv4mask - (i*8)) > 0)     
			maskv4[i] = p->ipv4mask - (i*8);
		else
			maskv4[i] = 0;
	}
	for (i=15; i>=0; i--) {
		if ((p->ipv6mask - (i*8)) > 8) 
			maskv6[i] = 8;
		else if ((p->ipv6mask - (i*8)) > 0)     
			maskv6[i] = p->ipv6mask - (i*8);
		else
			maskv6[i] = 0;
	}

	/* -----------------------------------------------------*/
	/*                 here we go                           */
	/*               it is sending time                     */
	/* -----------------------------------------------------*/
	
	/* we check with == -3 if the infinite option was choosed, otherwise send until number of packets number was reached */
	for(li = 0; ((p->count == -3) ? : li < p->count); ) {

	    clock_gettime(CLOCK_MONOTONIC, &now_ns);
	    gap = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last_ns.tv_sec*1000000000 + last_ns.tv_nsec);
	    gap1s = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) - (last1s_ns.tv_sec*1000000000 + last1s_ns.tv_nsec);
		
	    /*  every second we store how many packets were sent, we use this info in function.c to update the status bar 
			here we also adjust the gap between packets to get more accurate bandwidth values and count the sending time
	    */
	    if (gap1s >= 1000000000) {
			//here we know how many packets should be sent and how many were sent
			shouldbesent = 1000000000 / p->del;
			li_packets_sent_lastsec = li_packets_sent - li_last_packets_sent;
			li_last_packets_sent = li_packets_sent;
			li_packets_sent_interval = 0;
			//normally there is a little gap between the rate we want to send and the actual one, we try to adjust it a little bit
			//the first second just send as calculated without correction
			if (gap3s == 0) 
				correction = p->del;
			//the 2nd second we adjust the interval between packets and try to get better results
			else if (gap3s == 1) {
				correction = p->del * li_packets_sent_lastsec/shouldbesent ;
				/*printf("shouldbesent %ld and actual sent %ld, correction  %ld,  p->del %ld\n", 
				shouldbesent, li_packets_sent_lastsec, correction, p->del); */
			}
		
			last1s_ns.tv_sec = now_ns.tv_sec;
			last1s_ns.tv_nsec = now_ns.tv_nsec;
			gap1s = 0;
			gap2s++;
			sendtime = gap2s;
			gap3s++;
	    }

	    // XYZ
	    //in case we already did send enough packets, but the second is not yet there, stop sending
	    // this may introduce a little higher gap between the two packets at the end of each second
	    // but will prevent that more packets are sent as requested. 
	    // uncomment this if you want to skip this check
	    else if (li_packets_sent_interval >= shouldbesent ) {
	       continue; 
	    }

	    /* in speed ramp sending mode, we need to adjust timers according to start speed and step */
	    if ( ( p->ramp_mode == 1) )  {
			/* if the interval is over, let's recalculate delay */
			if (gap3s >= p->ramp_interval) {
			    step_counter++;
			    p->del = (long long)(1000000 * (long long)number * 8) / (p->ramp_start + (p->ramp_step * step_counter));
			    p->ramp_multiplier--;
			    gap3s = 0;
			    correction = p->del;
			    //printf("v ramp_mode == 1 novi del %ld in multoplier %d\n", p->del, p->ramp_multiplier);
			}       
			// if this was the last round, exit...
			if (p->ramp_multiplier < 0)
			    stop_flag = 1;
	    }

	    /* 	
	    in size ramp sending mode, when user has selected pps or delay between packets as rate. These means, 
	    that delay between packets will stay the same and only the packet size will change
	    */
	    else if ( ( p->ramp_mode > 2) )  {
	    	// in this case we change packet length but delay stays the same
			/* if the interval is over, let's recalculate delay */
			if (gap3s >= p->ramp_interval) {
				step_counter++;
				number = p->ramp_start + (p->ramp_step * step_counter);
				p->ramp_multiplier--;
				gap3s = 0;
				//printf("v ramp_mode > 2 novi number %ld in multoplier %d\n", number, p->ramp_multiplier);
			}       
			// if this was the last round, exit...
			if (p->ramp_multiplier < 0)
				stop_flag = 1;
	    }
	    
	    /*
	    in the size sending mode, but the user has selected Bandwith as rate. It means that BW will be the same and
	    because size of the packets will change, also the gap between packets has to change and we need to recalculate it
		*/
	    else if ( ( p->ramp_mode == 2) )  {
	    	// in this case we change packet length but delay stays the same
			/* if the interval is over, let's recalculate delay */
			if (gap3s >= p->ramp_interval) {
				step_counter++;
				number = p->ramp_start + (p->ramp_step * step_counter);
				p->del = (long long)(1000000 * (long long)number * 8) / (p->ramp_speed);
				p->ramp_multiplier--;
				gap3s = 0;
				//printf("v ramp_mode == 2 novi number %ld in p->del %ld in initial speed %ld \n", number, p->del, p->ramp_speed);
			}       
			// if this was the last round, then exit*/
			if (p->ramp_multiplier < 0)
				stop_flag = 1;
	    }

	    /* 
	    in case the duration option was choosed, we ignore the number of packets to send check inside this for loop so we need
	    to check if the duration selected is already over (if seconds transmitting is less than selected, then carry on, otherwise set
	    the stop_flag). Duration should be > 0 and p->count should be -3 (infinite) for this mode
		*/
	    if (( p->count == -3) && (p->duration <= gap2s) && (p->duration > 0)) {
			stop_flag = 1;
	    }

	    /* if stop button is pressed */
	    if (stop_flag == 1) {
			close(p->fd);
			return NULL;
	    }

	    /* 
	    OK, all the checks passed, now we need to check if there is already sending time or not. 
	    If there is time to send, do it again, otherwise do another round... 
	    if p->del == 1 then send always (this means that max speed was choosen 
	    */
	    
	    // XYZ
	    // if you want to send without correction, uncomment the line below and comment out the line with correction
	    
	    //if ((gap >= (p->del)) || (p->del == 1)) {
	    if ((gap >= (correction)) || (p->del == 1)) {

			c = sendto(p->fd, packet, number, 0, (struct sockaddr *)&p->sa, sizeof (p->sa));
			li++;

			last_ns.tv_sec = now_ns.tv_sec;
			last_ns.tv_nsec = now_ns.tv_nsec;
			gap = 0;

			if (c > 0) {
				sentnumber++;
				li_packets_sent = sentnumber;
				li_packets_sent_interval++;
			}

			/* do we need to change any fields */
			if (p->inc & (1<<0)) {
				/* changing source MAC address */
				/*packet[6] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));*/
				packet[7] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[8] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[9] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[10] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[11] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
			}
			/* change source IP address */
			if ( (p->inc & (1<<1)) && (p->ip_proto_in_use == 4)) {
				packet[p->ipv4start+12] = (packet[p->ipv4start+12] & ~(0xff>>maskv4[0])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv4[0]));
				packet[p->ipv4start+13] = (packet[p->ipv4start+13] & ~(0xff>>maskv4[1])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv4[1]));
				packet[p->ipv4start+14] = (packet[p->ipv4start+14] & ~(0xff>>maskv4[2])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv4[2]));
				packet[p->ipv4start+15] = (packet[p->ipv4start+15] & ~(0xff>>maskv4[3])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv4[3]));
			}
			/* change source IPv6 address */
			if ( (p->inc & (1<<2)) && (p->ip_proto_in_use == 6)) {
				packet[p->ipv6start+8] = (packet[p->ipv6start+8] & ~(0xff>>maskv6[0])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[0]));
				packet[p->ipv6start+9] = (packet[p->ipv6start+9] & ~(0xff>>maskv6[1])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[1]));
				packet[p->ipv6start+10] = (packet[p->ipv6start+10] & ~(0xff>>maskv6[2])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[2]));
				packet[p->ipv6start+11] = (packet[p->ipv6start+11] & ~(0xff>>maskv6[3])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[3]));
				packet[p->ipv6start+12] = (packet[p->ipv6start+12] & ~(0xff>>maskv6[4])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[4]));
				packet[p->ipv6start+13] = (packet[p->ipv6start+13] & ~(0xff>>maskv6[5])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[5]));
				packet[p->ipv6start+14] = (packet[p->ipv6start+14] & ~(0xff>>maskv6[6])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[6]));
				packet[p->ipv6start+15] = (packet[p->ipv6start+15] & ~(0xff>>maskv6[7])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[7]));
				packet[p->ipv6start+16] = (packet[p->ipv6start+16] & ~(0xff>>maskv6[8])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[8]));
				packet[p->ipv6start+17] = (packet[p->ipv6start+17] & ~(0xff>>maskv6[9])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[9]));
				packet[p->ipv6start+18] = (packet[p->ipv6start+18] & ~(0xff>>maskv6[10])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[10]));
				packet[p->ipv6start+19] = (packet[p->ipv6start+19] & ~(0xff>>maskv6[11])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[11]));
				packet[p->ipv6start+20] = (packet[p->ipv6start+20] & ~(0xff>>maskv6[12])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[12]));
				packet[p->ipv6start+21] = (packet[p->ipv6start+21] & ~(0xff>>maskv6[13])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[13]));
				packet[p->ipv6start+22] = (packet[p->ipv6start+22] & ~(0xff>>maskv6[14])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[14]));
				packet[p->ipv6start+23] = (packet[p->ipv6start+23] & ~(0xff>>maskv6[15])) + ((1+(int) (255.0*rand()/(RAND_MAX+1.0))) & (0xff>>maskv6[15]));
			}
			/* change source udp port */
			if ( (p->inc & (1<<3)) && (p->l4_proto_in_use == 17)) {
				packet[p->udpstart] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->udpstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
			}
			/* change source tcp port */
			if ( (p->inc & (1<<4)) && (p->l4_proto_in_use == 6)) {
				packet[p->tcpstart] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->tcpstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
			}
			/* increase the udp first payload byte value by one */
			if ( (p->inc & (1<<5)) && (p->l4_proto_in_use == 17)) {
				packet[p->udpstart+8]++;
			}
			/* changing RTP values: seq number++, timestamp for 10ms */
			if ( (p->inc & (1<<6)) && (p->l4_proto_in_use == 17)) {
				packet[p->udpstart+10] = li/256;
				packet[p->udpstart+11] = li%256;
				packet[p->udpstart+12] = (li*80)/16777216;
				packet[p->udpstart+13] = (li*80)/65536;
				packet[p->udpstart+14] = (li*80)/256;
				packet[p->udpstart+15] = (signed int)((li*80)%256);
			}
			/* changing RTP values: seq number++, timestamp for 20ms */
			if ( (p->inc & (1<<7)) && (p->l4_proto_in_use == 17)) {
				packet[p->udpstart+10] = li/256;
				packet[p->udpstart+11] = li%256;
				packet[p->udpstart+12] = (li*160)/16777216;
				packet[p->udpstart+13] = (li*160)/65536;
				packet[p->udpstart+14] = (li*160)/256;
				packet[p->udpstart+15] = (signed int)((li*160)%256);
			}
			/* changing RTP values: seq number++, timestamp for 30ms */
			if ( (p->inc & (1<<8)) && (p->l4_proto_in_use == 17)) {
				packet[p->udpstart+10] = li/256;
				packet[p->udpstart+11] = li%256;
				packet[p->udpstart+12] = (li*240)/16777216;
				packet[p->udpstart+13] = (li*240)/65536;
				packet[p->udpstart+14] = (li*240)/256;
				packet[p->udpstart+15] = (signed int)((li*240)%256);
			}
			/* changing byte x value */
			if (p->inc & (1<<9)) {
				/* increment it within specified range */
				if (p->xchange == 1) {
					if (xc < (p->xrange)) {
						stevec32 = (guint32*) &packet[p->xbyte-1];
						(*stevec32)++;
						xc++;
					}
					else    {
						memcpy(&packet[p->xbyte-1], p->xstart, 4);
						xc=0;
					}
				}
				/* decrement it within specified range */
				else if (p->xchange == 2) {
					if (xc < (p->xrange)) {
						stevec32 = (guint32*) &packet[p->xbyte-1];
						(*stevec32)--;
						xc++;
					}
					else    {
						memcpy(&packet[p->xbyte-1], p->xstart, 4);
						xc=0;
					}
				}
				/* set it random */
				else if (p->xchange == 0)
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));

				else if (p->xchange == 3) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte-0] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}       
					
				else if (p->xchange == 4) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}       
					
				else if (p->xchange == 5) {
					packet[p->xbyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->xbyte+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}       
						
			}
			/* changing byte y value */
			if (p->inc & (1<<10)) {
				/* byte y increment */
				if (p->ychange == 1) {
					if (yc < (p->yrange)) {
						stevec32 = (guint32*) &packet[p->ybyte-1];
						(*stevec32)++;
						yc++;
					}
					else    {
						memcpy(&packet[p->ybyte-1], p->ystart, 4);
						yc=0;
					}
				}
				/* decrement it within specified range */
				else if (p->ychange == 2) {
					if (yc < (p->yrange)) {
						stevec32 = (guint32*) &packet[p->ybyte-1];
						(*stevec32)--;
						yc++;
					}
					else    {
						memcpy(&packet[p->ybyte-1], p->ystart, 4);
						yc=0;
					}
				}
				/* set it random */
				else if (p->ychange == 0)
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));

				else if (p->ychange == 3) {
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte-0] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}       
					
				else if (p->ychange == 4) {
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}       
					
				else if (p->ychange == 5) {
					packet[p->ybyte-1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
					packet[p->ybyte+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				}       

			}
			/* for arp reply messages, change source MAC (ethernet part) *
			 * sender MAC and sender IP (arp part) */
			if ( (p->inc & (1<<11)) && (p->ip_proto_in_use == 806)) {
				//packet[p->ethstart] = 1+(int) (16.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+1] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+2] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+3] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+4] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+5] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+6] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+7] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+8] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				packet[p->ethstart+9] = 1+(int) (255.0*rand()/(RAND_MAX+1.0));
				//packet[6] = packet[p->ethstart];
				packet[7] = packet[p->ethstart+1];
				packet[8] = packet[p->ethstart+2];
				packet[9] = packet[p->ethstart+3];
				packet[10] = packet[p->ethstart+4];
				packet[11] = packet[p->ethstart+5];
			}
			/* correct the ipv4 checksum? */ 
			if ( (p->inc & (1<<16)) ) {
				packet[actualnumber-10] = 0x61;
				packet[actualnumber- 9] = 0x39;
				packet[actualnumber- 8] = 0x62;
				packet[actualnumber- 7] = 0x38;
				packet[actualnumber- 6] = 0x63;
				packet[actualnumber- 5] = 0x37;
				packet[actualnumber- 4] = 0x64;
				packet[actualnumber- 3] = 0x36;
				packet[actualnumber- 1]++;
				//(*(params1.ptr+params1.ph.incl_len-1))++;
			}
			/* correct the ipv4 checksum? */ 
			if ( (p->inc & (1<<12)) && (p->ip_proto_in_use == 4)) {
				/* first we set 0x00 in both fields and then recalculate it */
				packet[p->ipv4start+10] = 0x00;
				packet[p->ipv4start+11] = 0x00;
				ipcks = ((-1) - get_checksum16(p->ipv4start, p->ipv4start+19) % 0x10000);
				packet[p->ipv4start+10] = (char)(ipcks/256);
				packet[p->ipv4start+11] =  (char)(ipcks%256);
			}
			/* correct the UDP checksum value?*/
			if ( (p->inc & (1<<14)) && (p->l4_proto_in_use == 17)) {
				packet[p->udpstart+6] = (char)(0);
				packet[p->udpstart+7] =  (char)(0);

				if (p->ip_proto_in_use == 4) {
					pseudo_header = (guint32)(packet[p->ipv4start+9]);
					pseudo_header = pseudo_header + get_checksum32(p->ipv4start+12,p->ipv4start+19);
				}
				else if (p->ip_proto_in_use == 6) {
					pseudo_header = get_checksum32(p->ipv6start+8, p->ipv6start+39);
				}

				udpcksum = (guint32)(actualnumber - p->udpstart);

				/* pseudo header (ip part) + udplength + nr of cicles over guint16 */
				udpcksum = pseudo_header + udpcksum;

				/* what if length is odd */
				if( (actualnumber - (p->udpstart+8))%2 != 0) 
					odd = 1;
				/* previos value + part from udp checksum */
				udpcksum = udpcksum + get_checksum32(p->udpstart, actualnumber+odd);
				while (udpcksum >> 16)
					udpcksum = (udpcksum & 0xFFFF)+(udpcksum >> 16);
	
					/* the one's complement */
				udpcksum = (-1) - udpcksum;
			
				/* for ipv6 we need to substract 17 for udp protocol*/
				if (p->ip_proto_in_use == 6)
					udpcksum = udpcksum - 17;
			
				/* let's write it */
				packet[p->udpstart+6] = (char)(udpcksum/256);
				packet[p->udpstart+7] =  (char)(udpcksum%256);
			}
			/* correct tcp checksum*/
			if ( (p->inc & (1<<15)) && (p->l4_proto_in_use == 6)) {
				packet[p->tcpstart+16] = (char)(0);
				packet[p->tcpstart+17] =  (char)(0);

				if (p->ip_proto_in_use == 4) {
					pseudo_header = (guint32)(packet[p->ipv4start+9]);
					pseudo_header = pseudo_header + get_checksum32(p->ipv4start+12,p->ipv4start+19);
				}
				else if (p->ip_proto_in_use == 6) {
					pseudo_header = get_checksum32(p->ipv6start+8, p->ipv6start+39);
				}

				tcpcksum = (guint32)(actualnumber - p->tcpstart);
				/* pseudo header (ip part) + tcplength + nr of cicles over guint16 */
				tcpcksum = pseudo_header + tcpcksum;
				/* what if length is odd */
				if( (actualnumber - p->tcpstart)%2 != 0) 
					odd = 1;
				/* previos value + part from tcp checksum */
				tcpcksum = tcpcksum + get_checksum32(p->tcpstart, actualnumber+odd);
				while (tcpcksum >> 16)
					tcpcksum = (tcpcksum & 0xFFFF) + (tcpcksum >> 16);
				/* the one's complement */
				tcpcksum = (-1) - tcpcksum;

				/* if ipv6 is used, we need to substract -6 for tcp */
				if (p->ip_proto_in_use == 6) 
					tcpcksum = tcpcksum - 6;        
				/* let's write it */
				packet[p->tcpstart+16] = (char)(tcpcksum/256);
				packet[p->tcpstart+17] =  (char)(tcpcksum%256);
			}
			/* correct the icmp checksum...*/ 
			if ( (p->inc & (1<<13)) && (p->l4_proto_in_use == 1)) {
				packet[p->icmpstart+2] = (char)(0);
				packet[p->icmpstart+3] =  (char)(0);
				icmpcksum =  get_checksum16(p->icmpstart, p->icmpstop);
				/* the one's complement */
				icmpcksum = (-1) - icmpcksum;

				/* let's write it */
				packet[p->icmpstart+2] = (char)(icmpcksum/256);
				packet[p->icmpstart+3] =  (char)(icmpcksum%256);
			}
			/* correct the icmpv6 checksum...*/ 
			else if ( (p->inc & (1<<13)) && (p->l4_proto_in_use == 58)) {
				packet[p->icmpv6start+2] = (char)(0);
				packet[p->icmpv6start+3] =  (char)(0);

				pseudo_header = get_checksum32(p->ipv6start+8, p->ipv6start+39);

				icmpcksum = (guint32)(p->icmpv6stop - p->icmpv6start);

				/* pseudo header (ip part) + length + nr of cicles over guint16 */
				icmpcksum = pseudo_header + icmpcksum;
				/* if the length is odd we have to add a pad byte */
				if( (p->icmpv6stop - p->icmpv6start)%2 != 0)
				       odd = 1;
				/* previos value + part from checksum */
				icmpcksum = icmpcksum + get_checksum32(p->icmpv6start, p->icmpv6stop+odd);
				while (icmpcksum >> 16)
					icmpcksum = (icmpcksum & 0xFFFF)+ (icmpcksum >> 16);
				/* the one's complement */
				icmpcksum = (-1) - icmpcksum;

				// -58 stands for 3a what is protocol number for icmpv6
				//if (ip_proto_used == 6)
					icmpcksum = icmpcksum - 58;

				/* let's write it */
				packet[p->icmpv6start+2] = (char)(icmpcksum/256);
				packet[p->icmpv6start+3] = (char)(icmpcksum%256);
			}

	    }   
	    //else
	    //  test++;
	}


	//printf("  Sent all %ld packets on %s\n", sentnumber, iftext);
	stop_flag = 1;

	if (close(p->fd) != 0) {
		//printf("Warning! close(fd) returned -1!\n");
		//error("Warning! close(fd) returned -1!");
	}

	return NULL;

}


/* thread for sending sequences */
void* sendsequence (void *parameters)
{

	/* YYY check if li,... are long enough if inifinite number will be sent. Maybe put them into double */
	long li2, li=0, sentnumber = 0;
	long gap = 0, gap3 = 0;
	struct timeval nowstr1, first, last, last1;
	struct timespec first_ns, now_ns, last_ns;
	struct timespec first_ns1, now_ns1, last_ns1;
	int j, c;
	//struct sockaddr_ll sa;
	//struct ifreq ifr;

	struct params* p = (struct params*) parameters;

	/* this is the time we started */
	gettimeofday(&first, NULL);
	gettimeofday(&last, NULL);

	clock_gettime(CLOCK_MONOTONIC, &first_ns);
	clock_gettime(CLOCK_MONOTONIC, &now_ns);
	clock_gettime(CLOCK_MONOTONIC, &last_ns);

	/* to start first sequence immedialtelly */
	gap = p->del;

	for(j=0; j<10; j++)
		sentstream[j]=0;

	// now it depends how to send all the streams.... 
	if (p->random == 0) {

	   /* we check with == -3 if the infinite option was choosed */
	   for (li = 1; p->count == -3 ? TRUE : li < p->count; li++) {
		/* so wait the delay between sequences */
		while (gap < p->del) {
			//gettimeofday(&nowstr, NULL);
			clock_gettime(CLOCK_MONOTONIC, &now_ns);
			//gap = (nowstr.tv_sec*1000000 + nowstr.tv_usec) -
			//                      (last.tv_sec*1000000 + last.tv_usec);
			gap = (now_ns.tv_sec*1000000000 + now_ns.tv_nsec) -
				(last_ns.tv_sec*1000000000 + last_ns.tv_nsec);

			if (stop_flag == 1) {
				close(p->fd);
				return NULL;
			}
		}
		
		/* so we waited the desired time between sequences, now we go through all ten fields
		and send it if there is a name for a packet, and disable button is not on */
		for(j = 0; j < 10; j++) {
			/* skip it if there is no packet name */
			if (p->partable[j][0] == 0)
				continue;
			/* skip it if disable button is activated */
			if (p->partable[j][5] == 0)
				continue;

			/* now we are inside one sequence */
			/* this is the time we started */
			//gettimeofday(&first1, NULL);
			//gettimeofday(&last1, NULL);
			//gettimeofday(&nowstr1, NULL);

			clock_gettime(CLOCK_MONOTONIC, &first_ns1);
			clock_gettime(CLOCK_MONOTONIC, &now_ns1);
			clock_gettime(CLOCK_MONOTONIC, &last_ns1);
			
			/* to send first packet immedialtelly */
			gap3 = p->partable[j][3];

			/* now we will send this packet partable[j][2] number of times */
			for (li2 = 0; li2 < p->partable[j][2]; li2++) {
				/* wait enough time */
				while (gap3 < p->partable[j][3]) {
					//gettimeofday(&nowstr1, NULL);
					clock_gettime(CLOCK_MONOTONIC, &now_ns1);
					//gap3 = (nowstr1.tv_sec*1000000 + nowstr1.tv_usec) -
					//              (last1.tv_sec*1000000 + last1.tv_usec);
					gap3 = (now_ns1.tv_sec*1000000000 + now_ns1.tv_nsec) -
							(last_ns1.tv_sec*1000000000 + last_ns1.tv_nsec);

					if (stop_flag == 1) {
						close(p->fd);
						return NULL;
					}
				}

				/* put the packet on the wire */
				c = sendto(p->fd, p->pkttable[j], p->partable[j][1], 0, 
								(struct sockaddr *)&p->sa, sizeof (p->sa));

				last_ns1.tv_sec = now_ns1.tv_sec;
				last_ns1.tv_nsec = now_ns1.tv_nsec;
				gap3 = 0;

				if (c > 0) {
					sentstream[j]++;
					sentnumber++;
					li_packets_sent = sentnumber;
					//li_sentbytes = li_sentbytes + 24 + p->partable[j][1];
					li_sentbytes = li_sentbytes + p->partable[j][1];
				}

				if (sentnumber == p->count) {
					close(p->fd);
					stop_flag = 1;
					return NULL;
				}

				//gettimeofday(&nowstr, NULL);
				clock_gettime(CLOCK_MONOTONIC, &now_ns1);

				/* if the flag is set - the user clicked the stop button, we quit */
				if (stop_flag == 1) {
					close(p->fd);
					return NULL;
				}

			}
			
			/* here we gonna wait the desired time before sending the next row */
			//gettimeofday(&last1, NULL);   
			clock_gettime(CLOCK_MONOTONIC, &last_ns1);
			gap3 = 0;

			while (gap3 < p->partable[j][4]) {

				//gettimeofday(&nowstr1, NULL);
				clock_gettime(CLOCK_MONOTONIC, &now_ns1);
				gap3 = (now_ns1.tv_sec*1000000000 + now_ns1.tv_nsec) -
						(last_ns1.tv_sec*1000000000 + last_ns1.tv_nsec);

				if (stop_flag == 1) {
					close(p->fd);
					return NULL;
				}

			}
		}               
		//gettimeofday(&last, NULL);
		clock_gettime(CLOCK_MONOTONIC, &last_ns1);
		gap = 0;
	}
    }
    //ok, whe want to send all the streams in some random way... now how random is the random question :)
    else {
		//rewrite and accept only the active streams
		unsigned char pkttmp[10][9300];
		int pktnr[10], pktlength[10]; 
		int pktnrstart[10]; 
		float summ=0; 
		int rnd, out=0, in=0, sum=0;
		//int delay;
		int table[10000];
		//lets copy only the active streams in a cont. table without gaps, might be easier and faster
		for (j=0; j<10; j++) {
			/* skip it if there is no packet name or disable is activated or 0 packets in that stream to send */
			if ((p->partable[j][0] == 0) || (p->partable[j][5] == 0) || (p->partable[j][2]== 0)  ) {
				pktnr[j] = 0;
				continue;
			}
			else {
				//copy packet contents
				memcpy(&pkttmp[j][0], &(p->pkttable[j][0]), p->partable[j][1]);
				//number of packets to send
				pktnr[j] = p->partable[j][2];
				pktnrstart[j] = p->partable[j][2];
				//totol number of packets (all strems)
				summ = summ + pktnr[j];
				sum = (int)summ;
				pktlength[j] = p->partable[j][1];
			}
		}

		//now... if we have more than 10000 packets, go out
		if (summ > 9999) {
			error("not enough memory...");
			return NULL;
		}
		//table(out) stores which stream will be sent from 1-10. If there are 5,3,1 packets from streams 1,2,3
		//there will be table(out)= 0,0,0,0,0,1,1,1,2     (stream 1 has number 0)
		else {
			for (j=0, out=0; j<10; j++) {
				for (in=0; in<pktnr[j]; in++)  {
					table[out]=j;
					out++;
				}
			}
		}
		//printf("toklej p->del %lld \n", p->del);

		for (;;) {
			
			gettimeofday(&last1, NULL);
			gap3 = 0;

			rnd= (int) (summ*rand()/(RAND_MAX+1.0));
			rnd = table[rnd];

			// if one "cycle" is over, we have to reset it
			if (sum == 0)  {
				for (j=0; j<10; j++)
					pktnr[j]=pktnrstart[j];
				sum = (int) summ;
			}

			//we want to go sure, that random in random enough
			if (pktnr[rnd] > 0 ) {
				pktnr[rnd]--;   
				sum--;
			}
			else
				continue;

			c = sendto(p->fd, pkttmp[rnd], pktlength[rnd], 0, (struct sockaddr *)&p->sa, sizeof (p->sa));

			if (c > 0) {
				sentstream[rnd]++;
				sentnumber++;
				li_packets_sent = sentnumber;
				li_sentbytes = li_sentbytes + pktlength[rnd];
			}

			if (sentnumber == p->count) {
				stop_flag = 1;
				close(p->fd);
				return NULL;
			}

			//exit if stop flag is pressed
			if (stop_flag == 1) {
				close(p->fd);
				return NULL;
			}

			while (gap3 < p->del) {

				gettimeofday(&nowstr1, NULL);
				gap3 = (nowstr1.tv_sec*1000000 + nowstr1.tv_usec) -
						(last1.tv_sec*1000000 + last1.tv_usec);

				if (stop_flag == 1) {
					close(p->fd);
					return NULL;
				}
			}
		}

		return NULL;
    }

    stop_flag = 1;
    return NULL;
}

