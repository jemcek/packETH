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
 * function.c - all routines except callbacks and routines for sending
 *
 */

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <sys/time.h>
#include <sys/timeb.h>
#include <math.h>
#include <pthread.h>

#include <unistd.h>
#include <sys/types.h>

#include <net/if.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <netdb.h>

#include "callbacks.h"
#include "support.h"
#include "function.h"
#include "function_send.h"
#include "headers.h"
#include "config.h"

/* some global variables:
 * packet [] - the packet contents 
 * number - packet length
 * ... */
unsigned char packet[100001];
int number = 0;
int page;
gint autolength = 0;
int udp_start = 0;
int tcp_start = 0;
int icmp_start = 0;
int icmp_stop = 0;
int icmpv6_start = 0;
int icmpv6_stop = 0;
int ipv4_start = 0;
int ipv6_start = 0;
int eth_start = 0;
gboolean stop_flag = 0;
char iftext[20];
static unsigned long crc32_table[256];
int crc32_table_init = 0;
int ip_proto_used = 0; // 0 - none, 4 - ipv4, 6- IPv6, 806 - ARP
int l4_proto_used = 0; // 0 - none, 6 - tcp. 17 - udp
long li_packets_sent = 0;
long li_packets_sent_lastsec = 0;
long li_last_packets_sent = 0;
long li_sentbytes = 0;
int count10=0; 
long sentstream[10];
long desired_bw;
long sendtime = 0;

/* structure that holds parameters for generator */
struct params {
	long long del;
	double count;
	long inc;
	int type;
	gint timeflag;
	gint random;
	int udpstart; //udp payload start
	int tcpstart; //tcp header start
	int ipv4start;  //ipv4 header start
	int ipv6start;  //ipv6 header start
	int icmpstart;  //icmp and or icmpv6 header start
	int icmpstop;  //icmp and or icmpv6 header start
	int icmpv6start;  //icmp and or icmpv6 header start
	int icmpv6stop;  //icmp and or icmpv6 header start
	int ethstart;  //start of address position in arp header
	int xbyte;
	int ybyte;
	int xchange;
	int ychange;
	unsigned long xrange;
	unsigned long yrange;
	char xstart[4];
	char ystart[4];
	unsigned char pkttable[10][10000];
	/* partable columns mean: [0] - is there a packet or not (1)/(0), [1] - length of packet, [2] - 
	number of packets  [3] - gap between, [4] - gap to the next sequence, [5] - enable(1) / disable(0) */ 
	long int partable[10][6]; 
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
	int ramp_mode; // 0 - no ramp, 1 - speed ramp increasing, -1 - speed ramp decreasing, 2 - size ramp increasing, -2 - size ramp decreasing
	int ramp_multiplier;
	long long ramp_speed;
} params1;              

/* this function is called every second insiede the main gtk loop */
int gtk_timer(GtkButton *button) {
	
	GtkWidget *statusbar;
	GtkWidget *button1, *button2, *button3, *button4, *button5, *button6, *button7;
	gint context_id;
	char buff[200];
	unsigned int pkts=0;
	float mbits, link_mbits;
	float bw7, aw7;

	statusbar = lookup_widget("statusbar1");
	context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "Statusbar example");

	/* stats for Gen-b window this we do only once a second */
	if ((page == 1) && (count10 > 9)) {
		pkts = li_packets_sent_lastsec;
		mbits = (float)(pkts * number) / 125000; // 8 bits per byte / 1000000 for kbit
		link_mbits = (float)(pkts * (number + 24)) / 125000;
		bw7 = (float)desired_bw;
		aw7 = mbits*1000;

		//printf("torej, tokle je number %d tokle je desired %f in tokle actual %f in tokle razlika %.2f\n", number, bw7, aw7, ((bw7 - aw7) / bw7));
		//max speed option, no ok/nok warning
		if (desired_bw == 0) {
			snprintf(buff, 150, " Sent %ld pkts on %s (%d pkts/s, %.3f Mbit/s L2 data rate, %.3f Mbit/s link util, test duration %lds)", 
								li_packets_sent, iftext, pkts, mbits, link_mbits, sendtime);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
		}
		else {
			snprintf(buff, 120, " Sent %ld pkts on %s (%d pkts/s, %.3f Mbit/s L2 data rate, %.3f Mbit/s link util, test duration %lds)", 
								li_packets_sent, iftext, pkts, mbits, link_mbits, sendtime);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
		}
		
	
		//li_last_packets_sent = li_packets_sent;
		count10 = 0;
	}       
	/* stats for Gen-s window this we also do once a second */
	else if ((page == 2) && (count10 > 9)) {
		pkts = li_packets_sent - li_last_packets_sent;
		mbits = (float)(li_sentbytes) / 125000; // 8 bits per byte / 1000000 for mbit
		bw7 = (float)desired_bw;
		aw7 = mbits*1000;

		//printf("tokle je desired %f in tokle actual %f in tokle razlika %.2f\n", bw7, aw7, ((bw7 - aw7) / bw7));

		//under 100kbit/s the error rate is to sensible no nok warning
		if (aw7 < 100) {
			snprintf(buff, 150, "  Sent %ld packets on %s (%d packets/s, %.2f Mbit/s)", li_packets_sent, iftext, pkts, mbits);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
		}
		else if ( ((bw7 - aw7) / bw7)  > 0.1) {
			snprintf(buff, 150, "  Desired BW error > 10%%! Sent %ld packets on %s (%d packets/s, %.2f Mbit/s)", li_packets_sent, iftext, pkts, mbits);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
		}
		else {
			snprintf(buff, 150, "  Sent %ld packets on %s (%d packets/s, %.2f Mbit/s)", li_packets_sent, iftext, pkts, mbits);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
		}
	
		li_last_packets_sent = li_packets_sent;
		li_sentbytes=0;
		count10 = 0;
	}       

	/* to get better response, we check this every 100ms */
	if (stop_flag == 1) {
		button1 = lookup_widget("Build_button");
		button2 = lookup_widget("Gen_button");
		button3 = lookup_widget("Genp");
		button4 = lookup_widget("Interface_button");
		button5 = lookup_widget("Send_button");
		button6 = lookup_widget("Gensbt");
		button7 = lookup_widget("Stop_button");

		gtk_widget_set_sensitive (button1, TRUE);
		gtk_widget_set_sensitive (button2, TRUE);
		gtk_widget_set_sensitive (button3, TRUE);
		gtk_widget_set_sensitive (button4, TRUE);
		gtk_widget_set_sensitive (button5, TRUE);
		gtk_widget_set_sensitive (button6, TRUE);
		gtk_widget_set_sensitive (button7, FALSE);


		if (page == 1) {
			snprintf(buff, 100, "  Sent %ld packets on %s, test duration %lds ", li_packets_sent, iftext, sendtime);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
		}
		else if (page == 2) {
			snprintf(buff, 200, " Sent %ld packets on int: %s (Per stream: s1:%ld, s2:%ld, s3:%ld, s4:%ld, s5:%ld, s6: %ld, s7:%ld, s8:%ld, s9:%ld, s10:%ld)",  li_packets_sent, iftext, sentstream[0],sentstream[1], sentstream[2], sentstream[3], sentstream[4], sentstream[5], sentstream[6], sentstream[7],sentstream[8],sentstream[9]);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);

		}

		return FALSE;
	}

	count10 ++;
	return TRUE;
}

/* be carefull with number. when you build a packet you should make number++ after the last 
 * copied value in the packet[] field since you start with number = 0, but when you call 
 * packet_go_on_the_link() you pass that number as the number of packets which is one
 * more than in the last packet[number] = ... line */

/* send button was pressed */
int send_packet(GtkButton *button, gpointer user_data)
{
	GtkWidget *statusbar, *notebk, *reltime, *en5, *en6;
	GtkWidget *en1, *en2, *en3, *en4, *ckbt1, *ckbt2, *ckbt3, *ckbt4, *ckbt5, *xoptm, *yoptm;
	GtkWidget *optm1, *optm2, *optm3, *stopbt;
	GtkWidget *button1, *button2, *button3, *button4, *button5, *button6, *rndbt;
	GtkWidget *ckbt61, *ckbt50, *ckbt51, *ckbt52, *ckbt53, *ckbt54, *ckbt55;
	GtkWidget *ckbt56, *ckbt57, *ckbt58, *ckbt59, *ckbt60, *ckbt62, *ckbt63, *ckbt64, *ckbt65, *ckbt66, *ckbt67;
	GtkWidget *en219, *en220, *en221, *rdbt85, *rdbt95, *rdbt89, *rdbt91;
	GtkWidget *en222, *en223, *en224, *en225, *en226, *en227, *en228, *en229, *en230;

	int c, i, m, length, ramp_submode;
	gchar *en1_t, *en2_t, *en3_t, *en4_t, *en5_t, *en6_t, *en219_t, *en220_t, *en221_t;
	gchar *en222_t, *en223_t, *en224_t, *en225_t, *en226_t, *en227_t, *en228_t, *en229_t, *en230_t;
	gint context_id;
	char buff[100], buf2[80];
	struct tm *ptr;
	struct timespec tp;
	time_t now;
	pthread_t thread_id;

	stop_flag = 0;
	
	statusbar = lookup_widget("statusbar1");
	context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "Statusbar example");

	notebk = lookup_widget("notebook1");

	/* now we have to decide what happens when the send button is pressed */
	page =  gtk_notebook_get_current_page(GTK_NOTEBOOK(notebk));
	
	/* do we have the rights to do that? */
	if (getuid() && geteuid()) {
		snprintf(buff, 100, "  Sorry but you need the su rights");
		gtk_statusbar_push(GTK_STATUSBAR(button), GPOINTER_TO_INT(context_id), buff);
		error("Sorry but you need the su rights!");
		return -1;
	}

	if ( page == 0 ) { /* so we have the build notebook open, it means we send only one packet */   

		if (make_packet(button, user_data) == -1) {
			//printf("problems with making packet!\n");
			snprintf(buff, 100, "  Problems with making packet!");
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
			return -1;
		}
		
		/* YYY if the built packet is shorter then 60 bytes, we add padding zero bytes 
		 * to fill up the length till 60 (min ethrenet frame length). This bytes will be 
		 * added anyway by the device driver, so we do this just to prevent misunderstanding: 
		 * till now if your packet  was 20 bytes long, then it was also said -> 20 bytes 
		 * sent on eth0... but actually 60 bytes (+CRC) were sent */
		if (number < 60) {
			memset(&packet[number], 0x00, ( 60 - number ) );
			number = 60;
		}

		// thats how the packet looks like */
		//for (i = 0; i < number; i++)
		//      printf("%x ", packet[i]);
		//printf("\nnumber je %d\n", number);

		/* let's send the packet */
		c = packet_go_on_the_link(packet, number);

		if ( c == -2) {
			//printf("problems with sending\n");
			snprintf(buff, 100, "  Problems with sending!");
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
			return -1;
		}
                else if (c == -1) {
			snprintf(buff, 100, "  0 bytes sent on %s", iftext);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
                        error(" Could not sent packet:\n\nIs interface up?\nIs interface MTU larger than packet length?");
			return -1;
                        
                }
		else {
			clock_gettime(CLOCK_REALTIME, &tp);
			now=tp.tv_sec;
			ptr=localtime(&now);
			strftime(buf2,80, "%H:%M:%S", ptr);
			snprintf(buff, 100, " %s  -----> %d bytes sent on %s", buf2, c, iftext);
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
		}       

		return 1;
	}
	
	/* is it the generator that sends the build packets? */
	else if (page == 1) { 
		if (make_packet(button, user_data) == -1) {
			//printf("problems with making packet!\n");
			snprintf(buff, 100, "  Problems with making packet!");
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), 
							GPOINTER_TO_INT(context_id), buff);
			return -1;
		}

		/* open socket in raw mode */
		params1.fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (params1.fd == -1) {
			//printf("Error: Could not open socket!\n");
			snprintf(buff, 100, "  Problems with sending");
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
			error("Error: Could not open socket!");
			return -1;
		}               

		/* which interface would you like to use? */
		memset(&params1.ifr, 0, sizeof(params1.ifr));
		strncpy (params1.ifr.ifr_name, iftext, sizeof(params1.ifr.ifr_name) - 1);
		params1.ifr.ifr_name[sizeof(params1.ifr.ifr_name)-1] = '\0';

		/* does the interface exists? */
		if (ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr) == -1) {
			snprintf(buff, 100, "  Problems with sending");
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
			snprintf(buff, 100, "No such interface: %s", iftext);
			error(buff);
			close(params1.fd);
			return -1;
		}

		/* is the interface up? */
		ioctl(params1.fd, SIOCGIFFLAGS, &params1.ifr);
		if ( (params1.ifr.ifr_flags & IFF_UP) == 0) {
			snprintf(buff, 100, "  Problems with sending");
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
			snprintf(buff, 100, "Interface %s is down", iftext);
			error(buff);
			close(params1.fd);
			return -1;
		}

		/* just write in the structure again */
		ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr);

		/* well we need this to work, don't ask me what is it about */
		memset(&params1.sa, 0, sizeof (params1.sa));
		params1.sa.sll_family    = AF_PACKET;
		params1.sa.sll_ifindex   = params1.ifr.ifr_ifindex;
		params1.sa.sll_protocol  = htons(ETH_P_ALL);

		button1 = lookup_widget("Build_button");
		button2 = lookup_widget("Gen_button");
		button3 = lookup_widget("Genp");
		button4 = lookup_widget("Interface_button");
		button5 = lookup_widget("Send_button");
		button6 = lookup_widget("Gensbt");
		stopbt = lookup_widget("Stop_button");
		en1 = lookup_widget("entry109");
		en2 = lookup_widget("entry110");
		en3 = lookup_widget("entry206");
		en219 = lookup_widget ("entry219");
		en220 = lookup_widget ("entry220");
		en221 = lookup_widget("entry221");
		en222 = lookup_widget("entry222");
		en223 = lookup_widget("entry223");
		en224 = lookup_widget("entry224");
		en225 = lookup_widget("entry225");
		en226 = lookup_widget("entry226");
		en227 = lookup_widget("entry227");
		en228 = lookup_widget("entry228");
		en229 = lookup_widget("entry229");
		en230 = lookup_widget("entry230");
		ckbt1 = lookup_widget("checkbutton35");
		ckbt2 = lookup_widget("radiobutton80");
		ckbt3 = lookup_widget("radiobutton81");
		ckbt4 = lookup_widget("radiobutton87");
		ckbt5 = lookup_widget("radiobutton83");
		rdbt85 = lookup_widget("radiobutton85");
		rdbt95 = lookup_widget("radiobutton95");
		rdbt89 = lookup_widget("radiobutton89");
		rdbt91 = lookup_widget("radiobutton91");

		ckbt50 = lookup_widget ("checkbutton50");
		ckbt51 = lookup_widget ("checkbutton51");
		ckbt52 = lookup_widget ("checkbutton52");
		ckbt53 = lookup_widget ("checkbutton53");
		ckbt54 = lookup_widget ("checkbutton54");
		ckbt55 = lookup_widget ("checkbutton55");
		ckbt56 = lookup_widget ("checkbutton56");
		ckbt57 = lookup_widget ("checkbutton57");
		ckbt58 = lookup_widget ("checkbutton58");
		ckbt59 = lookup_widget ("checkbutton59");
		ckbt60 = lookup_widget ("checkbutton60");
		ckbt61 = lookup_widget ("checkbutton61");
		ckbt62 = lookup_widget ("checkbutton62");
		ckbt63 = lookup_widget ("checkbutton63");
		ckbt64 = lookup_widget ("checkbutton64");
		ckbt65 = lookup_widget ("checkbutton65");
		ckbt66 = lookup_widget ("checkbutton66");
		ckbt67 = lookup_widget ("checkbutton67");

		/* do we have to adjust any parameters while sending? */
		params1.inc = 0;
		//now set different bites for each parameter
		// source mac
		if ((gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt61))) ) params1.inc = params1.inc + 1;
		//source ipv4
		if ((gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt50))) ) {
			params1.inc = params1.inc + 2;
			//check what user has inserted for mask
			en219_t = (char *)gtk_entry_get_text(GTK_ENTRY(en219));
			length = strlen(en219_t);
			for(m=0; m<length; m++) {
				if (isdigit(*(en219_t+m)) == 0) {
					error("Error: Wrong IPv4 mask entry!");
					return -1;
				}
			}
			params1.ipv4mask = strtol(en219_t, (char **)NULL, 10);
			if ( (params1.ipv4mask < 0) || (params1.ipv4mask > 32) ) {
				error("Error: IPv4 mask must be between 0 and 32!");
				return -1;
			}
		}
		//source ipv6
		if ((gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt53))) ) {
			params1.inc = params1.inc + 4;
			//check what user has inserted for mask
			en220_t = (char *)gtk_entry_get_text(GTK_ENTRY(en220));
			length = strlen(en220_t);
			for(m=0; m<length; m++) {
				if (isdigit(*(en220_t+m)) == 0) {
					error("Error: Wrong IPv6 mask entry!");
					return -1;
				}
			}
			params1.ipv6mask = strtol(en220_t, (char **)NULL, 10);
			if ( (params1.ipv6mask < 0) || (params1.ipv6mask > 128) ) {
				error("Error: IPv6 mask must be between 0 and 128!");
				return -1;
			}
		}
		//source udp port
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt52)))  params1.inc = params1.inc + 8;
		//source tcp port
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt51)))  params1.inc = params1.inc + 16;
		//udp first payload byte
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt54)))  params1.inc = params1.inc + 32;
		// rtp set nr and timestamp 10ms
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt55)))  params1.inc = params1.inc + 64;
		// rtp set nr and timestamp 20ms
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt56)))  params1.inc = params1.inc + 128;
		// rtp set nr and timestamp 30ms
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt57)))  params1.inc = params1.inc + 256;
		// change byte x
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt58)))  params1.inc = params1.inc + 512;
		//change byte y
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt59)))  params1.inc = params1.inc + 1024;
		//arp reply random source ip and mac
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt60)))  params1.inc = params1.inc + 2048;
		// correct ipv4 checksum
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt62)))  params1.inc = params1.inc + 4096;
		// corrent icmp & icmpv6 checksums
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt63)))  params1.inc = params1.inc + 8192;
		// correct udp checksum
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt64)))  params1.inc = params1.inc + 16384;
		// correct tcp checksum
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt65)))  params1.inc = params1.inc + 32768;
		// correct tcp checksum
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt67)))  params1.inc = params1.inc + 65536;

		//printf("tokle je params1.inc %d\n", params1.inc);

		en1_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));
		en2_t = (char *)gtk_entry_get_text(GTK_ENTRY(en2));
		en3_t = (char *)gtk_entry_get_text(GTK_ENTRY(en3));
		en221_t = (char *)gtk_entry_get_text(GTK_ENTRY(en221));
		en222_t = (char *)gtk_entry_get_text(GTK_ENTRY(en222));
		en223_t = (char *)gtk_entry_get_text(GTK_ENTRY(en223));
		en224_t = (char *)gtk_entry_get_text(GTK_ENTRY(en224));
		en225_t = (char *)gtk_entry_get_text(GTK_ENTRY(en225));
		en226_t = (char *)gtk_entry_get_text(GTK_ENTRY(en226));
		en227_t = (char *)gtk_entry_get_text(GTK_ENTRY(en227));
		en228_t = (char *)gtk_entry_get_text(GTK_ENTRY(en228));
		en229_t = (char *)gtk_entry_get_text(GTK_ENTRY(en229));
		en230_t = (char *)gtk_entry_get_text(GTK_ENTRY(en230));

		/* changing mac address */
		if ( ((params1.inc & (1<<0)) ) && (number < 14) ) {
				error("Error: Packets is not long enough to change MAC address");
				return -1;      
		}
		/* changing ip source address */
		if ( ((params1.inc & (1<<1)) ) && (number < (ipv4_start + 20)) && (ip_proto_used == 4) ) {
				error("Error: Packet is not long enough to change source IP address");
				return -1;
		}
		/* ipv6 source address */
		if ( ((params1.inc & (1<<2)) ) && (number < (ipv6_start + 40) ) && (ip_proto_used == 6)) {
				error("Error: Packet is not long enough to change source IPv6 address");
				return -1;
		}
		/* source udp port */
		if ( ((params1.inc & (1<<3)) ) && (number < (udp_start + 8)) && (l4_proto_used == 17)) {
				error("Error: Packet isn't long enough to change UDP port");
				return -1;      
		}
		/* tcp source port */
		if ( ((params1.inc & (1<<4)) ) && (number < (tcp_start + 20)) && (l4_proto_used == 6) ) {
				error("Error: Packet isn't long enough to change TCP port");
				return -1;      
		}
		/* increase udp payload by one */
		if ( ((params1.inc & (1<<5)) ) && (number < (udp_start + 9)) && (l4_proto_used == 17) ) {
				error("Error: Packet is not long enough to increase UDP payload");
				return -1;      
		}
		/* rtp values */
		if ( ((params1.inc & (1<<6)) ) && (number < (udp_start + 14)) && (l4_proto_used == 17) ) {
				error("Error: Packet is not long enough to increase RTP values");
				return -1;
		}
		/* rtp values */
		if ( ((params1.inc & (1<<7)) ) && (number < (udp_start + 14)) && (l4_proto_used == 17) ) {
				error("Error: Packet is not long enough to increase RTP values");
				return -1;
		}
		/* rtp values */
		if ( ((params1.inc & (1<<8)) ) && (number < (udp_start + 14)) && (l4_proto_used == 17) ) {
				error("Error: Packet is not long enough to increase RTP values");
				return -1;
		}
		/* arp values */
		if ( ((params1.inc & (1<<11)) ) && (number < (eth_start + 1 + 6 + 4)) && (ip_proto_used == 806) ) {
				error("Error: Packet is not long enough to change ARP values");
				return -1;
		}
		/* changing byte x */
		if ( (params1.inc & (1<<9)) ) {
			/* offset x field, is it ok */
			en5 = lookup_widget("entry160");
			en5_t = (char *)gtk_entry_get_text(GTK_ENTRY(en5));
			length = strlen(en5_t);
			for(m=0; m<length; m++) {
				if (isdigit(*(en5_t+m)) == 0) {
				error("Error: Wrong byte x entry!");
				return -1;
				}
			}
			if ( (strtol(en5_t, (char **)NULL, 10) == 0) || 
					(number < strtol(en5_t, (char **)NULL, 10)) ) {
				error("Error: Wrong byte x offset!");
				return -1;      
			}
			params1.xbyte = strtol(en5_t, (char **)NULL, 10);

			/* option menu button for x byte */
			xoptm = lookup_widget("optionmenu14");
			params1.xchange = gtk_combo_box_get_active (GTK_COMBO_BOX (xoptm));
			memcpy(params1.xstart, &packet[params1.xbyte-1], 4);

			if ((params1.xchange==1) || (params1.xchange==2)) {
				/* range button for x byte */
				en5 = lookup_widget("entry161");
				en5_t = (char *)gtk_entry_get_text(GTK_ENTRY(en5));
				length = strlen(en5_t);
				for(m=0; m<length; m++) {
					if (isdigit(*(en5_t+m)) == 0) {
					error("Error: Wrong byte x range entry!");
					return -1;
					}
				}
				if ( (strtol(en5_t, (char **)NULL, 10) == 0) ) { 
					error("Error: Wrong byte x range!");
					return -1;      
				}
				params1.xrange = strtol(en5_t, (char **)NULL, 10);
			}

		}
		/* changing byte y */
		if ( (params1.inc & (1<<10)) ) {
			en6 = lookup_widget("entry162");
			en6_t = (char *)gtk_entry_get_text(GTK_ENTRY(en6));
			length = strlen(en6_t);
			for(m=0; m<length; m++) {
				if (isdigit(*(en6_t+m)) == 0) {
				error("Error: Wrong byte y entry!");
				return -1;
				}
			}
			if ( (strtol(en6_t, (char **)NULL, 10) == 0) || 
					(number < strtol(en6_t, (char **)NULL, 10)) ) {
				error("Error: Wrong byte y offset!");
				return -1;      
			}
			params1.ybyte = strtol(en6_t, (char **)NULL, 10);
			yoptm = lookup_widget("optionmenu15");
			memcpy(params1.ystart, &packet[params1.ybyte-1], 4);
			params1.ychange = gtk_combo_box_get_active (GTK_COMBO_BOX (yoptm));

			if ((params1.ychange==1) || (params1.ychange==2)) {
				en6 = lookup_widget("entry163");
				en6_t = (char *)gtk_entry_get_text(GTK_ENTRY(en6));
				if ( (strtol(en6_t, (char **)NULL, 10) == 0) )  {
					error("Error: Wrong byte y range!");
					return -1;      
				}
				length = strlen(en6_t);
				for(m=0; m<length; m++) {
					if (isdigit(*(en6_t+m)) == 0) {
					error("Error: Wrong byte y range entry!");
					return -1;
					}
				}
				params1.yrange = strtol(en6_t, (char **)NULL, 10);
			}

		}

		/* Infinite -  just keep on sending till stop is pressed */
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rdbt91))) {
			params1.count = -3;
			params1.duration = 0;
		}
		/* number of packets to send*/
		else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rdbt89))) {
			/* there can be rubbish in this field */
			if (check_digit(en1_t, strlen(en1_t), "Error: Number of packets to send field") == -1)
					return -1;

			params1.count = strtol(en1_t, (char **)NULL, 10);
			/* we allow to send 999999999 max */
			if ( (params1.count > 999999999) || (params1.count < 1) ) {
				//printf("Error: Packets send number value\n");
				error("Error: Packets send number value (1 - 999999999)");
				return -1;
			}
			params1.duration = 0;
		}
		/* duration in seconds */
		else {
			/* there can be rubbish in this field */
			if (check_digit(en222_t, strlen(en222_t), "Error: Duration of seconds to send field") == -1)
					return -1;

			params1.duration = strtol(en222_t, (char **)NULL, 10);
			/* we allow max 9999999 seconds */
			if ( (params1.duration > 9999999) || (params1.duration < 1) ) {
				//printf("Error: Packets send number value\n");
				error("Error: Seconds duration value (1 - 9999999)");
				return -1;
			}
			params1.count = -3;
		}

		// speed & bandwidth selection
		// bandwidth
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt2))) {
			params1.ramp_mode = 0; // we will overide this in case speed ramp (1) or size ramp (2)
			ramp_submode = 0;
			/* there can be rubbish in this field */
			if (check_digit(en3_t, strlen(en3_t), "Error: Bandwidth") == -1)
					return -1;

			params1.del = strtoll(en3_t, (char **)NULL, 10);

			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt5)))  //Mbit/s
				params1.del = params1.del * 1000;

			params1.ramp_speed = params1.del;

			/* max bandwidth 100G == 100000M == 100000000Kbit/s */
			if ( (params1.del > 100000000) || (params1.del < 1) ) {
				//printf("Error: Bandwidth\n");
				error("Error: Bandwidth (1-100000000kbit/s (100G))");
				return -1;
			}
			
			desired_bw = (long)params1.del;

			//printf("v  %lld\n", params1.del);
			//convert kbit/s to delay between them...
			if (number < 60) 
				params1.del = (long long)(1000000 * 60 * 8) / params1.del;
			else
				//tmpL = 1000000.0 * (double)number * 8.0 / tmpL;
				params1.del = (long long)(1000000 * (long long)number * 8) / params1.del;

			//printf("v pcl %lld\n", params1.del);
			//faster we can't do it... 1us is the resolution...
			if (params1.del < 1)
				params1.del = 1;

		}
		// delay between packets
		else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt3))) {
			params1.ramp_mode = 0; // we will overide this in case speed ramp (1) or size ramp (2)
			ramp_submode = 1;
			/* there can be rubbish in this field */
			if (check_digit(en2_t, strlen(en2_t), "Error: Delay between packets field") == -1)
					return -1;

			params1.del = strtoll(en2_t, (char **)NULL, 10);
			/* max delay 999,999999 s */
			if ( (params1.del > 999999999) || (params1.del < 1) ) {
				//printf("Error: Delay between packets value\n");
				error("Error: Delay between packets value (1-999999999)");
				return -1;
			}
			if ((gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rdbt85))) ) {
				params1.del = params1.del * 1000;
				if (number < 60)
					desired_bw = (long)(1000000*60*8/params1.del); 
				else
					desired_bw = (long)(1000000*(long long)number*8/params1.del); 
				//printf("v pcl %lld\n", params1.del);
				//printf("v pcl %ld\n", desired_bw);
			}
			else {
				if (number < 60)
					desired_bw = (long)(1000000*60*8/params1.del); 
				else
					desired_bw = (long)(1000000*(long long)number*8/params1.del); 
				//printf("v pcl %lld\n", params1.del);
				//printf("v pcl %ld\n", desired_bw);
			}
			//printf("v pcl %lld\n", params1.del);
		}
		// packets per second
		else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt4))) {
			params1.ramp_mode = 0; // we will overide this in case speed ramp (1) or size ramp (2)
			ramp_submode = 2;
			/* there can be rubbish in this field */
			if (check_digit(en221_t, strlen(en221_t), "Error: Packets per seconds field") == -1)
					return -1;

			params1.del = strtoll(en221_t, (char **)NULL, 10);
			/* max delay 999,999999 s */
			if ( (params1.del > 999999999) || (params1.del < 1) ) {
				//printf("Error: Delay between packets value\n");
				error("Error: Packets per seconds field (1-999999999)");
				return -1;
			}
			params1.del = 1000000000 / params1.del ;
			if (number < 60)
				desired_bw = (long)(1000000*60*8/params1.del); 
			else
				desired_bw = (long)(1000000*(long long)number*8/params1.del); 
			//printf("v pps  %lld\n", params1.del);
			//printf("v pps %ld\n", desired_bw);
			//printf("v pcl %lld\n", params1.del);
		}
		// ramp
		else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rdbt95))) {
			params1.ramp_mode = 1;
			ramp_submode = 3;
			/* there can be rubbish in this field */
			if (check_digit(en223_t, strlen(en223_t), "Error: Bandwidth ramp start speed") == -1)  return -1;
			if (check_digit(en224_t, strlen(en224_t), "Error: Bandwidth ramp stop speed") == -1)  return -1;
			if (check_digit(en225_t, strlen(en225_t), "Error: Bandwidth ramp step speed") == -1)  return -1;
			if (check_digit(en226_t, strlen(en226_t), "Error: Bandwidth ramp interval") == -1)  return -1;

			params1.ramp_start = strtoll(en223_t, (char **)NULL, 10);
			params1.ramp_stop = strtoll(en224_t, (char **)NULL, 10);
			params1.ramp_step = strtoll(en225_t, (char **)NULL, 10);
			params1.ramp_interval = strtoll(en226_t, (char **)NULL, 10);

			if ( (params1.ramp_start > 9999) || (params1.ramp_start < 1) ) {
				error("Error: Bandwidth ramp start speed (1Mbit/s - 9999Mbit/s)");
				return -1;
			}
			if ( (params1.ramp_stop > 9999) || (params1.ramp_stop < 1) ) {
				error("Error: Bandwidth ramp stop speed (1Mbit/s - 9999Mbit/s)");
				return -1;
			}
			if ( (params1.ramp_step > 9999) || (params1.ramp_step < 1) ) {
				error("Error: Bandwidth ramp step speed (1Mbit/s - 9999Mbit/s)");
				return -1;
			}
			if ( (params1.ramp_interval > 999999) || (params1.ramp_interval < 1) ) {
				error("Error: Bandwidth ramp interval (1 - 999999 sec)");
				return -1;
			}

			params1.ramp_start = params1.ramp_start * 1000;
			params1.ramp_stop  = params1.ramp_stop  * 1000;
			params1.ramp_step  = params1.ramp_step  * 1000;
			/* how many times we have to increase/decrease speed */
			params1.ramp_multiplier = (params1.ramp_stop - params1.ramp_start) / params1.ramp_step;

			/* if this is a ramp down, we just make the step a negative value and that's it */
			if (params1.ramp_multiplier < 0) {
				params1.ramp_multiplier = params1.ramp_multiplier * (-1);
				params1.ramp_step = params1.ramp_step * (-1);
			}

			if (number < 60) {
				params1.del  = (long long)(1000000 * 60 * 8) / params1.ramp_start;
			}
			else {
				params1.del = (long long)(1000000 * (long long)number * 8) / params1.ramp_start;
			}

			//printf("tokle je korakov %d in tokle je step %d in tokle je mode %d\n", params1.ramp_multiplier, params1.ramp_step, params1.ramp_mode);
			//printf("v pcl %lld\n", params1.del);
			//faster we can't do it... 1us is the resolution...
		}
		else {
			//max speed
			params1.ramp_mode = 0;
			ramp_submode = 4;
			params1.del = 1;
			desired_bw = 0;
		}

		// it the ramp for size is active
		if ( (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt66))) && !(gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rdbt95))) ){
			//which ramp submode is on? if this is bandwith, then delay between packets will chande with different mode
			// all other submodes have same delay, so bandwidth will change due to longer/shorter packets
			params1.ramp_mode = 2;
			params1.ramp_mode = params1.ramp_mode + ramp_submode; //2 -means bw was chosse, >2 all other modes
			/* there can be rubbish in this field */
			if (check_digit(en227_t, strlen(en227_t), "Error: Size ramp start length") == -1)  return -1;
			if (check_digit(en228_t, strlen(en228_t), "Error: Size ramp stop length") == -1)  return -1;
			if (check_digit(en229_t, strlen(en229_t), "Error: Size ramp step length") == -1)  return -1;
			if (check_digit(en230_t, strlen(en230_t), "Error: Size ramp interval") == -1)  return -1;

			params1.ramp_start = strtoll(en227_t, (char **)NULL, 10);
			params1.ramp_stop = strtoll(en228_t, (char **)NULL, 10);
			params1.ramp_step = strtoll(en229_t, (char **)NULL, 10);
			params1.ramp_interval = strtoll(en230_t, (char **)NULL, 10);

			if ( (params1.ramp_start > MAX_MTU) || (params1.ramp_start < 60) ) {
				error("Error: Size ramp start length (60 - " MAX_MTU_STR "bytes)");
				return -1;
			}
			if ( (params1.ramp_stop > MAX_MTU) || (params1.ramp_stop < 60) ) {
				error("Error: Size ramp stop length (60 - " MAX_MTU_STR " bytes)");
				return -1;
			}
			if ( (params1.ramp_step > MAX_MTU) || (params1.ramp_step < 1) ) {
				error("Error: Size ramp step length (1 - " MAX_MTU_STR " bytes)");
				return -1;
			}
			if ( (params1.ramp_interval > 999999) || (params1.ramp_interval < 1) ) {
				error("Error: Size ramp interval (1 - 999999 sec)");
				return -1;
			}

			/* how many times we have to increase/decrease speed */
			params1.ramp_multiplier = (params1.ramp_stop - params1.ramp_start) / params1.ramp_step;

			/* if this is a ramp down, we just make the step a negative value and that's it */
			if (params1.ramp_multiplier < 0) {
				params1.ramp_multiplier = params1.ramp_multiplier * (-1);
				params1.ramp_step = params1.ramp_step * (-1);
			}

			if (number < params1.ramp_start) {
				error("Error: Built packet must be >= Size ramp start length!");
				return -1;
			}
			if (number < params1.ramp_stop) {
				error("Error: Built packet must be >= Size ramp stop length!");
				return -1;
			}

			//printf("tokle je korakov %d in tokle je step %d in tokle je mode %d\n", params1.ramp_multiplier, params1.ramp_step, params1.ramp_mode);
			//printf("v pcl %lld\n", params1.del);
			//faster we can't do it... 1us is the resolution...
		}

		/* YYY if the built packet is shorter then 60 bytes, we add padding zero bytes 
		 * to fill up the length till 60 (min ethrenet frame length). This bytes will be 
		 * added anyway by the device driver, so we do this just to prevent misunderstanding: 
		 * till now if your packet  was 20 bytes long, then it was also said -> 20 bytes 
		 * sent on eth0... but actually 60 bytes (+CRC) were sent */
		if (number < 60) {
			memset(&packet[number], 0x00, ( 60 - number ) );
			/* there were problems with sendbuilt function, if the packet was shorter then
			 * 60 bytes. Checksum was wrong calculated */
			/* number = 60; */
		}

		params1.udpstart = udp_start;
		params1.tcpstart = tcp_start;
		params1.ipv4start = ipv4_start;
		params1.ipv6start = ipv6_start;
		params1.ethstart = eth_start;
		params1.icmpstart = icmp_start;
		params1.icmpstop = icmp_stop;
		params1.icmpv6start = icmpv6_start;
		params1.icmpv6stop = icmpv6_stop;
		params1.ip_proto_in_use = ip_proto_used;
		params1.l4_proto_in_use = l4_proto_used;

		//if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(reltime))) 
			params1.timeflag = 1;
		//else
		//      params1.timeflag = 0;

		gtk_widget_set_sensitive (button1, FALSE);
		gtk_widget_set_sensitive (button2, FALSE);
		gtk_widget_set_sensitive (button3, FALSE);
		gtk_widget_set_sensitive (button4, FALSE);
		gtk_widget_set_sensitive (button5, FALSE);
		gtk_widget_set_sensitive (button6, FALSE);
		gtk_widget_set_sensitive (stopbt, TRUE);

		snprintf(buff, 100, "  Starting generator...");
		gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);

		li_packets_sent = 0;
		li_last_packets_sent = 0;
		count10 = 0;
		g_timeout_add( 100, (GSourceFunc)gtk_timer, button);

		pthread_create(&thread_id, NULL, &sendbuilt, &params1);

		return 1;
	}

	/* is it the generator that sends different sequences? */
	else if (page == 2) { 
		char buff4[101];
		FILE *file_p;
		int j = 0, sum = 0, sum1 = 0;
		GtkWidget *optm11, *optm22;

		//abstime = lookup_widget("radiobutton36");
		reltime = lookup_widget("radiobutton37");
		//toolbar = lookup_widget("toolbar1");
		stopbt = lookup_widget("Stop_button");
		optm1 = lookup_widget("radiobutton72");
		optm11 = lookup_widget("radiobutton73");
		//optm111 = lookup_widget("radiobutton79");
		optm2 = lookup_widget("entry151");
		optm22 = lookup_widget("entry204");
		optm3 = lookup_widget("entry152");
		button1 = lookup_widget("Build_button");
		button2 = lookup_widget("Gen_button");
		button3 = lookup_widget("Genp");
		button4 = lookup_widget("Interface_button");
		button5 = lookup_widget("Send_button");
		button6 = lookup_widget("Gensbt");
		rndbt = lookup_widget("radiobutton78");

		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(reltime))) 
			params1.timeflag = 1;
		else
			params1.timeflag = 0;

		
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rndbt))) 
			params1.random = 1;
		else
			params1.random = 0;

		en2_t = (char *)gtk_entry_get_text(GTK_ENTRY(optm3));

		/* there can be rubbish in this field */
		if (check_digit(en2_t, strlen(en2_t), "Error: Delay between sequences field") == -1)
				return -1;

		params1.del = strtoll(en2_t, (char **)NULL, 10);
		/* max delay 999,999999 s */
		if ( (params1.del > 999999999) || (params1.del < 0) ) {
			//printf("Error: Delay between sequences field\n");
			error("Error: Delay between sequences field (0 - 999999999)");
			return -1;
		}

		/* we fill in a table with the parameters */
		for (i=0; i<10; i++) {

			/* name of the packet and packet contents */
			snprintf(buff4, 100, "entry%d", 111+i);
			en1 = lookup_widget(buff4);
			en1_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));

			/* enable or disable */
			snprintf(buff4, 100, "checkbutton%d", 25+i);
			ckbt1 = lookup_widget(buff4);
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ckbt1))) {
				params1.partable[i][5] = 0;
				continue;
			}
			else 
				params1.partable[i][5] = 1;

			/* if there is no name, skip it */
			if ( strlen(en1_t) == 0 )  {
				params1.partable[i][0] = 0;
				continue;
			}
			else
				params1.partable[i][0] = 1;

			/* open file for reading */
			if ( (file_p = fopen(en1_t, "r")) == NULL) {
				snprintf(buff4, 100, "Error: Can not open file for reading:%s", en1_t);
				//printf("Error: Can not open file for reading %s\n", en1_t);
				error(buff4);
				return -1;
			}

			/* we have to read the packet contents stored in a file */
			{
			struct pcap_hdr fh;
			struct pcaprec_hdr ph;
			char pkt_temp[100];
			int freads;

			/* first we read the pcap file header */
			freads = fread(pkt_temp, sizeof(fh), 1, file_p);
			/* if EOF, exit */
			if (freads == 0)
				return 1;

			 memcpy(&fh, pkt_temp, 24);

			 /* if magic number in NOK, exit */
			 if (fh.magic != PCAP_MAGIC)
				return -1;

			/* next the  pcap packet header */
			freads = fread(pkt_temp, sizeof(ph), 1, file_p);

			/* if EOF, exit */
			if (freads == 0)
				return 1;

			/* copy the 16 bytes into ph structure */
			memcpy(&ph, pkt_temp, 16);

			/* and the packet itself, but only up to the capture length */
			freads = fread(&params1.pkttable[i][0], ph.incl_len, 1, file_p);

			/* if EOF, exit */
			if (freads == 0)
				return 1;

			fclose(file_p);
			params1.partable[i][1] = ph.incl_len;
			}

			/* number of packets to send */
			snprintf(buff4, 100, "entry%d", 121+i);
			en2 = lookup_widget(buff4);
			en2_t = (char *)gtk_entry_get_text(GTK_ENTRY(en2));
			snprintf(buff4, 100, "Error: Number of packets field in row %d", i+1);
			if (check_digit(en2_t,strlen(en2_t), buff4) == -1)
					return -1;

			params1.partable[i][2] = strtol(en2_t, (char **)NULL, 10);
			/* we allow to send 9999999 max */
			if ( (params1.partable[i][2] > 9999999) || (params1.partable[i][2] < 0) ) {
				snprintf(buff4, 100, "Error: number of packets value in row %d", i+1);
				//printf("Error: number of packets value in row %d\n", i+1);
				error(buff4);
				return -1;
			}

			if (params1.random == 0) {
				/* delay between packets */
				snprintf(buff4, 100, "entry%d", 131+i);
				en3 = lookup_widget(buff4);
				en3_t = (char *)gtk_entry_get_text(GTK_ENTRY(en3));
				snprintf(buff4, 100, "Error: Delay between packets field in row %d", i+1);
				if (check_digit(en3_t,strlen(en3_t), buff4) == -1)
						return -1;

				params1.partable[i][3] = strtol(en3_t, (char **)NULL, 10);
				/* max delay 999,999999 s */
				if ( (params1.partable[i][3] > 999999999) || (params1.partable[i][3] < 0) ) {
					snprintf(buff4, 100, "Error: delay between value in row %d", i+1);
					//printf("Error: delay between value in row %d\n", i+1);
					error(buff4);
					return -1;
				}
			
				/* delay to next sequence */
				snprintf(buff4, 100, "entry%d", 141+i);
				en4 = lookup_widget(buff4);
				en4_t = (char *)gtk_entry_get_text(GTK_ENTRY(en4));
				snprintf(buff4, 100, "Error: Delay to next value in row %d", i+1);
				if (check_digit(en4_t,strlen(en4_t), buff4) == -1)
						return -1;

				params1.partable[i][4] = strtol(en4_t, (char **)NULL, 10);
				/* max delay 999,999999 s */
				if ( (params1.partable[i][4] > 999999999) || (params1.partable[i][4] < 0) ) {
					snprintf(buff4, 100, "Error: delay to next value in row %d", i+1);
					//printf("Error: delay to next value in row %d\n", i+1);
					error(buff4);
					return -1;
				}
			}
			else {
				params1.partable[i][3] = 0;
				params1.partable[i][4] = 0;
				
			}       
		}       

		en1_t = (char *)gtk_entry_get_text(GTK_ENTRY(optm2));
		en3_t = (char *)gtk_entry_get_text(GTK_ENTRY(optm22));

		// number of cycles, convert this in number of packets
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(optm1))) {
			double tmp=0;

			/* there can be rubbish in this field */
			if (check_digit(en1_t, strlen(en1_t), 
							"Error: Number of cycles to send field") == -1)
					return -1;

			params1.count = strtod(en1_t, (char **)NULL);
			/* we allow to send 9999999 max */
			if ( (params1.count > 999999999) || (params1.count < 1) ) {
				//printf("Error: Number of sequences to send field\n");
				error("Error: Number of cycles to send field (1 - 999999999)");
				return -1;
			}
			for (i=0; i<10; i++)
				tmp = tmp + params1.partable[i][2]; 
			params1.count = params1.count * tmp;
		}
		// number of packets
		else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(optm11))) {
			/* there can be rubbish in this field */
			if (check_digit(en3_t, strlen(en3_t), 
							"Error: Number of total packets field") == -1)
					return -1;

			params1.count = strtod(en3_t, (char **)NULL);
			/* we allow to send 9999999999 max */
			if ( (params1.count > 9999999999.0) || (params1.count < 1) ) {
				//printf("Error: Number of sequences to send field\n");
				error("Error: Number of total packets (1 - 9999999999)");
				return -1;
			}
		}
		/* or just keep on sending till stop is pressed */
		else 
			params1.count = -3;

		/* if all the fields are empty or disabled we return immediattely */
		for (j=0; j<10; j++) {
			sum = sum + params1.partable[j][0];
			sum1 = sum1 + params1.partable[j][5];
		}

		if ( (sum ==0 ) || (sum1 == 0) ) {
			snprintf(buff, 100, "  Nothing to send...");
			gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);
			return 1;
		}

		/* open socket in raw mode */
		params1.fd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
		if (params1.fd == -1) {
			//printf("Error: Could not open socket!\n");
			snprintf(buff, 100, "  Problems with sending");
			gtk_statusbar_push(GTK_STATUSBAR(button), GPOINTER_TO_INT(context_id), buff);
			error("Error: Could not open socket!");
			return -1;
		}               

		/* which interface would you like to use? */
		memset(&params1.ifr, 0, sizeof(params1.ifr));
		strncpy (params1.ifr.ifr_name, iftext, sizeof(params1.ifr.ifr_name) - 1);
		params1.ifr.ifr_name[sizeof(params1.ifr.ifr_name)-1] = '\0';

		/* does the interface exists? */
		if (ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr) == -1) {
			snprintf(buff, 100, "  Problems with sending");
			gtk_statusbar_push(GTK_STATUSBAR(button), GPOINTER_TO_INT(context_id), buff);
			snprintf(buff, 100, "No such interface: %s", iftext);
			error(buff);
			close(params1.fd);
			return -1;
		}

		/* is the interface up? */
		ioctl(params1.fd, SIOCGIFFLAGS, &params1.ifr);
		if ( (params1.ifr.ifr_flags & IFF_UP) == 0) {
			snprintf(buff, 100, "  Problems with sending");
			gtk_statusbar_push(GTK_STATUSBAR(button), GPOINTER_TO_INT(context_id), buff);
			snprintf(buff, 100, "Interface %s is down", iftext);
			error(buff);
			close(params1.fd);
			return -1;
		}

		/* just write in the structure again */
		ioctl(params1.fd, SIOCGIFINDEX, &params1.ifr);

		/* well we need this to work, don't ask me what is it about */
		memset(&params1.sa, 0, sizeof (params1.sa));
		params1.sa.sll_family    = AF_PACKET;
		params1.sa.sll_ifindex   = params1.ifr.ifr_ifindex;
		params1.sa.sll_protocol  = htons(ETH_P_ALL);

		gtk_widget_set_sensitive (button1, FALSE);
		gtk_widget_set_sensitive (button2, FALSE);
		gtk_widget_set_sensitive (button3, FALSE);
		gtk_widget_set_sensitive (button4, FALSE);
		gtk_widget_set_sensitive (button5, FALSE);
		gtk_widget_set_sensitive (button6, FALSE);
		gtk_widget_set_sensitive (stopbt, TRUE);
	
		li_packets_sent = 0;
		li_last_packets_sent = 0;
		count10 = 0;
		g_timeout_add( 100, (GSourceFunc)gtk_timer, button);

		snprintf(buff, 100, "  Starting stream generator...");
		gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);

		pthread_create(&thread_id, NULL, &sendsequence, &params1);
		return 1;
	}

	/* is it the generator that uses the kernel module? */
	else if (page == 3) { 
		;
	}

	return 1;
}


int make_packet(GtkButton *button, gpointer user_data)
{
	GtkWidget *ipv4, *ipv6, *arp, *usedef;
	GtkWidget *text_e;
	int max, length;
	gchar *text;

	/* first we fill packet field with 0 */
	memset(packet, 0x00, 10000);

	/* YYY what about auto selection for link layer is on?
	 * in case of saving packet we don't get here and it is ok
	 * in case of user defined payload we automatically disable this feature and it is ok
	 * so what about arp, ipv4 and ipv6?
	 * in case of an arp packet we accept the auto get mac option and it means that 
	 * we take the source and destination mac address from the arp protokol field
	 * in case of an ipv4 packet this means that we don't open the raw socket but
	 * do all the sending on ip socket which helps us getting the mac address */
	
	//auto_bt = lookup_widget("auto_get_mac_cbt");
	ipv4 = lookup_widget("ippkt_radibt");
	ipv6 = lookup_widget("IPv6_rdbt");
	arp = lookup_widget("arppkt_radiobt");
	usedef = lookup_widget("usedef2_radibt");

	/* what about next layer: ipv4, ipv6, arp or manually attached payload? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ipv4))) {
		
		/* now we get the link layer info */
		if (link_level_get(button, user_data) == -1) {
			//printf("Error: problem on link layer with IPv4 packet\n");
			return -1;
		}

		/* call the function that gets the ipv4 protocol information */
		if (ipv4_get(button, user_data) == -1) {
			//printf("Error: problem with IPv4 information\n");
			return -1;
		}
		
		/* grrr, oh you could think on this earlier!!! */
		if (autolength > 0) {
			//printf("tole je auto %d tole pa number %d\n", autolength, number);
			packet[autolength] = (unsigned char)((number - (autolength + 2))/256);
			packet[autolength+1] = (unsigned char)((number - (autolength + 2))%256);
		}       
		
		return 1;
	}
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ipv6))) {
		/* now we get the link layer info */
		if (link_level_get(button, user_data) == -1) {
			return -1;
		}

		/* call the function that gets the ipv6 protocol information */
		if (ipv6_get(button, user_data) == -1) {
			//printf("Error: problem with IPv6 information\n");
			return -1;
		}
		return 1;
	}
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(arp))) {
	 
		/* now we get the link layer info */
		if (link_level_get(button, user_data) == -1) {
			//printf("Error: problem on link layer with arp packet\n");
			return -1;
		}

		/* call the function that gets the arp protocol information */
		if (arp_get(button, user_data) == -1) {
			//printf("Error: problem with arp information\n");
			return -1;
		}
			
		if (autolength > 0) {
			//printf("tole je auto %d tole pa number %d\n", autolength, number);
			packet[autolength] = (unsigned char)((number - (autolength + 2))/256);
			packet[autolength+1] = (unsigned char)((number - (autolength + 2))%256);
		}       
		return 1;
	}
	
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(usedef))) {
		/* if usedef is active we will manually get the link layer info */
		if (link_level_get(button, user_data) == -1) {
			//printf("Error: problem on link layer\n");
			return -1;
		}
		
		max = 9900;
 
		text_e = lookup_widget("text1");
		GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e));
		length = gtk_text_buffer_get_char_count(buffer);
		GtkTextIter start,end;
		gtk_text_buffer_get_bounds(buffer,&start,&end);
		text = gtk_text_buffer_get_text(buffer,&start,&end,FALSE);      
	
		if (get_network_payload(button, user_data, length, max, text) == -1) {
			//printf("Error: problem with payload on network layer\n");
			g_free(text);
			return -1;
		}
		else
			g_free(text);

		if (autolength > 0) {
			//printf("tole je auto %d tole pa number %d\n", autolength, number);
			packet[autolength] = (unsigned char)((number - (autolength + 2))/256);
			packet[autolength+1] = (unsigned char)((number - (autolength + 2))%256);
		}       
	}
	else {  /* none of above -> something is wrong! */
		//printf("Error: problem with network layer button\n");
		error("Error: problem with network layer button");
		return -1;
	}
		
	return 1;
}


int ipv6_get(GtkButton *button, gpointer user_data) {
	GtkWidget *version, *tos, *flowlabel, *payloadlength, *nextheader, *hoplimit;
	GtkWidget *src6ip, *dst6ip, *payloadlength_bt, *pay_text_e;
	GtkWidget *extensionhdr/*, *exthdrbto*/;
	GtkWidget *udp_bt, *tcp_bt, *icmp6_bt, *usedef_bt;

	gchar *version_t, *tos_t, *flowlabel_t, *plength_t, *next_t, *hop_t;
	gchar *src_t, *dst_t, *ext_t, *pay_text;
	guint32 pseudo_header_sum;
	int length_start, length_start_field=0, x_length, i;
	int pay_length, pay_max;
	//int dst_length;

	gchar tmp[4];
	gchar tmp2[6];
	//gchar src_tmp[40];
	//gchar dst_tmp[40];

	version = lookup_widget("entry195");
	tos = lookup_widget("entry196");
	flowlabel = lookup_widget("entry197");
	payloadlength = lookup_widget("entry198");
	payloadlength_bt = lookup_widget("checkbutton43");
	nextheader = lookup_widget("entry199");
	hoplimit = lookup_widget("entry200");
	src6ip = lookup_widget("entry201");
	dst6ip = lookup_widget("entry202");
	//src6bt = lookup_widget("button88");
	//dst6bt = lookup_widget("button89");
	extensionhdr = lookup_widget("entry203");
	//exthdrbto = lookup_widget("button91");
	udp_bt = lookup_widget("radiobutton67");
	tcp_bt = lookup_widget("radiobutton68");
	icmp6_bt = lookup_widget("radiobutton69");
	usedef_bt = lookup_widget("radiobutton71");

	version_t = (char *)gtk_entry_get_text(GTK_ENTRY(version));
	tos_t = (char *)gtk_entry_get_text(GTK_ENTRY(tos));
	flowlabel_t = (char *)gtk_entry_get_text(GTK_ENTRY(flowlabel));
	plength_t = (char *)gtk_entry_get_text(GTK_ENTRY(payloadlength));
	next_t = (char *)gtk_entry_get_text(GTK_ENTRY(nextheader));
	hop_t = (char *)gtk_entry_get_text(GTK_ENTRY(hoplimit));
	src_t = (char *)gtk_entry_get_text(GTK_ENTRY(src6ip));
	dst_t = (char *)gtk_entry_get_text(GTK_ENTRY(dst6ip));
	ext_t = (char *)gtk_entry_get_text(GTK_ENTRY(extensionhdr));

	ip_proto_used = 6;

	/* source ip address */
	ipv6_start = number;

	/*start parsing the ipv6 header */
	strncpy(&tmp[0], version_t, 1);
	strncpy(&tmp[1], tos_t, 1);
	strncpy(&tmp2[0], (tos_t+1), 1);
	strncpy(&tmp2[1], flowlabel_t, 5);
	
	if (char2x(tmp) == -1) {
		error("Error: ipv6 version or tos field");
		return -1;
	}

	packet[number] = (unsigned char)char2x(tmp);
	number++;
	
	if (char2x(tmp2) == -1) {
		error("Error: ipv6 tos field or flow label");
		return -1;
	}

	packet[number] = (unsigned char)char2x(tmp2);
	number++;

	if (char2x(tmp2+2) == -1) {
		error("Error: flow label");
		return -1;
	}

	packet[number] = (unsigned char)char2x(tmp2+2);
	number++;

	if (char2x(tmp2+4) == -1) {
		error("Error: ipv6 tos field or flow label");
		return -1;
	}

	packet[number] = (unsigned char)char2x(tmp2+4);
	number++;

	/* total length */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(payloadlength_bt))) {
		length_start_field = number;
		number++;
		number++;
	}
	else {
		length_start = 0; /* if length start is 0, then we leave it in the end */
		if ( (atol(plength_t) < 0) || (atol(plength_t) > 65535) ) {
			error("Error: ipv6 total length range");
			return -1;
		}

		/* there can be rubbish in this field */
		if (check_digit(plength_t, strlen(plength_t), 
					"Error: ipv6 total length field values") == -1)
				return -1;

		packet[number] = (char)(atol(plength_t)/256);
		number++;       
		packet[number] = (char)(atol(plength_t)%256);
		number++;       
	}

	if (char2x(next_t) == -1) {
		error("Error: ipv6 next header field");
		return -1;
	}

	packet[number] = (unsigned char)char2x(next_t);
	number++;

	/* hop limit */
	if ( (atoi(hop_t) < 0) || (atoi(hop_t) > 255) ) {
		error("Error: ipv6 hop limit range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(hop_t, strlen(hop_t), "Error: ipv6 hop limit field values") == -1)
				return -1;

	packet[number] = (char)(atoi(hop_t));
	number++;       

	// now the source address
	if (check_ipv6_address(src_t, 1) == -1) {
		error("Error: Wrong source ipv6 address");
		return -1;
	}
	
	// now the destination address
	if (check_ipv6_address(dst_t, 1) == -1) {
		error("Error: Wrong source ipv6 address");
		return -1;
	}
	
	
	//pseudo header for udp and tcp checksum
	pseudo_header_sum = get_checksum32(number-32, number-1);


	//extension headers 
	x_length = strlen(ext_t);
	if ( (x_length !=0) && (x_length % 16 != 0) ) {
		error("Error: extension header must be n times 64 bytes!");
		return -1;
	}
	
	for (i=0; i< (x_length/2); i++) {
		if (char2x(ext_t) == -1) {
			error("Error: extension header!");
			return -1;
		}
		packet[number] = (unsigned char)char2x(ext_t);
		number++;
		ext_t++; ext_t++;
	}
		
	//if auto header length button is enabled, this is where the packet length count starts
	length_start = number;

	/* so we came to the end of ip header. what is next? */
	/* tcp, udp, icmp or manually attached payload? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(udp_bt))) {
		if (udp_get(button, user_data, pseudo_header_sum) == -1) {
			//printf("Error: Problem with UDP information\n");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tcp_bt))) {
		if (tcp_get(button, user_data, pseudo_header_sum) == -1) {
			//printf("Error: Problem with TCP information\n");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(icmp6_bt))) {
		if (icmpv6_get(button, user_data, pseudo_header_sum) == -1) {
			//printf("Error: Problem with ICMP information\n");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(usedef_bt))) {
			
		pay_text_e = lookup_widget("text2");
		GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(pay_text_e));
		pay_length = gtk_text_buffer_get_char_count(buffer);    
		GtkTextIter start,end;
		//gtk_text_buffer_get_start_iter(buffer,start);
		//gtk_text_buffer_get_end_iter(buffer,end);
		gtk_text_buffer_get_bounds(buffer,&start,&end);
		pay_text = gtk_text_buffer_get_text(buffer,&start,&end,FALSE);
		//g_free(start);
		//g_free(end);
		//pay_text = (char *) malloc(pay_length + 1);
		//pay_text = gtk_editable_get_chars(GTK_EDITABLE(pay_text_e), 0, -1);

		/* YYY 1514-number is not ok in case we use 802.1q!!! */
		pay_max = 9900 - number;

		if (get_network_payload(button, user_data, pay_length, pay_max, pay_text) == -1) {
			//printf("Error: Problem with IPv4 payload\n");
			g_free(pay_text);
			return -1;
		}
		else
			g_free(pay_text);
	}

	else {
		error("Error: IPv6 zoombie error!!!");
		return -1;
	}
		
	
	/* so we are back again to cumpute the length and checksum. so this is for length */
	if (length_start > 0) {
		packet[length_start_field] = (char)((number - length_start)/256);
		packet[length_start_field+1] = (char)((number - length_start)%256);
	}

	return 1;
}

/* let's parse the IPv4 protokol information */
int ipv4_get(GtkButton *button, gpointer user_data) {
	GtkWidget *version, *header_length, *tos, *total_length, *identification, *flags;
	GtkWidget *frag_offset, *ttl, *protocol, *header_cks, *header_cks_bt;
	GtkWidget *src_ip, *dst_ip, *options, *total_length_bt;
	GtkWidget *udp_bt, *tcp_bt, *icmp_bt, *igmp_bt, *usedef_bt, *pay_text_e;
	gchar *version_t, *header_length_t, *tos_t, *total_length_t, *identification_t, *flags_t;
	gchar *frag_offset_t, *ttl_t, *protocol_t, *header_cks_t;
	gchar *src_ip_t, *dst_ip_t, *options_t, *pay_text;
	int length_start, header_cks_start, cks_start, cks_stop;
	gchar tmp[4];
	int i, j, pay_length, pay_max;
	guint16 value, ipcksum;
	guint32 pseudo_header_sum;
	
	version = lookup_widget("entry26");
	header_length = lookup_widget("entry27");
	tos = lookup_widget("entry28");
	total_length = lookup_widget("entry29");
	total_length_bt = lookup_widget("checkbutton21");
	identification = lookup_widget("entry30");
	flags = lookup_widget("entry31");
	frag_offset = lookup_widget("entry32");
	ttl = lookup_widget("entry44");
	protocol = lookup_widget("entry34");
	header_cks = lookup_widget("entry35");
	header_cks_bt = lookup_widget("ip_header_cks_cbt");
	src_ip = lookup_widget("entry38");
	dst_ip = lookup_widget("entry37");
	options = lookup_widget("entry39");
	udp_bt = lookup_widget("udp_bt");
	tcp_bt = lookup_widget("tcp_bt");
	icmp_bt = lookup_widget("icmp_bt");
	igmp_bt = lookup_widget("igmp_bt");
	usedef_bt = lookup_widget("ip_user_data_bt");
	
	version_t = (char *)gtk_entry_get_text(GTK_ENTRY(version));
	header_length_t = (char *)gtk_entry_get_text(GTK_ENTRY(header_length));
	tos_t = (char *)gtk_entry_get_text(GTK_ENTRY(tos));
	total_length_t = (char *)gtk_entry_get_text(GTK_ENTRY(total_length));
	identification_t = (char *)gtk_entry_get_text(GTK_ENTRY(identification));
	flags_t = (char *)gtk_entry_get_text(GTK_ENTRY(flags));
	frag_offset_t = (char *)gtk_entry_get_text(GTK_ENTRY(frag_offset));
	ttl_t = (char *)gtk_entry_get_text(GTK_ENTRY(ttl));
	protocol_t = (char *)gtk_entry_get_text(GTK_ENTRY(protocol));
	header_cks_t = (char *)gtk_entry_get_text(GTK_ENTRY(header_cks));
	src_ip_t = (char *)gtk_entry_get_text(GTK_ENTRY(src_ip));
	dst_ip_t = (char *)gtk_entry_get_text(GTK_ENTRY(dst_ip));
	options_t = (char *)gtk_entry_get_text(GTK_ENTRY(options));

	ip_proto_used = 4;
	
	/* we want to know where the ip header starts, to calculate the checksum later */
	cks_start = number;
	/* and also later for checking what parameters we can change */
	ipv4_start = number;

	/* now we have all the widgets, so let start parsing them */
	/* starting with version */
	strncpy(&tmp[0], version_t, 1);
	strncpy(&tmp[1], header_length_t, 1);
	
	if (char2x(tmp) == -1) {
		//printf("Error: ipv4 version or header length field\n");
		error("Error: ipv4 version or header length field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(tmp);
	number++;
	
	/* tos field */
	if (char2x(tos_t) == -1) {
		//printf("Error: ipv4 tos field\n");
		error("Error: ipv4 tos field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(tos_t);
	number++;

	/* total length */
	/* if auto is on then we have to calculate this, but we can do this
	 * at the end, when we have the whole ip packet together. so if auto 
	 * is enabled we set the marking and recaltulate it in the end */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(total_length_bt))) {
		length_start = number;
		number++;
		number++;
	}
	else {
		length_start = 0; /* if length start is 0, then we leave it in the end */
		if ( (atol(total_length_t) < 0) || (atol(total_length_t) > 65535) ) {
			//printf("Error: ipv4 total length range\n");
			error("Error: ipv4 total length range");
			return -1;
		}

		/* there can be rubbish in this field */
		if (check_digit(total_length_t, strlen(total_length_t), 
					"Error: ipv4 total length field values") == -1)
				return -1;

		packet[number] = (char)(atol(total_length_t)/256);
		number++;       
		packet[number] = (char)(atol(total_length_t)%256);
		number++;       
	}
	
	/* identification */
	if (char2x(identification_t) == -1) {
		//printf("Error: ipv4 identification field\n");
		error("Error: ipv4 identification field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(identification_t);
	number++;
	identification_t++; identification_t++;
	if (char2x(identification_t) == -1) {
		//printf("Error: ipv4 identification field\n");
		error("Error: ipv4 identification field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(identification_t);
	number++;

	/* flags and fragment offset */
	if ( (atoi(flags_t) > 7) || (atoi(flags_t) < 0) ) {
		//printf("Error: ipv4 flags field: the value can be beetwen 0 and 7\n");
		error("Error: ipv4 flags field: the value can be beetwen 0 and 7");
		return -1;
	}
		
	if ( (atoi(frag_offset_t) > 8191) || (atoi(frag_offset_t) < 0) ) {
		//printf("Error: ipv4 fragmentation offset field: (0 - 8191)\n");
		error("Error: ipv4 fragmentation offset field: (0 - 8191)");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(flags_t, strlen(flags_t), "Error: ipv4 flags values") == -1)
				return -1;

	/* there can be rubbish in this field */
	if (check_digit(frag_offset_t, strlen(frag_offset_t), 
					"Error: ipv4 fragmentation offset field values ") == -1)
				return -1;

	/* this is the correct int value now 
	 * we need to store it as 2 byte hex value */
	value = (atoi(flags_t)<<13   & 0xE000) | 
		(atoi(frag_offset_t) & 0x1FFF) ;
	
	/* YYY what about big endian computers - hope it works */
	value = htons(value);
	memcpy(&packet[number], &value, 2);
	number++;
	number++;
		
	/* ttl value */
	if ( (atoi(ttl_t) < 0) || (atoi(ttl_t) > 255) ) {
		//printf("Error: ipv4 ttl range\n");
		error("Error: ipv4 ttl range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(ttl_t, strlen(ttl_t), "Error: ipv4 ttl field values") == -1)
				return -1;

	packet[number] = (char)(atoi(ttl_t));
	number++;       

	/* protocol field */
	if ( (atoi(protocol_t) < 0) || (atoi(protocol_t) > 255) ) {
		//printf("Error: ipv4 protocol range\n");
		error("Error: ipv4 protocol range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(protocol_t, strlen(protocol_t), "Error: ipv4 protocol field values") == -1)
				return -1;

	packet[number] = (char)(atoi(protocol_t));
	number++;       

	pseudo_header_sum = (guint32)(packet[number-1]);
	
	/* header checksum */
	/* if auto is on then we have to calculate this, but we can do this
	 * at the end and recaltulate it for now we store the current number into
	 * another variable. we will calculate length in the end */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(header_cks_bt))) {
		header_cks_start = number;
		packet[number] = (unsigned char)0;
		number++;
		packet[number] = (unsigned char)0;
		number++;
	}
	else {
		/* if header_cks_start = 0, we leave it in the end */
		header_cks_start = 0;
		if (char2x(header_cks_t) == -1) {
			//printf("Error: ipv4 header checksum field\n");
			error("Error: ipv4 header checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(header_cks_t);
		header_cks_t++; header_cks_t++; number++;
		if (char2x(header_cks_t) == -1) {
			//printf("Error: ipv4 header checksum field\n");
			error("Error: ipv4 header checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(header_cks_t);
		number++;
	}
	
	if (check_ip_address(src_ip_t) == -1) {
		//printf("Error: Wrong source ipv4 address\n");
		error("Error: Wrong source ipv4 address");
		return -1;
	}
	
	for (i=0; i<4; i++) {
		for(j=0; j<4 && (*src_ip_t != '\0'); j++) {
			if ( ((int)*src_ip_t == '.') && (i<3) && (j>0) ) {
				src_ip_t++;
				break;
			}
			tmp[j] = *src_ip_t;
			src_ip_t++;
		}
		tmp[j] = '\0';
		packet[number] = (unsigned char)(atoi(tmp));
		number++;               
	}

	/* destination ip address */
	if (check_ip_address(dst_ip_t) == -1) {
		//printf("Error: Wrong destination ipv4 address\n");
		error("Error: Wrong destination ipv4 address");
		return -1;
	}
	
	for (i=0; i<4; i++) {
		for(j=0; j<4 && (*dst_ip_t != '\0'); j++) {
			if ( ((int)*dst_ip_t == '.') && (i<3) && (j>0) ) {
				dst_ip_t++;
				break;
			}
			tmp[j] = *dst_ip_t;
			dst_ip_t++;
		}
		tmp[j] = '\0';
		packet[number] = (unsigned char)(atoi(tmp));
		number++;               
	}

	/* this is checksum for protocol field plus IP source and destination 
	 * we need this later when we want to calculate the TCP or UDP checksum
	 * there we need this values so we pass them when calling the routine*/
	pseudo_header_sum = pseudo_header_sum + get_checksum32(number-8, number-1);
	
	/* options? do allow then and how long can they be??? 
	 * ok we allow them and limit them to 40 bytes and the user should 
	 * care that the options length is always a multiple of 32 bits (4 bytes) */
	if ( (strlen(options_t)%8) != 0) {
		//printf("Error: Wrong ipv4 length of options field (length mod 8 must be 0)\n");
		error("Error: Wrong ipv4 length of options field      \n(length mod 8 must be 0)");
		return -1;
	}
	
	if ( strlen(options_t) > 80) {
		//printf("Error: ipv4 options field to long\n");
		error("Error: ipv4 options field to long");
		return -1;
	}
	
	j = strlen(options_t)/2;
	for (i=0; i<j; i++) {
		if (char2x(options_t) == -1) {
			//printf("Error: ipv4 options field\n");
			error("Error: ipv4 options field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(options_t);
		number++; options_t++; options_t++;
	}

	cks_stop = number;

	/* so we came to the end of ip header. what is next? */
	/* tcp, udp, icmp or manually attached payload? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(udp_bt))) {
		if (udp_get(button, user_data, pseudo_header_sum) == -1) {
			//printf("Error: Problem with UDP information\n");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tcp_bt))) {
		if (tcp_get(button, user_data, pseudo_header_sum) == -1) {
			//printf("Error: Problem with TCP information\n");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(icmp_bt))) {
		if (icmp_get(button, user_data) == -1) {
			//printf("Error: Problem with ICMP information\n");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(igmp_bt))) {
		if (igmp_get(button, user_data) == -1) {
			//printf("Error: Problem with IGMP information\n");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(usedef_bt))) {
			
		pay_text_e = lookup_widget("text2");
		GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(pay_text_e));
		pay_length = gtk_text_buffer_get_char_count(buffer);    
		GtkTextIter start,end;
		//gtk_text_buffer_get_start_iter(buffer,start);
		//gtk_text_buffer_get_end_iter(buffer,end);
		gtk_text_buffer_get_bounds(buffer,&start,&end);
		pay_text = gtk_text_buffer_get_text(buffer,&start,&end,FALSE);
		//g_free(start);
		//g_free(end);
		//pay_text = (char *) malloc(pay_length + 1);
		//pay_text = gtk_editable_get_chars(GTK_EDITABLE(pay_text_e), 0, -1);

		/* YYY 1514-number is not ok in case we use 802.1q!!! */
		pay_max = 9900 - number;

		if (get_network_payload(button, user_data, pay_length, pay_max, pay_text) == -1) {
			//printf("Error: Problem with IPv4 payload\n");
			g_free(pay_text);
			return -1;
		}
		else
			g_free(pay_text);
	}

	else {
		//printf("Error: IPv4 zoombie error!!!\n");
		error("Error: IPv4 zoombie error!!!");
		return -1;
	}
		
	
	/* so we are back again to cumpute the length and checksum. so this is for length */
	if (length_start > 0) {
		packet[length_start] = (char)((number - length_start + 2)/256);
		packet[length_start+1] = (char)((number - length_start + 2)%256);
	}

	/* and this for checksum */
	if (header_cks_start > 0) {
		ipcksum = ((-1) - get_checksum16(cks_start, cks_stop) % 0x10000);
		packet[header_cks_start] = (char)(ipcksum/256);
		packet[header_cks_start+1] =  (char)(ipcksum%256);
	}
	
	return 1;
}
	

int udp_get(GtkButton *button, gpointer user_data, guint32 pseudo_header_sum) 
{
	
	GtkWidget *srcport, *dstport, *length, *length_bt, *checksum, *checksum_bt;
	GtkWidget *payload_bt, *payload;

	gchar *srcport_t, *dstport_t, *length_t, *checksum_t, *payload_t;

	int length_start, checksum_start, cks_start, cks_stop, payload_length, odd=0;
	guint32 udpcksum;
	
	srcport = lookup_widget("entry56");
	dstport = lookup_widget("entry41");
	length = lookup_widget("entry42");
	length_bt = lookup_widget("checkbutton3");
	checksum = lookup_widget("entry43");
	checksum_bt = lookup_widget("checkbutton4");
	payload = lookup_widget("text3");
	payload_bt = lookup_widget("checkbutton5");
	
	srcport_t= (char *)gtk_entry_get_text(GTK_ENTRY(srcport));
	dstport_t= (char *)gtk_entry_get_text(GTK_ENTRY(dstport));
	length_t= (char *)gtk_entry_get_text(GTK_ENTRY(length));
	checksum_t= (char *)gtk_entry_get_text(GTK_ENTRY(checksum));

	l4_proto_used = 17;
	
	cks_start = number;
	/* we need this one for knowing where the udp payload starts
	 * we need this one when sending the packets out and modifing some values */
	udp_start = number;     
	
	/* source port */
	if ( (atoi(srcport_t) < 0) || (atoi(srcport_t) > 65535) ) {
		//printf("Error: Udp source port range\n");
		error("Error: Udp source port range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(srcport_t, strlen(srcport_t), "Error: Udp srcport field values") == -1)
				return -1;

	packet[number] = (char)(atol(srcport_t)/256);
	number++;       
	packet[number] = (char)(atol(srcport_t)%256);
	number++;       
	
	/* destination port */
	if ( (atoi(dstport_t) < 0) || (atoi(dstport_t) > 65535) ) {
		//printf("Error: Udp destination port range\n");
		error("Error: Udp destination port range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(dstport_t, strlen(dstport_t), "Error: Udp destination port field values") == -1)
				return -1;

	packet[number] = (char)(atol(dstport_t)/256);
	number++;       
	packet[number] = (char)(atol(dstport_t)%256);
	number++;       
	
	/* udp length */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(length_bt))) {
		length_start = number;
		number++;
		number++;
	}
	else {
		/* if length_start = 0, we leave it in the end */
		length_start = 0;
		if ( (atoi(length_t) < 0) || (atoi(length_t) > 65535) ) {
			//printf("Error: Udp length range\n");
			error("Error: Udp length range");
			return -1;
		}
	
		/* there can be rubbish in this field */
		if (check_digit(length_t, strlen(length_t), "Error: Udp length field values") == -1)
				return -1;

		packet[number] = (char)(atol(length_t)/256);
		number++;       
		packet[number] = (char)(atol(length_t)%256);
		number++;       
	}
	
	/* udp checksum */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(checksum_bt))) {
		checksum_start = number;
		packet[number] = (unsigned char)0;
		number++;
		packet[number] = (unsigned char)0;
		number++;
	}
	else {
		/* if checksum_start = 0, we leave it in the end */
		checksum_start = 0;
	
		if (char2x(checksum_t) == -1) {
			//printf("Error: udp checksum field\n");
			error("Error: udp checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		checksum_t++; checksum_t++; number++;
		if (char2x(checksum_t) == -1) {
			//printf("Error: udp checksum field\n");
			error("Error: udp checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		number++;
	}

		
	/* udp payload */
	/* so do we allow packet's longer than 1518 (1522) bytes or not ? Not.*/
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(payload_bt))) {
		
		GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(payload));
		payload_length = gtk_text_buffer_get_char_count(buffer);
		GtkTextIter start,end;
		gtk_text_buffer_get_bounds(buffer,&start,&end);
		//gtk_text_buffer_get_start_iter(buffer,&start);
		//gtk_text_buffer_get_end_iter(buffer,&end);
		payload_t = gtk_text_buffer_get_text(buffer,&start,&end,FALSE);
		//g_free(start);
		//g_free(end);
		//payload_t = (char *) malloc(payload_length + 1);
		//payload_t = gtk_editable_get_chars(GTK_EDITABLE(payload),0,-1);
		
		if (get_network_payload(button, user_data, payload_length, 
						9900, payload_t) == -1) {
			//printf("Error: Problem with udp payload\n");
			g_free(payload_t);
			return -1;
		}
		else
			g_free(payload_t);

		cks_stop = number;
	}
	else
		cks_stop = number;

	/* it will be possible that we add some other protocols on top of udp
	 * they will follow here... */

	
	/* we have to fill the corect udp length if auto was enabled
	 * we add 2 bytes for source port and 2 bytes for dest port 
	 * because length_start points at udp length field  */
	if (length_start > 0) {
		packet[length_start] = (char)((number - length_start + 4)/256);
		packet[length_start+1] = (char)((number - length_start + 4)%256);
	}

	/* and finally compute the udp checksum if auto was enabled */
	if (checksum_start > 0) {
		/* if the user manually inserts the length value what then??? */
		/* we don't care it that means, if you manually insert the length
		 * than the auto checksum button won't help you 
		 * it would be better if the value would be correct either */
		
		/* this if for udp length  */
		udpcksum = (guint32)(cks_stop - cks_start);
		/* pseudo header (ip part) + udplength + nr of cicles over guint16 */
		udpcksum = pseudo_header_sum + udpcksum;
		/* if the length is odd we have to add a pad byte */
		if( (cks_stop - cks_start)%2 != 0)
			       odd = 1;
		/* previos value + part from udp checksum */
		udpcksum = udpcksum + get_checksum32(cks_start, cks_stop+odd);
		while (udpcksum >> 16)
			udpcksum = (udpcksum & 0xFFFF)+ (udpcksum >> 16);
		/* the one's complement */
		udpcksum = (-1) - udpcksum;

		// -17, stands for udp protocol value
		if (ip_proto_used == 6)
			udpcksum = udpcksum - 17;

		/* let's write it */
		packet[checksum_start] = (char)(udpcksum/256);
		packet[checksum_start+1] =  (char)(udpcksum%256);
	}
	return 1;
}

	
int tcp_get(GtkButton *button, gpointer user_data, guint32 pseudo_header_sum) {
	
	GtkWidget *srcport, *dstport, *sequence_number, *ack_number, *header_length;
	GtkWidget *flag_cwr, *flag_ecn;
	GtkWidget *flag_urg, *flag_ack, *flag_psh, *flag_rst, *flag_syn, *flag_fin;
	GtkWidget *window_size, *checksum, *checksum_bt, *urgent_pointer, *options;
	GtkWidget *payload_bt, *payload;

	gchar *srcport_t, *dstport_t, *sequence_number_t, *ack_number_t, *header_length_t;
	gchar *window_size_t, *checksum_t, *urgent_pointer_t, *options_t, *payload_t;

	int checksum_start, cks_start, cks_stop, i, j, payload_length, odd=0;
	guint32 tcpcksum;
	guint32 seqnr, acknr;
	int flag_value = 0;

	srcport = lookup_widget("entry46");
	dstport = lookup_widget("entry47");
	sequence_number = lookup_widget("entry48");
	ack_number = lookup_widget("entry49");
	header_length = lookup_widget("entry50");
	flag_cwr = lookup_widget("checkbutton22");
	flag_ecn = lookup_widget("checkbutton23");
	flag_urg = lookup_widget("checkbutton7");
	flag_ack = lookup_widget("checkbutton8");
	flag_psh = lookup_widget("checkbutton9");
	flag_rst = lookup_widget("checkbutton10");
	flag_syn = lookup_widget("checkbutton11");
	flag_fin = lookup_widget("checkbutton12");
	window_size = lookup_widget("entry51");
	checksum = lookup_widget("entry52");
	checksum_bt = lookup_widget("checkbutton13");
	urgent_pointer = lookup_widget("entry53");
	options = lookup_widget("entry54");
	payload_bt = lookup_widget("checkbutton14");
	payload = lookup_widget("text4");
	
	srcport_t= (char *)gtk_entry_get_text(GTK_ENTRY(srcport));
	dstport_t= (char *)gtk_entry_get_text(GTK_ENTRY(dstport));
	sequence_number_t = (char *)gtk_entry_get_text(GTK_ENTRY(sequence_number));
	ack_number_t = (char *)gtk_entry_get_text(GTK_ENTRY(ack_number));
	header_length_t = (char *)gtk_entry_get_text(GTK_ENTRY(header_length));
	window_size_t = (char *)gtk_entry_get_text(GTK_ENTRY(window_size));
	checksum_t = (char *)gtk_entry_get_text(GTK_ENTRY(checksum));
	urgent_pointer_t = (char *)gtk_entry_get_text(GTK_ENTRY(urgent_pointer));
	options_t = (char *)gtk_entry_get_text(GTK_ENTRY(options));
	
	l4_proto_used = 6;

	cks_start = number;
	
	/* we need this one for knowing where the tcp part starts
	 * we need this one when sending the packets out and modifing some values */
	tcp_start = number;     
		
	/* source port */
	if ( (atoi(srcport_t) < 0) || (atoi(srcport_t) > 65535) ) {
		//printf("Error: tcp source port range\n");
		error("Error: tcp source port range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(srcport_t, strlen(srcport_t), "Error: tcp srcport field values") == -1)
				return -1;

	packet[number] = (char)(atol(srcport_t)/256);
	number++;
	packet[number] = (char)(atol(srcport_t)%256);
	number++;
	
	/* destination port */
	if ( (atoi(dstport_t) < 0) || (atoi(dstport_t) > 65535) ) {
		//printf("Error: tcp destination port range\n");
		error("Error: tcp destination port range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(dstport_t, strlen(dstport_t), "Error: tcp destination port field values") == -1)
				return -1;

	packet[number] = (char)(atol(dstport_t)/256);
	number++;
	packet[number] = (char)(atol(dstport_t)%256);
	number++;

	/* sequence number */
	if ( strtoull(sequence_number_t, (char **)NULL, 10) > 0xFFFFFFFF ) {
		//printf("Error: tcp sequence number range\n");
		error("Error: tcp sequence number range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(sequence_number_t, strlen(sequence_number_t), 
						"Error: tcp sequence number field values") == -1)
				return -1;

	seqnr = strtoul(sequence_number_t, (char **)NULL, 10);
	packet[number] = (char)(seqnr/16777216);
	number++;
	packet[number] = (char)(seqnr/65536);
	number++;
	packet[number] = (char)(seqnr/256);
	number++;
	packet[number] = (char)(seqnr%256);
	number++;

	/* acknowledgment number */
	if ( strtoull(ack_number_t, (char **)NULL, 10) > 0xFFFFFFFF) {
		//printf("Error: tcp ack number range\n");
		error("Error: tcp ack number range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(ack_number_t, strlen(ack_number_t), "Error: tcp ack number field values") == -1)
				return -1;

	acknr = strtoul(ack_number_t, (char **)NULL, 10);
	packet[number] = (char)(acknr/16777216);
	number++;
	packet[number] = (char)(acknr/65536);
	number++;
	packet[number] = (char)(acknr/256);
	number++;
	packet[number] = (char)(acknr%256);
	number++;

	/* header length */     
	if ( (atoi(header_length_t) < 0) || (atoi(header_length_t) > 60) ) {
		//printf("Error: tcp header_length range\n");
		error("Error: tcp header_length range");
		return -1;
	}

	/* since we insert value as int, when dividing it with 4 there must remain 0 */
	if ( atoi(header_length_t) % 4 !=  0) {
		//printf("Error: tcp header_length range\n");
		error("Error: Wrong tcp header length value          \n(length mod 4 must be 0)");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(header_length_t, strlen(header_length_t), 
						"Error: tcp header_length field values") == -1)
				return -1;

	packet[number] = (char)((atoi(header_length_t)*4));
	number++;       

	/* flags */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_cwr))) {
		flag_value = flag_value + 128;
	}       
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_ecn))) {
		flag_value = flag_value + 64;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_urg))) {
		flag_value = flag_value + 32;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_ack))) {
		flag_value = flag_value + 16;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_psh))) {
		flag_value = flag_value + 8;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_rst))) {
		flag_value = flag_value + 4;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_syn))) {
		flag_value = flag_value + 2;
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(flag_fin))) {
		flag_value = flag_value + 1;
	}
	packet[number] = (char)flag_value;
	number++;       
	
	/* window size */       
	if ( (atoi(window_size_t) < 0) || (atoi(window_size_t) > 65535) ) {
		//printf("Error: tcp window size range\n");
		error("Error: tcp window size range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(window_size_t, strlen(window_size_t), "Error: tcp window size field values") == -1)
				return -1;

	packet[number] = (char)(atol(window_size_t)/256);
	number++;       
	packet[number] = (char)(atol(window_size_t)%256);
	number++;       

	/* tcp checksum */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(checksum_bt))) {
		checksum_start = number;
		packet[number] = (unsigned char)0;
		number++;
		packet[number] = (unsigned char)0;
		number++;
	}
	else {
		/* if checksum_start = 0, we leave it in the end */
		checksum_start = 0;
	
		if (char2x(checksum_t) == -1) {
			//printf("Error: tcp checksum field\n");
			error("Error: tcp checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		checksum_t++; checksum_t++; number++;
		if (char2x(checksum_t) == -1) {
			//printf("Error: tcp checksum field\n");
			error("Error: tcp checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		number++;
	}
		
	/* urgent pointer */    
	if ( (atoi(urgent_pointer_t) < 0) || (atoi(urgent_pointer_t) > 65535) ) {
		//printf("Error: tcp urgent pointer range\n");
		error("Error: tcp urgent pointer range");
		return -1;
	}

	/* there can be rubbish in this field */
	if (check_digit(urgent_pointer_t, strlen(urgent_pointer_t), 
						"Error: tcp urgent pointer field values") == -1)
				return -1;

	packet[number] = (char)(atol(urgent_pointer_t)/256);
	number++;       
	packet[number] = (char)(atol(urgent_pointer_t)%256);
	number++;       

	/* tcp options */
	if ( (strlen(options_t)%8) != 0) {
		//printf("Error: Wrong length of tcp options field (length mod 8 must be 0)\n");
		error("Error: Wrong length of tcp options field      \n(length mod 8 must be 0)");
		return -1;
	}
	
	if ( strlen(options_t) > 80) {
		//printf("Error: tcp options field to long\n");
		error("Error: tcp options field to long");
		return -1;
	}
	
	j = strlen(options_t)/2;
	for (i=0; i<j; i++) {
		if (char2x(options_t) == -1) {
			//printf("Error: tcp options field\n");
			error("Error: tcp options field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(options_t);
		number++; options_t++; options_t++;
	}

	/* tcp payload */       
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(payload_bt))) {
		
		GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(payload));
		payload_length = gtk_text_buffer_get_char_count(buffer);
		GtkTextIter start,end;
		//gtk_text_buffer_get_start_iter(buffer,start);
		//gtk_text_buffer_get_end_iter(buffer,end);
		gtk_text_buffer_get_bounds(buffer,&start,&end);
		payload_t = gtk_text_buffer_get_text(buffer,&start,&end,FALSE);
		//g_free(start);
		//g_free(end);
		//payload_t = (char *) malloc(payload_length + 1);
		//payload_t = gtk_editable_get_chars(GTK_EDITABLE(payload),0,-1);
		
		/* YYY 1514-number is not ok in case we use 802.1q!!! */
		if (get_network_payload(button, user_data, payload_length, 
						9900-number, payload_t) == -1) {
			//printf("Error: Problem with tcp payload\n");
			g_free(payload_t);
			return -1;
		}
		else
			g_free(payload_t);

		cks_stop = number;
	}
	else
		cks_stop = number;

	/* it will be possible that we add some other protocols on top of tcp
	 * they will follow here... */
	

	/* and finally compute the tcp checksum if auto was enabled */
	if (checksum_start > 0) {
		
		/* this if for length  */
		tcpcksum = (guint32)(cks_stop - cks_start);
		/* pseudo header (ip part) + tcplength + nr of cicles over guint16 */
		tcpcksum = pseudo_header_sum + tcpcksum;
		/* if length is odd we have to add a pad byte */
		if( (cks_stop - cks_start)%2 != 0)
				odd = 1;
		/* previos value + part from tcp checksum */
		tcpcksum = tcpcksum + get_checksum32(cks_start, cks_stop+odd);
		while (tcpcksum >> 16)
			tcpcksum = (tcpcksum & 0xFFFF) + (tcpcksum >> 16);
		/* the one's complement */
		tcpcksum = (-1) - tcpcksum;

		/* what about if the lenght is odd ??? 
		 * we check this in get_checksum routine */

		// -6, stands for tcp protocol value
		if (ip_proto_used == 6)
			tcpcksum = tcpcksum - 6;
		
		/* let's write it */
		packet[checksum_start] = (char)(tcpcksum/256);
		packet[checksum_start+1] =  (char)(tcpcksum%256);
	}
	
	return 1;
}

int igmp_get(GtkButton *button, gpointer user_data) {
	
	GtkWidget *type, *menux;

	GtkWidget *maxresptime, *checksum, *cks_bt, *groupaddress, *resv, *nosf, *sourceaddresses;

	gchar *type_t;
	gchar *maxresptime_t, *checksum_t, *groupaddress_t;     
	gchar *resv_t, *nosf_t, *sourceaddresses_t;     
	
	int igmp_start, igmp_stop, checksum_start, payload_length;
	guint16 igmpcksum;
	gchar tmp[4];
	int i, j, menu_index;
	
	type = lookup_widget("entry166");
	type_t = (char *)gtk_entry_get_text(GTK_ENTRY(type));
	
	igmp_start = number;
	
	/* type */
	if (char2x(type_t) == -1) {
		//printf("Error: igmp type field\n");
		error("Error: igmp type field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(type_t);
	number++;

	maxresptime = lookup_widget("entry167");
	checksum = lookup_widget("entry168");
	cks_bt = lookup_widget("checkbutton41");

	maxresptime_t = (char *)gtk_entry_get_text(GTK_ENTRY(maxresptime));
	checksum_t = (char *)gtk_entry_get_text(GTK_ENTRY(checksum));
	/*gcc warning otherwise*/
	groupaddress = lookup_widget("entry169");

	/* igmp max response time */
	if (char2x(maxresptime_t) == -1) {
		//printf("Error: igmp max response time\n");
		error("Error: igmp max response time");
		return -1;
	}
	packet[number] = (unsigned char)char2x(maxresptime_t);
	number++;
			
	/* checksum */  
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cks_bt))) {
		checksum_start = number;
		packet[number] = (unsigned char)0;
		number++;
		packet[number] = (unsigned char)0;
		number++;
	}
	else {
		/* if checksum_start = 0, we leave it in the end */
		checksum_start = 0;

		if (char2x(checksum_t) == -1) {
			//printf("Error: igmp reply checksum field\n");
			error("Error: igmp checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		checksum_t++; checksum_t++; number++;
		if (char2x(checksum_t) == -1) {
			//printf("Error: igmp reply checksum field\n");
			error("Error: igmp checksum field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		number++;
	}
			
	menux = lookup_widget("optionmenu20");
	menu_index = gtk_combo_box_get_active (GTK_COMBO_BOX (menux));

	/* IGMP V3 query */
	if (menu_index == 1) {
		/* group address */
		groupaddress = lookup_widget("entry169");
		groupaddress_t = (char *)gtk_entry_get_text(GTK_ENTRY(groupaddress));
		if (check_ip_address(groupaddress_t) == -1) {
			//printf("Error: Wrong igmp address\n");
			error("Error: Wrong igmp group address");
			return -1;
		}
		
		for (i=0; i<4; i++) {
			for(j=0; j<4 && (*groupaddress_t != '\0'); j++) {
				if ( ((int)*groupaddress_t == '.') && (i<3) && (j>0) ) {
					groupaddress_t++;
					break;
				}
				tmp[j] = *groupaddress_t;
				groupaddress_t++;
			}
			tmp[j] = '\0';
			packet[number] = (unsigned char)(atoi(tmp));
			number++;               
		}
			
		resv = lookup_widget("entry171");
		nosf = lookup_widget("entry172");
		sourceaddresses = lookup_widget("entry173");

		resv_t = (char *)gtk_entry_get_text(GTK_ENTRY(resv));
		nosf_t = (char *)gtk_entry_get_text(GTK_ENTRY(nosf));
		sourceaddresses_t = (char *)gtk_entry_get_text(GTK_ENTRY(sourceaddresses));

		/* Resv, S, QRV, QQIC IGMP V3 values */
		if (char2x(resv_t) == -1) {
			//printf("Error: Resv, S, QRV, QQIC IGMP V3 values\n");
			error("Error: Resv, S, QRV, QQIC IGMP V3 values");
			return -1;
		}
		packet[number] = (unsigned char)char2x(resv_t);
		resv_t++; resv_t++; number++;
		if (char2x(resv_t) == -1) {
			//printf("Error: Resv, S, QRV, QQIC IGMP V3 values\n");
			error("Error: Resv, S, QRV, QQIC IGMP V3 values");
			return -1;
		}
		packet[number] = (unsigned char)char2x(resv_t);
		number++;
		
		/* number of sources */
		if (char2x(nosf_t) == -1) {
			//printf("Error: IGMP V3 number of sources\n");
			error("Error: IGMP V3 number of sources");
			return -1;
		}
		packet[number] = (unsigned char)char2x(nosf_t);
		nosf_t++; nosf_t++; number++;
		if (char2x(nosf_t) == -1) {
			//printf("Error: IGMP V3 number of sources\n");
			error("Error: IGMP V3 number of sources");
			return -1;
		}
		packet[number] = (unsigned char)char2x(nosf_t);
		number++;
		
		/* source addresses */
		payload_length = strlen(sourceaddresses_t);
		
		if (get_network_payload(button, user_data, payload_length, 
					9900, sourceaddresses_t) == -1) {
			//printf("problem with igmp reply payload\n");
			return -1;
		}
		
		igmp_stop = number;

		if (checksum_start > 0) {
			
			igmpcksum =  get_checksum16(igmp_start, igmp_stop); 
			/* the one's complement */
			igmpcksum = (-1) - igmpcksum;

			/* let's write it */
			packet[checksum_start] = (char)(igmpcksum/256);
			packet[checksum_start+1] =  (char)(igmpcksum%256);
		}
	}

	/* IGMP V3 report */
	else if (menu_index == 4) {
		resv = lookup_widget("entry176");
		nosf = lookup_widget("entry177");
		sourceaddresses = lookup_widget("entry178");

		resv_t = (char *)gtk_entry_get_text(GTK_ENTRY(resv));
		nosf_t = (char *)gtk_entry_get_text(GTK_ENTRY(nosf));
		sourceaddresses_t = (char *)gtk_entry_get_text(GTK_ENTRY(sourceaddresses));

		/* Resv values */
		if (char2x(resv_t) == -1) {
			//printf("Error: Resv, S, QRV, QQIC IGMP V3 values\n");
			error("Error: Reserved IGMP V3 report values");
			return -1;
		}
		packet[number] = (unsigned char)char2x(resv_t);
		resv_t++; resv_t++; number++;
		if (char2x(resv_t) == -1) {
			//printf("Error: Resv, S, QRV, QQIC IGMP V3 values\n");
			error("Error: Reserved IGMP V3 report values");
			return -1;
		}
		packet[number] = (unsigned char)char2x(resv_t);
		number++;
		
		/* number of group records */
		if (char2x(nosf_t) == -1) {
			//printf("Error: IGMP V3 number of sources\n");
			error("Error: IGMP V3 report number of group records");
			return -1;
		}
		packet[number] = (unsigned char)char2x(nosf_t);
		nosf_t++; nosf_t++; number++;
		if (char2x(nosf_t) == -1) {
			//printf("Error: IGMP V3 number of sources\n");
			error("Error: IGMP V3 report number of group records");
			return -1;
		}
		packet[number] = (unsigned char)char2x(nosf_t);
		number++;
		
		/* group records */
		payload_length = strlen(sourceaddresses_t);
		
		/* YYY 1514-number is not ok in case we use 802.1q!!! */
		if (get_network_payload(button, user_data, payload_length, 
					9900, sourceaddresses_t) == -1) {
			//printf("problem with igmp reply payload\n");
			return -1;
		}
		
		igmp_stop = number;

		if (checksum_start > 0) {
			
			igmpcksum =  get_checksum16(igmp_start, igmp_stop); 
			/* the one's complement */
			igmpcksum = (-1) - igmpcksum;

			/* let's write it */
			packet[checksum_start] = (char)(igmpcksum/256);
			packet[checksum_start+1] =  (char)(igmpcksum%256);
		}


	}
	/* for all the other types */
	else    {
		/* group address */
		groupaddress = lookup_widget("entry175");
		groupaddress_t = (char *)gtk_entry_get_text(GTK_ENTRY(groupaddress));
		if (check_ip_address(groupaddress_t) == -1) {
			//printf("Error: Wrong igmp address\n");
			error("Error: Wrong igmp group address");
			return -1;
		}
		
		for (i=0; i<4; i++) {
			for(j=0; j<4 && (*groupaddress_t != '\0'); j++) {
				if ( ((int)*groupaddress_t == '.') && (i<3) && (j>0) ) {
					groupaddress_t++;
					break;
				}
				tmp[j] = *groupaddress_t;
				groupaddress_t++;
			}
			tmp[j] = '\0';
			packet[number] = (unsigned char)(atoi(tmp));
			number++;               
		}

		igmp_stop = number;

		if (checksum_start > 0) {
			
			igmpcksum =  get_checksum16(igmp_start, igmp_stop); 
			/* the one's complement */
			igmpcksum = (-1) - igmpcksum;

			/* let's write it */
			packet[checksum_start] = (char)(igmpcksum/256);
			packet[checksum_start+1] =  (char)(igmpcksum%256);
		}
	}       
	
	return 1;
}
	
int icmp_get(GtkButton *button, gpointer user_data) {
	
	GtkWidget *type; 
	GtkWidget *code, *checksum, *cks_bt, *identifier, *seq_nr, *unused;
	GtkWidget *data_bt, *data, *datalen;

	gchar *type_t;
	gchar *code_t, *checksum_t, *identifier_t, *seq_nr_t, *data_t, *data_t_len, *unused_t;  
	
	int checksum_start, payload_length;
	guint32 icmpcksum;
	
	type = lookup_widget("entry57");
	type_t = (char *)gtk_entry_get_text(GTK_ENTRY(type));
	
	icmp_start = number;
	l4_proto_used = 1;
	
	/* type */
	if (char2x(type_t) == -1) {
		//printf("Error: icmp type field\n");
		error("Error: icmp type field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(type_t);
	number++;

	/* YYY hmmm, it would be better to be the type filed inserted as int
	 * not as hex, so we have to calculate it */
	switch (atoi(type_t)) {
		case 0: {
			//printf("ICMP echo reply\n");
			code = lookup_widget("entry62");
			checksum = lookup_widget("entry63");
			cks_bt = lookup_widget("checkbutton16");
			identifier = lookup_widget("entry64");
			seq_nr = lookup_widget("entry65");
			data_bt = lookup_widget("checkbutton17");
			data = lookup_widget("entry66");
			datalen = lookup_widget("entry207");

			code_t = (char *)gtk_entry_get_text(GTK_ENTRY(code));
			checksum_t = (char *)gtk_entry_get_text(GTK_ENTRY(checksum));
			identifier_t = (char *)gtk_entry_get_text(GTK_ENTRY(identifier));
			seq_nr_t = (char *)gtk_entry_get_text(GTK_ENTRY(seq_nr));
			data_t = (char *)gtk_entry_get_text(GTK_ENTRY(data));
			data_t_len = (char *)gtk_entry_get_text(GTK_ENTRY(datalen));
			
			/* code */
			if (char2x(code_t) == -1) {
				//printf("Error: icmp reply code field\n");
				error("Error: icmp reply code field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(code_t);
			number++;
			
			/* checksum */  
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cks_bt))) {
				checksum_start = number;
				packet[number] = (unsigned char)0;
				number++;
				packet[number] = (unsigned char)0;
				number++;
			}
			else {
			/* if checksum_start = 0, we leave it in the end */
				checksum_start = 0;
	
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp reply checksum field\n");
					error("Error: icmp reply checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				checksum_t++; checksum_t++; number++;
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp reply checksum field\n");
					error("Error: icmp reply checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				number++;
			}
			
			/* identifier */
			if (char2x(identifier_t) == -1) {
				//printf("Error: icmp reply identifier field\n");
				error("Error: icmp reply identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(identifier_t);
			identifier_t++; identifier_t++; number++;
			if (char2x(identifier_t) == -1) {
				//printf("Error: icmp reply identifier field\n");
				error("Error: icmp reply identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(identifier_t);
			number++;
			
			/* sequence number */
			if (char2x(seq_nr_t) == -1) {
				//printf("Error: icmp reply identifier field\n");
				error("Error: icmp reply identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(seq_nr_t);
			seq_nr_t++; seq_nr_t++; number++;
			if (char2x(seq_nr_t) == -1) {
				//printf("Error: icmp reply identifier field\n");
				error("Error: icmp reply identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(seq_nr_t);
			number++;
			
			/* data */
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(data_bt))) {
				if (strlen(data_t) != 2) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}       
				if (char2x(data_t) == -1) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}
				
				if ( (atol(data_t_len) < 0) || (atol(data_t_len) > 9500) ) {
					error("Error: ICMP data length");
					return -1;
				}

				/* there can be rubbish in this field */
				if (check_digit(data_t_len, strlen(data_t_len),
					"Error: icmp data") == -1)
					return -1;
				
				for (payload_length=0; payload_length<atol(data_t_len); payload_length++) {             
					packet[number] = (unsigned char)char2x(data_t);
					number++;                               

				}

				icmp_stop = number;
			}
			else
				icmp_stop = number;

			if (checksum_start > 0) {
				
				icmpcksum =  get_checksum16(icmp_start, icmp_stop); 
				/* the one's complement */
				icmpcksum = (-1) - icmpcksum;

				/* let's write it */
				packet[checksum_start] = (char)(icmpcksum/256);
				packet[checksum_start+1] =  (char)(icmpcksum%256);
			}
			break;
		}
		

		/* icmp echo request */
		case 8: {
			//printf("ICMP echo request\n");
			code = lookup_widget("entry74");
			checksum = lookup_widget("entry77");
			cks_bt = lookup_widget("checkbutton20");
			identifier = lookup_widget("entry75");
			seq_nr = lookup_widget("entry78");
			data_bt = lookup_widget("checkbutton19");
			data = lookup_widget("entry76");

			code_t = (char *)gtk_entry_get_text(GTK_ENTRY(code));
			checksum_t = (char *)gtk_entry_get_text(GTK_ENTRY(checksum));
			identifier_t = (char *)gtk_entry_get_text(GTK_ENTRY(identifier));
			seq_nr_t = (char *)gtk_entry_get_text(GTK_ENTRY(seq_nr));
			data_t = (char *)gtk_entry_get_text(GTK_ENTRY(data));
			datalen = lookup_widget("entry211");
			data_t_len = (char *)gtk_entry_get_text(GTK_ENTRY(datalen));

			
			/* code */
			if (char2x(code_t) == -1) {
				//printf("Error: icmp request code field\n");
				error("Error: icmp request code field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(code_t);
			number++;
			
			/* checksum */  
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cks_bt))) {
				checksum_start = number;
				packet[number] = (unsigned char)0;
				number++;
				packet[number] = (unsigned char)0;
				number++;
			}
			else {
			/* if checksum_start = 0, we leave it in the end */
				checksum_start = 0;
	
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp request checksum field\n");
					error("Error: icmp request checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				checksum_t++; checksum_t++; number++;
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp request checksum field\n");
					error("Error: icmp request checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				number++;
			}
			
			/* identifier */
			if (char2x(identifier_t) == -1) {
				//printf("Error: icmp request identifier field\n");
				error("Error: icmp request identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(identifier_t);
			identifier_t++; identifier_t++; number++;
			if (char2x(identifier_t) == -1) {
				//printf("Error: icmp request identifier field\n");
				error("Error: icmp request identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(identifier_t);
			number++;
			
			/* sequence number */
			if (char2x(seq_nr_t) == -1) {
				//printf("Error: icmp request identifier field\n");
				error("Error: icmp request identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(seq_nr_t);
			seq_nr_t++; seq_nr_t++; number++;
			if (char2x(seq_nr_t) == -1) {
				//printf("Error: icmp request identifier field\n");
				error("Error: icmp request identifier field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(seq_nr_t);
			number++;
			
			/* data */
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(data_bt))) {
				if (strlen(data_t) != 2) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}
				if (char2x(data_t) == -1) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}

				if ( (atol(data_t_len) < 0) || (atol(data_t_len) > 9500) ) {
					error("Error: ICMP data length");
					return -1;
				}

				/* there can be rubbish in this field */
				if (check_digit(data_t_len, strlen(data_t_len),
					"Error: icmp data") == -1)
					return -1;

				for (payload_length=0; payload_length<atol(data_t_len); payload_length++) {
					packet[number] = (unsigned char)char2x(data_t);
					number++;

				}


				icmp_stop = number;
			}
			else
				icmp_stop = number;

			if (checksum_start > 0) {
				
				icmpcksum =  get_checksum16(icmp_start, icmp_stop); 
				/* the one's complement */
				icmpcksum = (-1) - icmpcksum;

				/* let's write it */
				packet[checksum_start] = (char)(icmpcksum/256);
				packet[checksum_start+1] =  (char)(icmpcksum%256);
			}
			break;
		}
		
			
		/* icmp destination unreacheable */
		case 3: {
			//printf("ICMP destination unreacheable\n");
			code = lookup_widget("entry58");
			checksum = lookup_widget("entry59");
			cks_bt = lookup_widget("checkbutton15");
			unused = lookup_widget("entry60");
			data_bt = lookup_widget("checkbutton24");
			data = lookup_widget("entry61");

			code_t = (char *)gtk_entry_get_text(GTK_ENTRY(code));
			checksum_t = (char *)gtk_entry_get_text(GTK_ENTRY(checksum));
			unused_t = (char *)gtk_entry_get_text(GTK_ENTRY(unused));
			data_t = (char *)gtk_entry_get_text(GTK_ENTRY(data));
			datalen = lookup_widget("entry210");
			data_t_len = (char *)gtk_entry_get_text(GTK_ENTRY(datalen));
			
			/* code */
			if (char2x(code_t) == -1) {
				//printf("Error: icmp destination unreacheable code field\n");
				error("Error: icmp destination unreacheable code field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(code_t);
			number++;
			
			/* checksum */  
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cks_bt))) {
				checksum_start = number;
				packet[number] = (unsigned char)0;
				number++;
				packet[number] = (unsigned char)0;
				number++;
			}
			else {
			/* if checksum_start = 0, we leave it in the end */
				checksum_start = 0;
	
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp destination unreacheable checksum field\n");
					error("Error: icmp destination unreacheable checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				checksum_t++; checksum_t++; number++;
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp destination unreacheable checksum field\n");
					error("Error: icmp destination unreacheable checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				number++;
			}
			
			/* unused field */
			if (char2x(unused_t) == -1) {
				//printf("Error: icmp destination unreacheable unused field\n");
				error("Error: icmp destination unreacheable unused field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(unused_t);
			unused_t++; unused_t++; number++;
			if (char2x(unused_t) == -1) {
				//printf("Error: icmp destination unreacheable unused field\n");
				error("Error: icmp destination unreacheable unused field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(unused_t);
			unused_t++; unused_t++; number++;
			if (char2x(unused_t) == -1) {
				//printf("Error: icmp destination unreacheable unused field\n");
				error("Error: icmp destination unreacheable unused field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(unused_t);
			unused_t++; unused_t++; number++;
			if (char2x(unused_t) == -1) {
				//printf("Error: icmp destination unreacheable unused field\n");
				error("Error: icmp destination unreacheable unused field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(unused_t);
			number++;
			
			/* data */
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(data_bt))) {
				if (strlen(data_t) != 2) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}
				if (char2x(data_t) == -1) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}

				if ( (atol(data_t_len) < 0) || (atol(data_t_len) > 9500) ) {
					error("Error: ICMP data length");
					return -1;
				}

				/* there can be rubbish in this field */
				if (check_digit(data_t_len, strlen(data_t_len),
					"Error: icmp data") == -1)
					return -1;

				for (payload_length=0; payload_length<atol(data_t_len); payload_length++) {
					packet[number] = (unsigned char)char2x(data_t);
					number++;

				}


				icmp_stop = number;
			}
			else
				icmp_stop = number;

			if (checksum_start > 0) {
				
				icmpcksum =  get_checksum16(icmp_start, icmp_stop); 
				/* the one's complement */
				icmpcksum = (-1) - icmpcksum;

				/* let's write it */
				packet[checksum_start] = (char)(icmpcksum/256);
				packet[checksum_start+1] =  (char)(icmpcksum%256);
			}
			break;
		}
			
		default: {
			//printf("Other type of icmp message\n");
			code = lookup_widget("entry157");
			checksum = lookup_widget("entry158");
			cks_bt = lookup_widget("checkbutton38");
			data = lookup_widget("entry159");

			code_t = (char *)gtk_entry_get_text(GTK_ENTRY(code));
			checksum_t = (char *)gtk_entry_get_text(GTK_ENTRY(checksum));
			data_t = (char *)gtk_entry_get_text(GTK_ENTRY(data));
			datalen = lookup_widget("entry209");
			data_t_len = (char *)gtk_entry_get_text(GTK_ENTRY(datalen));
			
			/* code */
			if (char2x(code_t) == -1) {
				//printf("Error: icmp other code field\n");
				error("Error: icmp other code field");
				return -1;
			}
			packet[number] = (unsigned char)char2x(code_t);
			number++;
			
			/* checksum */  
			if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cks_bt))) {
				checksum_start = number;
				packet[number] = (unsigned char)0;
				number++;
				packet[number] = (unsigned char)0;
				number++;
			}
			/* if checksum_start = 0, we leave it in the end */
			else {
				checksum_start = 0;
	
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp destination unreacheable checksum field\n");
					error("Error: icmp destination unreacheable checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				checksum_t++; checksum_t++; number++;
				if (char2x(checksum_t) == -1) {
					//printf("Error: icmp destination unreacheable checksum field\n");
					error("Error: icmp destination unreacheable checksum field");
					return -1;
				}
				packet[number] = (unsigned char)char2x(checksum_t);
				number++;
			}
			
			/* data */
				if (strlen(data_t) != 2) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}
				if (char2x(data_t) == -1) {
					error("Error: Wrong icmp data pattern");
					return -1;
				}

				if ( (atol(data_t_len) < 0) || (atol(data_t_len) > 9500) ) {
					error("Error: ICMP data length");
					return -1;
				}

				/* there can be rubbish in this field */
				if (check_digit(data_t_len, strlen(data_t_len),
					"Error: icmp data") == -1)
					return -1;

				for (payload_length=0; payload_length<atol(data_t_len); payload_length++) {
					packet[number] = (unsigned char)char2x(data_t);
					number++;

				}


			icmp_stop = number;

			if (checksum_start > 0) {
				
				icmpcksum =  get_checksum16(icmp_start, icmp_stop); 
				/* the one's complement */
				icmpcksum = (-1) - icmpcksum;

				/* let's write it */
				packet[checksum_start] = (char)(icmpcksum/256);
				packet[checksum_start+1] =  (char)(icmpcksum%256);
			}
		}
	}
	return 1;
}
		
/* we have to parse the arp protocol information */
int arp_get(GtkButton *button, gpointer user_data)
{
	GtkWidget *hwtype, *prottype, *hwsize, *protsize;
	GtkWidget *rbt10, *rbt11, *rbt17, *en81;
	GtkWidget *sendermac, *senderip, *targetmac, *targetip;
	gchar *hwtype_t, *prottype_t, *hwsize_t, *protsize_t, *en81_t;
	gchar *sendermac_t, *senderip_t, *targetmac_t, *targetip_t;
	int i, j;
	gchar tmp[4];

	hwtype = lookup_widget("A_hwtype"); 
	prottype = lookup_widget("A_prottype");     
	hwsize = lookup_widget("A_hwsize"); 
	protsize = lookup_widget("A_protsize");     
	
	rbt10 = lookup_widget("radiobutton10");     
	rbt11 = lookup_widget("radiobutton11");     
	rbt17 = lookup_widget("radiobutton17");     
	en81 = lookup_widget("entry81");    

	sendermac = lookup_widget("A_sendermac");   
	senderip = lookup_widget("A_senderip");     
	targetmac = lookup_widget("A_targetmac");   
	targetip = lookup_widget("A_targetip");     

	hwtype_t = (char *)gtk_entry_get_text(GTK_ENTRY(hwtype));
	prottype_t = (char *)gtk_entry_get_text(GTK_ENTRY(prottype));
	hwsize_t = (char *)gtk_entry_get_text(GTK_ENTRY(hwsize));
	protsize_t = (char *)gtk_entry_get_text(GTK_ENTRY(protsize));
	sendermac_t = (char *)gtk_entry_get_text(GTK_ENTRY(sendermac));
	senderip_t = (char *)gtk_entry_get_text(GTK_ENTRY(senderip));
	targetmac_t = (char *)gtk_entry_get_text(GTK_ENTRY(targetmac));
	targetip_t = (char *)gtk_entry_get_text(GTK_ENTRY(targetip));
	en81_t = (char *)gtk_entry_get_text(GTK_ENTRY(en81));
	
	ip_proto_used = 806;
	l4_proto_used = 0;

	/* now we have all the widget and we start parsing the info: we start with the hardware type */
	if (char2x(hwtype_t) == -1) {
		//printf("Error: hwtype field\n");
		error("Error: hwtype field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(hwtype_t);
	hwtype_t++; hwtype_t++; number++;
	if (char2x(hwtype_t) == -1) {
		//printf("Error: hwtype field\n");
		error("Error: hwtype field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(hwtype_t);
	number++;

	/* prottype */
	if (char2x(prottype_t) == -1) {
		//printf("Error: prottype field\n");
		error("Error: prottype field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(prottype_t);
	prottype_t++; prottype_t++; number++;
	if (char2x(prottype_t) == -1) {
		//printf("Error: prottype field\n");
		error("Error: prottype field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(prottype_t);
	number++;

	/* hwsize */
	if (char2x(hwsize_t) == -1) {
		//printf("Error: hwsize field\n");
		error("Error: hwsize field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(hwsize_t);
	number++;

	/* protsize */
	if (char2x(protsize_t) == -1) {
		//printf("Error: protsize field\n");
		error("Error: protsize field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(protsize_t);
	number++;

	/* which opcode */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rbt10))) {
		packet[number] = 0x00;
		number++;
		packet[number] = 0x01;
		number++;
		
	}
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rbt11))) { 
		packet[number] = 0x00;
		number++;
		packet[number] = 0x02;
		number++;
	}
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rbt17))) { 
		if (char2x(en81_t) == -1) {
			//printf("Error: entry arp opcode\n");
			error("Error: entry arp opcode");
			return -1;
		}
		packet[number] = (unsigned char)char2x(en81_t);
		en81_t++; en81_t++; number++;
		if (char2x(en81_t) == -1) {
			//printf("Error: entry arp opcode\n");
			error("Error: entry arp opcode");
			return -1;
		}
		packet[number] = (unsigned char)char2x(en81_t);
		number++;
	}
	else {
		//printf("Error: Something is wrong with the arp opcode\n");
		error("Error: Something is wrong with the arp opcode");
		return -1;
	}

	
	/* and now the ip&mac values: check if addresses are ok */
	eth_start = number;
	
	if (check_mac_address(sendermac_t) == -1) {
		//printf("Error: Wrong mac entry in arp sender field, can't copy it\n");
		error("Error: Wrong mac entry in arp sender field, can't copy it");
		return -1;
	}
	if (check_mac_address(targetmac_t) == -1) {
		//printf("Error: Wrong mac entry in arp target field, can't copy it\n");
		error("Error: Wrong mac entry in arp target field, can't copy it");
		return -1;
	}
	if (check_ip_address(senderip_t) == -1) {
		//printf("Error: Wrong ip entry in arp sender field, can't copy it\n");
		error("Error: Wrong ip entry in arp sender field, can't copy it");
		return -1;
	}
	if (check_ip_address(targetip_t) == -1) {
		//printf("Error: Wrong ip entry in arp target field, can't copy it\n");
		error("Error: Wrong ip entry in arp target field, can't copy it");
		return -1;
	}
	
	/* if all addresses are ok, we copy them into packet: first sender mac */
	for(i=0; i<6; i++) {
		packet[number] = (unsigned char)char2x(sendermac_t);
		sendermac_t = sendermac_t + 3; number++;
	}
	
	/* sender ip */
	for (i=0; i<4; i++) {
		for(j=0; j<4 && (*senderip_t != '\0'); j++) {
			if ( ((int)*senderip_t == '.') && (i<3) && (j>0) ) {
				senderip_t++;
				break;
			}
			tmp[j] = *senderip_t;
			senderip_t++;
		}
		tmp[j] = '\0';
		packet[number] = (unsigned char)(atoi(tmp));
		number++;               
	}
	
	/* target mac */
	for(i=0; i<6; i++) {
		packet[number] = (unsigned char)char2x(targetmac_t);
		targetmac_t = targetmac_t + 3; number++;
	}
	
	/* target ip */
	for (i=0; i<4; i++) {
		for(j=0; j<4 && (*targetip_t != '\0'); j++) {
			if ( ((int)*targetip_t == '.') && (i<3) && (j>0) ) {
				targetip_t++;
				break;
			}
			tmp[j] = *targetip_t;
			targetip_t++;
		}
		tmp[j] = '\0';
		packet[number] = (unsigned char)(atoi(tmp));
		number++;               
	}
	
	return 1;
}


/* user choosed to manually attach payload, so here we are */
int get_network_payload(GtkButton *button, gpointer user_data, int length, int max, gchar *entry)
{
	int i, stevec = 0;
	gchar *ptr;

	/* firs we check if total length without spaces is an even number */
	ptr = entry;
	for (i=0; i < length; i++, ptr++) {
		if (isspace(*ptr) != 0) { /* prazne znake ne upostevam */
			continue;
		}       
		stevec++;
	}

	if ( stevec % 2 != 0) {
		//printf("Error: Payload lengtht must be an even number\n");
		error("Error: Payload lengtht must be an even number");
		return -1;
	}
	
	stevec = 1;

	for (i=0; i < length ; ) {
		if (isspace(*entry) != 0) { /* prazne znake ne upostevam */
			entry++;
			i++;
			continue;
		}       
		if (stevec > max) {
			//printf("Error: Network layer payload lengtht to long\n");
			error("Error: Network layer payload lengtht to long");
			return -1;
		}
		if (char2x(entry) == -1) {
			//printf("Error: network layer payload\n");
			error("Error: network layer payload");
			return -1;
		}
		packet[number] = (unsigned char)char2x(entry);
		number++; i++; i++; entry++; entry++; stevec++;;        
	}
	return 1;       
}


int link_level_get(GtkButton *button, gpointer user_data)
{
	GtkWidget *ver2_tbt, *_801q_cbt, *_8023_tbt;
	GtkWidget *ethtype_e;
	gchar *ethtype_t;

	ver2_tbt = lookup_widget("bt_ver2");
	_8023_tbt = lookup_widget("bt_8023");
	_801q_cbt = lookup_widget("bt_8021q");

	/* always we need first the dest and source mac address */
	if (get_mac_from_string(button) == -1) {
		//printf("Error: mac address field\n");
		error("Error: mac address field");
		return -1;
	}
	number = 12;

	/* is 802.1q active - do we need to add 4 or 8 bytes? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(_801q_cbt))) {
		if (get_8021q(button) == -1) {
			//printf("Error: 802.1q field\n");
			return -1;
		}
	}
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(_8023_tbt))) { /* uporabimo ethernet vezije 802.3 */
		if (get_8023(button) == -1) {
			//printf("Error: 802.3 field");
			return -1;
		}
	}

	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ver2_tbt))){ /* pol pa verzijo 2 */ 
		autolength = 0;
		ethtype_e = lookup_widget("L_ethtype");
		ethtype_t = (char *)gtk_entry_get_text(GTK_ENTRY(ethtype_e));
		if (char2x(ethtype_t) == -1) {
			//printf("Error: ethernet type field\n");
			error("Error: ethernet type field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(ethtype_t);
		ethtype_t++; ethtype_t++; number++;
		if (char2x(ethtype_t) == -1) {
			//printf("Error: ethernet type field\n");
			error("Error: ethernet type field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(ethtype_t);
		number++;
	}
	else {/* kva a je mogoce token ring??? */
		//printf("Error: in ethernet field\n");
		error("Error: in ethernet field");
		return -1;
	}


	return 1;
}


/* if we are in the 802.3 ethernet version */
int get_8023(GtkButton *button)
{
	GtkWidget *ethlength_e/*, *L8023llc_tbt*/, *L8023llcsnap_tbt, *Ldsap_e, *Lssap_e;
	GtkWidget *Lctrl_e, *Loui_e, *Lpid_e, *autolength_bt;
	gchar *Ldsap_t, *Lssap_t, *Lctrl_t, *Loui_t, *Lpid_t;
	gchar *ethlength_t;

	/* do we need to calculate the length field or will be suplied manually */
	autolength_bt = lookup_widget("checkbutton2");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(autolength_bt))) {
		autolength = number;
		packet[number] = 0x0; number++; packet[number] = 0x0; number++;
	}
	else {
		autolength = 0;
		ethlength_e = lookup_widget("entry5");
		ethlength_t = (char *)gtk_entry_get_text(GTK_ENTRY(ethlength_e));
		if (char2x(ethlength_t) == -1) {
			//printf("Error: 802.3 length field\n");
			error("Error: 802.3 length field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(ethlength_t);
		ethlength_t++; ethlength_t++; number++;
		if (char2x(ethlength_t) == -1) {
			//printf("Error: 802.3 length field\n");
			error("Error: 802.3 length field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(ethlength_t);
		number++;
	}
	
	//L8023llc_tbt = lookup_widget("L_8023_llc_tbt");
	L8023llcsnap_tbt = lookup_widget("L_8023_llcsnap_tbt");
	Ldsap_e = lookup_widget("L_dsap");
	Lssap_e= lookup_widget("L_ssap");
	Lctrl_e= lookup_widget("L_ctrl");

	Ldsap_t = (char *)gtk_entry_get_text(GTK_ENTRY(Ldsap_e));
	if (char2x(Ldsap_t) == -1) {
		//printf("Error: 802.3 ldsap field\n");
		error("Error: 802.3 ldsap field");
		       return -1;
	}
	packet[number] = (unsigned char)char2x(Ldsap_t);
	number++;

	Lssap_t = (char *)gtk_entry_get_text(GTK_ENTRY(Lssap_e));
	if (char2x(Lssap_t) == -1) {
		//printf("Error: 802.3 lssap field\n");
		error("Error: 802.3 lssap field");
		       return -1;
	}
	packet[number] = (unsigned char)char2x(Lssap_t);
	number++;

	Lctrl_t = (char *)gtk_entry_get_text(GTK_ENTRY(Lctrl_e));
	if (char2x(Lctrl_t) == -1) {
		//printf("Error: 802.3 Ctrl field\n");
		error("Error: 802.3 Ctrl field");
		       return -1;
	}
	packet[number] = (unsigned char)char2x(Lctrl_t);
	number++;

	/* do we need snap encapsulation */ 
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(L8023llcsnap_tbt))) {
		Loui_e = lookup_widget("L_oui");
		Lpid_e = lookup_widget("L_pid");
		
		Loui_t = (char *)gtk_entry_get_text(GTK_ENTRY(Loui_e));
		if (char2x(Loui_t) == -1) {
			//printf("Error: 802.3 oui field\n");
			error("Error: 802.3 oui field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(Loui_t);
		number++; Loui_t++, Loui_t++;

		if (char2x(Loui_t) == -1) {
			//printf("Error: 802.3 oui field\n");
			error("Error: 802.3 oui field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(Loui_t);
		number++; Loui_t++, Loui_t++;

		if (char2x(Loui_t) == -1) {
			//printf("Error: 802.3 oui field\n");
			error("Error: 802.3 oui field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(Loui_t);
		number++; 

		Lpid_t = (char *)gtk_entry_get_text(GTK_ENTRY(Lpid_e));
		if (char2x(Lpid_t) == -1) {
			//printf("Error: 802.3 snap pid field\n");
			error("Error: 802.3 snap pid field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(Lpid_t);
		number++; Lpid_t++; Lpid_t++;

		if (char2x(Lpid_t) == -1) {
			//printf("Error: 802.3 snap pid field\n");
			error("Error: 802.3 snap pid field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(Lpid_t);
		number++; 

		return 1;
	}
	else 
		return 1;
}


/* function parses 802.1q field */
int get_8021q(GtkButton *button)
{
	GtkWidget *vlan_e, *priority_m, *cfi1_rbt, *vlanid_e, *QinQ_bt, *QinQ, *QinQpvid;
	gchar *vlan_t, *vlanid_t, *QinQ_t; 
	gint menu_index, cfi =0;
        guint32 vlan_value;

	QinQ_bt = lookup_widget("checkbutton40");

	/* what about QinQ field? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(QinQ_bt))) {
		QinQpvid = lookup_widget("optionmenu21");
		QinQ = lookup_widget("entry165");
		
		menu_index = gtk_combo_box_get_active (GTK_COMBO_BOX (QinQpvid));

		switch (menu_index) {
			case 0: {
				packet[number] = (unsigned char)char2x("81");
				number++;
				packet[number] = (unsigned char)char2x("00");
				number++;
				break;
			}
			case 1: {
				packet[number] = (unsigned char)char2x("91");
				number++;
				packet[number] = (unsigned char)char2x("00");
				number++;
				break;
			}
			case 2: {
				packet[number] = (unsigned char)char2x("92");
				number++;
				packet[number] = (unsigned char)char2x("00");
				number++;
				break;
			}
			case 3: {
				packet[number] = (unsigned char)char2x("88");
				number++;
				packet[number] = (unsigned char)char2x("a8");
				number++;
				break;
			}
		}

		QinQ_t = (char *)gtk_entry_get_text(GTK_ENTRY(QinQ));
		if (char2x(QinQ_t) == -1) {
			//printf("Error: VLAN QinQ type field\n");
			error("Error: VLAN QinQ field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(QinQ_t);
		QinQ_t++; QinQ_t++; number++;
		if (char2x(QinQ_t) == -1) {
			//printf("Error: VLAN QinQ type field\n");
			error("Error: VLAN QinQ field");
			return -1;
		}
		packet[number] = (unsigned char)char2x(QinQ_t);
		number++;

	}

	vlan_e = lookup_widget("L_tag_id");
	priority_m = lookup_widget("L_optmenu2_bt");
	cfi1_rbt = lookup_widget("checkbutton39");
	vlanid_e = lookup_widget("L_vlan_id");
	vlan_t = (char *)gtk_entry_get_text(GTK_ENTRY(vlan_e));
	vlanid_t = (char *)gtk_entry_get_text(GTK_ENTRY(vlanid_e));
		
	/* first we chech the vlan protocol id */
	if (char2x(vlan_t) == -1) {
		//printf("Error: 802.1q type field\n");
		error("Error: 802.1q type field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(vlan_t);
	vlan_t++; vlan_t++; number++;
	if (char2x(vlan_t) == -1) {
		//printf("Error: 802.1q type field\n");
		error("Error: 802.1q type field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(vlan_t);
	number++;       
	
	/* next we need the priority */
	menu_index = gtk_combo_box_get_active (GTK_COMBO_BOX (priority_m));

	/* what about CFI bit? */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cfi1_rbt)))
		cfi = 1;
	else 
		cfi = 0;

        if ( (atoi(vlanid_t) > 4095) || (atoi(vlanid_t) < 0) ) {
	        //printf("Error: vlan id value: (0 - 4095)\n");
	        error("Error: Vlan Id value: (0 - 4095)");
	        return -1;
	}

        /* there can be rubbish in this field */
	if (check_digit(vlanid_t, strlen(vlanid_t),
					"Error: Vlan Id field values ") == -1)
	return -1;

        vlan_value = (menu_index<<13   & 0xE000) |
		     (cfi<<12 & 0x1000) |
		     (atoi(vlanid_t) & 0x0FFF) ;
        vlan_value = htons(vlan_value);
        memcpy(&packet[number], &vlan_value, 2);
        number++;
        number++;

	return 1;
}


/* calculate the checksum 
 * we pass the start and stop number in packet[] 
 * where we won't to calculate the checksum */
guint32 get_checksum32(int cks_start, int cks_stop) 

{
	guint32 value;
	long sum = 0;

	for (; cks_start<cks_stop; ) {
		/* we take 16 bit word's -> 2 bytes */
		value = (packet[cks_start]<<8) + packet[cks_start+1];
		sum = sum + value;
		/* for every cicle, this means where the sum exceeds 
		 * the 16 bit unsigned max value (65536), you have to add 1
		 * to the rest */
		//sum = (sum % 0x10000) + (sum / 0x10000);
		cks_start +=2; 
	}
	/* we don't do extract the sum from 0xFFFF (or -1), so you have to do
	 * this later */
	//return (sum % 0x10000);
	return sum;
}
	

guint16 get_checksum16(int cks_start, int cks_stop) 

{
	guint16 value;
	long sum = 0;

	for (; cks_start<cks_stop; ) {
		/* we take 16 bit word's -> 2 bytes */
		value = (packet[cks_start]<<8) + packet[cks_start+1];
		sum = sum + value;
		/* for every cicle, this means where the sum exceeds 
		 * the 16 bit unsigned max value (65536), you have to add 1
		 * to the rest */
		sum = (sum % 0x10000) + (sum / 0x10000);
		cks_start +=2; 
	}
	/* we don't do extract the sum from 0xFFFF (or -1), so you have to do
	 * this later */
	return (sum % 0x10000);
	//return sum;
}
/*check ip address */
int check_ip_address(gchar *ptr)
{
	int i, j;
	gchar tmp[4];
	
	for (i=0; i<4; i++) {
		for(j=0; j<4 && (*ptr != '\0'); j++) {
			if ( ((int)*ptr == '.') && (i<3) && (j>0) ) {
				ptr++;
				break;
			}
			if ( (*ptr <48) || (*ptr>57) )
				return -1;
			else {
				tmp[j] = *ptr;
				ptr++;
			}
		}
		tmp[j] = '\0';
		if ( (atoi(tmp) < 0) || (atoi(tmp) > 255) || (strlen(tmp)==0) || (strlen(tmp)>3) )
			return -1;
	}
	return 1;
}

/*check ipv6 address, if insert is==1, it means we insert the values, otherwise only check */
int check_ipv6_address(gchar *ptr, int insert)
{
	int stevec, dolzina, i=0, j=0, enojno=0, dvojno=-1;
	gchar paket[8][4];
	gchar *ptrstart;

	ptrstart = ptr;

	// first set everything to 0
	for(j=0; j<8; j++)
		memset(paket[j], 48, (gchar)4);

	//length of provided ipv6 adress including :    
	dolzina = strlen(ptr);  

	//lets start from the left side until the end or until :: is found      
	for(stevec=0, j=0, i=0; stevec < dolzina ; stevec++, ptr++) {

		//only hex digit and : is allowed
		if ( (isxdigit(*ptr) == 0) && (*ptr != ':') )
			return -1;      

		//if we get to : we need some movement :)
		if ( (*ptr == ':') ) {
			enojno++;
			//move the string to rigth depending how many characters are thre
			if(i<=3) {
				switch (i) {
					case 1: {
						paket[j][3]=paket[j][0];
						paket[j][0]='0';
						break;
					}
					case 2: {
						paket[j][2]=paket[j][0];
						paket[j][3]=paket[j][1];
						paket[j][0]='0';
						paket[j][1]='0';
						break;
					}
					case 3: {
						paket[j][3]=paket[j][2];
						paket[j][2]=paket[j][1];
						paket[j][1]=paket[j][0];
						paket[j][0]='0';
						break;
					}
					default:
						break;

				}
			}
			i=0;
			j++;
		}
		else {
			//hm, already 4 digits and no : -> error
			if (i>3)
				return -1;
			paket[j][i] = *ptr;
			i++;
		}
		//ok, double :: met, we break here and will go now from right to left
		if ( (*ptr == ':') && (*(ptr+1) == ':') ) {
			//already seen one :: , eroor
			if (dvojno >=0)
				return -1;
			else {
				// remember the offet
				dvojno = stevec;
				break;
			}
		}
			
	}

	//now from the right hand side up to the ::
	//initialize values
	j=7;
	i=0;
	ptr=ptrstart+dolzina-1;

	//ok, and now from right to left
	for(stevec=0; ((dolzina-stevec) > 0) && dolzina<39 && enojno<7 ; stevec++, ptr--) {

		//only hex digit and : is allowed
		if ( (isxdigit(*ptr) == 0) && (*ptr != ':') )
			return -1;      

		if ( (*ptr == ':') ) {
			i=0;
			j--;
		}
		else {
			if (i>3)
				return -1;
			paket[j][3-i] = *ptr;
			i++;
		}
		//ok, we met another ::
		if ( (*ptr == ':') && (*(ptr-1) == ':') ) {
			//if it is the same one offset then ok, otherwise error
			if (dvojno != dolzina-stevec-2)
				return -1;
			else
				break;
		}
			
	} 

	//length shorter then max but no :: visible
	if ( ((dvojno==-1) && (enojno!=7)) || (enojno>7) )
		return -1;


	if (insert == 1) {
		for(j=0; j<8; j++) {
			for (i=0; i<4; i++, i++) {
				//printf("prvi in drugi:%c %c\n", paket[j][i]);
				packet[number] = (unsigned char)char2x(&paket[j][i]);
				number++;
			}
				
		}
	}

	return 1;
}


/* check mac address */
int check_mac_address(gchar *ptr)
{
	int i;

	if ( strlen(ptr) > 17)
		return -1;
	/* all mac addresses must be in full xx:xx:xx:xx:xx:xx format. f:... in not ok 0f:... works */
	for(i=0; i<6; i++) {
		if (char2x(ptr) == -1)
			return -1;
		ptr = ptr+2;
		if ( (*ptr != ':') && (i<5) )
			return -1;
		else
			ptr++;
	}
	return 1;
}


/* function parses mac address */
int get_mac_from_string(GtkButton *button)
{
	GtkWidget *dstmac_e, *srcmac_e;
	gchar *dstmac_t, *srcmac_t;
	int dst_length, src_length, i;

	dstmac_e = lookup_widget("L_dst_mac");
	srcmac_e = lookup_widget("L_src_mac");
	dstmac_t = (char *)gtk_entry_get_text(GTK_ENTRY(dstmac_e));
	srcmac_t = (char *)gtk_entry_get_text(GTK_ENTRY(srcmac_e));
	dst_length = strlen(dstmac_t);
	src_length = strlen(srcmac_t);

	/* mac naslov mora viti v formatu xx:xx:xx:xx:xx:xx to pomeni 17 znakov skupaj! */
	if ((src_length != 17) || (dst_length != 17))
		return -1;
	
	/* first we store destination address into packet[] */
	for(i=0; i<6; i++) {
		if (char2x(dstmac_t) == -1)
			return -1;
		packet[i] = (unsigned char)char2x(dstmac_t);
		dstmac_t = dstmac_t + 2;
		if ((i<5) && (*dstmac_t != ':'))
			return -1;
		else if (i == 5)
			;
		else
			dstmac_t++;
	}
		 
	/* source address into packet[] */
	for(i=6; i<12; i++) {
		if (char2x(srcmac_t) == -1)
			return -1;
		packet[i] = (unsigned char)char2x(srcmac_t);
		srcmac_t = srcmac_t + 2;
		if ((i<5) && (*srcmac_t != ':'))
			return -1;
		else if (i == 5)
			;
		else
			srcmac_t++;
	}
		 
	return 1;
}


/* function takes pointer to char and converts two chars to hex and returns signed int. If you want to use te return value as char, you need to cast back to (unsigned char) */
signed int char2x(char *p) 
{
    unsigned char x=0;

    if ( (*p >= '0') && (*p <= '9')) {
	x = ((*p) - 48) * 16;
    }
    else if ((*p >= 'A') && (*p <= 'F')) {
	x = ((*p) - 55) * 16;
    }
    else if ((*p >= 'a') && (*p <= 'f')) {
	x = ((*p) - 87) * 16;
    }
    else {
	return -1;
    }
    p++;
    if ( (*p >= '0') && (*p <= '9')) {
	x = x + ((*p) - 48);
    }
    else if ((*p >= 'A') && (*p <= 'F')) {
	x = x + ((*p) - 55);
    }
    else if ((*p >= 'a') && (*p <= 'f')) {
	x = x + ((*p) - 87);
    }
    else {
	return -1;
    }
    return (int)x;
}


char c4(int value)
{
	switch(value) {
		case 0: return '0';
		case 1: return '1';
		case 2: return '2';
		case 3: return '3';
		case 4: return '4';
		case 5: return '5';
		case 6: return '6';
		case 7: return '7';
		case 8: return '8';
		case 9: return '9';
		case 10: return 'A';
		case 11: return 'B';
		case 12: return 'C';
		case 13: return 'D';
		case 14: return 'E';
		case 15: return 'F';
		default: return '0';
	}       
}


char *c8(char *s, unsigned char x) {
	*s++ = c4(x>>4);
	*s++ = c4(x & 0x0F);
	*s = '\0';
	return s;
}


int insert_frequency(int codec, int frequency, int length, GtkWidget *payload_entry, gint amp_index) 
{
	double  fs = 8000;      /* vzorcna frekvenca */
	double amp;      /* amplituda */
	double  ph = 0;         /* zacetna faza */
	double delta_ph;
	double sample;       /* 16 bit variable */
	gchar entry_t[2*length+1];
	gchar *ptr;

	ptr = entry_t;
	delta_ph = 2* M_PI *frequency/fs;

	/* the amp values are: low - 5000, mid - 15000, max - 30000 */
	amp = 5000 + amp_index * 7500 + amp_index * amp_index * 2500;

	while(length) {
		sample = amp*sin(ph);
		ph = ph + delta_ph;
		while (ph > (2*M_PI)) {
		    ph = ph - (2*M_PI);
		}
	
		if (codec == 1) 
			c8(ptr, linear2alaw((gint16)sample));
		else
			c8(ptr, linear2ulaw((gint16)sample));
		ptr++;
		ptr++;

		length--;
	}

	*ptr = '\0';

	gtk_entry_set_text(GTK_ENTRY(payload_entry), entry_t);

	return 1;
}


/* Following three routines are from Sun Microsystems, Inc. */
unsigned char linear2alaw(int pcm_val)  /* 2's complement (16-bit range) */
{
	static short seg_aend[8] = {0x1F, 0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF};
	int             mask; 
	int             seg;  
	unsigned char   aval;

	pcm_val = pcm_val >> 3;

	if (pcm_val >= 0) {
		mask = 0xD5;            /* sign (7th) bit = 1 */
	} else {
		mask = 0x55;            /* sign bit = 0 */
		pcm_val = -pcm_val - 1;
	}

	/* Convert the scaled magnitude to segment number. */
	seg = search(pcm_val, seg_aend, 8);

	/* Combine the sign, segment, and quantization bits. */

	if (seg >= 8)           /* out of range, return maximum value. */
		return (unsigned char) (0x7F ^ mask);
	else {
		aval = (unsigned char) seg << 4;
		if (seg < 2)
			aval |= (pcm_val >> 1) & 0xf;
		else
			aval |= (pcm_val >> seg) & 0xf;
		return (aval ^ mask);
	}
}


unsigned char linear2ulaw(short pcm_val)  /* 2's complement (16-bit range) */
{
	static short seg_uend[8] = {0x3F, 0x7F, 0xFF, 0x1FF, 0x3FF, 0x7FF, 0xFFF, 0x1FFF};
	short           mask;
	short           seg;
	unsigned char   uval;

	/* Get the sign and the magnitude of the value. */
	pcm_val = pcm_val >> 2;
	if (pcm_val < 0) {
		pcm_val = -pcm_val;
		mask = 0x7F;
	} else {
		mask = 0xFF;
	}
	if ( pcm_val > 8159 ) pcm_val = 8159;           /* clip the magnitude */
	pcm_val += (0x84 >> 2);

	/* Convert the scaled magnitude to segment number. */
	seg = search(pcm_val, seg_uend, 8);

	/*
	 * Combine the sign, segment, quantization bits;
	 * and complement the code word.
	 */
	if (seg >= 8)           /* out of range, return maximum value. */
		return (unsigned char) (0x7F ^ mask);
	else {
		uval = (unsigned char) (seg << 4) | ((pcm_val >> (seg + 1)) & 0xF);
		return (uval ^ mask);
	}

}


short search(int val, short *table, int size)
{
	int i;

	for (i = 0; i < size; i++) {
		if (val <= *table++)
			return (i);
	}
	return (size);
}


int check_digit(char *field, int length, char *text)
{
	int i;
	
	/* we check if the field contains only numbers and is not empty */
	if (length == 0) {
		//printf("%s\n", text);
		error(text);
		return -1;
	}

	for(i=0; i < length; i++, field++) {
		if (isdigit(*field) == 0) {
			//printf("%s\n", text);
			error(text);
			return -1;
		}       
	}
	return 1;
}       


int check_hex(char *field, int length, char *text)
{
	int i;

	for(i=0; i < length; i++, field++) {
		if (isxdigit(*field) == 0) {
			//printf("%s\n", text);
			error(text);
			return -1;
		}       
	}
	return 1;
}


/* what format do we allow for packet files */
/* YYY add to ignore the comments  */
int check_if_file_is_packet(FILE *file_p)
{
	int c, i=0;     
	gboolean first = 1;

	while ( (c = fgetc( file_p )) != EOF ) {
		if (first ==1) {
			if (isspace(c) != 0) 
				continue;
			if (c == 35) {
				while ( getc(file_p) != 10);
				continue;
			}
		}
		if (isxdigit(c) == 0) {
			//printf("Error: File does not contain a valid packet!\n");
			error("Error: File does not contain a valid packet");
			return -1;
		}

		if (first == 1)
			first = 0;
		else
			first = 1;
		i++;
	}
	
	/* 1514 or 1518, how to enable the vlan checking */
	if ( (i%2 != 0) || (i > 3536) ) {
		//printf("Error: File length is not ok\n");
		error("Error: File length is not ok");
		return -1;
	}

	return i;
}


void statusbar_text(GtkButton *button, char *text) {

	GtkWidget *statusbar;
	gint context_id;
	char buff[101];

	statusbar = lookup_widget("statusbar1");
	context_id = gtk_statusbar_get_context_id(GTK_STATUSBAR(statusbar), "Statusbar example");

	snprintf(buff, strlen(text)+1, "%s", text );
	gtk_statusbar_push(GTK_STATUSBAR(statusbar), GPOINTER_TO_INT(context_id), buff);

}

void gen_crc32_table()
{
	unsigned long crc, poly;
	int i, j;

	poly = 0xEDB88320L;
	for (i = 0; i < 256; i++) {
		crc = i;
		for (j = 8; j > 0; j--) {
			if (crc & 1)
				crc = (crc >> 1) ^ poly;
			else
				crc >>= 1;
		}
		crc32_table[i] = crc;
	}
}


unsigned long get_crc32(unsigned char *p, int len)
{
	register unsigned long crc;
	int i;
	if (!crc32_table_init) {
		gen_crc32_table();
		crc32_table_init = 1;
	}
	
	crc = 0xFFFFFFFF;
	for (i=0; i<len; i++) {
		crc = (crc>>8) ^ crc32_table[ (crc ^ *p++) & 0xFF ];
	}
	crc = crc^0xFFFFFFFF;
	/* big endian to little endian */
	crc = ((crc >> 24) & 0x000000FF) ^
	      ((crc >>  8) & 0x0000FF00) ^
	      ((crc <<  8) & 0x00FF0000) ^
	      ((crc << 24) & 0xFF000000);
	return crc;
}


int icmpv6_get(GtkButton *button, gpointer user_data, guint32 pseudo_header_sum) {

	GtkWidget *type, *code, *checksum, *cks_bt;
	GtkWidget *msgbody, *data_bt, *datapat, *datalen;

	gchar *type_t, *code_t, *checksum_t;
	gchar *msgbody_t, *data_t_pat, *data_t_len;

	int checksum_start, odd, payload_length, i, j;
	guint32 icmpcksum;

	type = lookup_widget("entry215");
	type_t = (char *)gtk_entry_get_text(GTK_ENTRY(type));

	//icmp_start = number;
	icmpv6_start = number;
	
	/* next header for icmpv6 is 0x3a or 58 */
	l4_proto_used = 58;

	/* type */
	if (char2x(type_t) == -1) {
		error("Error: icmpv6 type field");
		return -1;
	}
	packet[number] = (unsigned char)char2x(type_t);
	number++;

	code = lookup_widget("entry216");
	checksum = lookup_widget("entry217");
	cks_bt = lookup_widget("checkbutton48");
	data_bt = lookup_widget("checkbutton47");
	datapat = lookup_widget("entry212");
	datalen = lookup_widget("entry213");
	msgbody = lookup_widget("entry214");

	code_t = (char *)gtk_entry_get_text(GTK_ENTRY(code));
	checksum_t = (char *)gtk_entry_get_text(GTK_ENTRY(checksum));
	data_t_pat = (char *)gtk_entry_get_text(GTK_ENTRY(datapat));
	data_t_len = (char *)gtk_entry_get_text(GTK_ENTRY(datalen));
	msgbody_t = (char *)gtk_entry_get_text(GTK_ENTRY(msgbody));

	/* code */
	if (char2x(code_t) == -1) {
		  error("Error: icmpv6 reply code field");
		  return -1;
	}
	packet[number] = (unsigned char)char2x(code_t);
	number++;

	/* checksum */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(cks_bt))) {
		checksum_start = number;
		packet[number] = (unsigned char)0;
		number++;
		packet[number] = (unsigned char)0;
		number++;
	}
	else {
	/* if checksum_start = 0, we leave it in the end */
		checksum_start = 0;

		if (char2x(checksum_t) == -1) {
			 //printf("Error: icmp reply checksum field\n");
			 error("Error: icmpv6 reply checksum field");
			 return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		checksum_t++; checksum_t++; number++;
		if (char2x(checksum_t) == -1) {
		       //printf("Error: icmp reply checksum field\n");
		       error("Error: icmpv6 reply checksum field");
		       return -1;
		}
		packet[number] = (unsigned char)char2x(checksum_t);
		number++;
	 }

	/* optional message body */
	if ( (strlen(msgbody_t) != 0) && (strlen(msgbody_t) %2 != 0)) {
		error("Error: ICMPv6 message body must be an even number");
		return -1;
	}

	j = strlen(msgbody_t)/2;
	for (i=0; i<j; i++) {
		if (char2x(msgbody_t) == -1) {
			error("Error: icmpv6 message body");
			return -1;
		}
		packet[number] = (unsigned char)char2x(msgbody_t);
		number++; msgbody_t++; msgbody_t++;
	}

	/* data */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(data_bt))) {
		if (strlen(data_t_pat) != 2) {
			error("Error: Wrong icmpv6 data pattern");
			return -1;
		}
		if (char2x(data_t_pat) == -1) {
			error("Error: Wrong icmpv6 data pattern");
			return -1;
		}

		if ( (atol(data_t_len) < 0) || (atol(data_t_len) > 9500) ) {
			error("Error: icmpv6 data length");
			return -1;
		}

		/* there can be rubbish in this field */
		if (check_digit(data_t_len, strlen(data_t_len),
			"Error: icmpv6 data") == -1)
			return -1;

	       for (payload_length=0; payload_length<atol(data_t_len); payload_length++) {
			packet[number] = (unsigned char)char2x(data_t_pat);
			number++;

	       }

	       //icmp_stop = number;
	       icmpv6_stop = number;

	 }
	 else {
	       //icmp_stop = number;
	       icmpv6_stop = number;
	}

	 if (checksum_start > 0) {

		icmpcksum = (guint32)(icmpv6_stop - icmpv6_start);
		/* pseudo header (ip part) + length + nr of cicles over guint16 */
		icmpcksum = pseudo_header_sum + icmpcksum;
		/* if the length is odd we have to add a pad byte */

		if( (icmpv6_stop - icmpv6_start)%2 != 0)
			       odd = 1;
		/* previos value + part from checksum */
		icmpcksum = icmpcksum + get_checksum32(icmpv6_start, icmpv6_stop+odd);
		while (icmpcksum >> 16)
			icmpcksum = (icmpcksum & 0xFFFF)+ (icmpcksum >> 16);
		/* the one's complement */
		icmpcksum = (-1) - icmpcksum;

		// -58 stands for 3a what is protocol number for icmpv6
		if (ip_proto_used == 6)
			icmpcksum = icmpcksum - 58;

		/* let's write it */
		packet[checksum_start] = (char)(icmpcksum/256);
		packet[checksum_start+1] =  (char)(icmpcksum%256);


	 }

	return 1;
}

