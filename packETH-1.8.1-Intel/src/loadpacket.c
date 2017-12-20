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

#include <gtk/gtk.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "loadpacket.h"
#include <ctype.h>
#include "support.h"
#include "function.h"
#include "callbacks.h"
//#include "libnet/libnet-headers.h"
//#include "headers.h"

static GtkWidget *w1, *w2, *w3, *w4, *w5, *w6, *w7, *w8;
char field[31000];
char temp[20];
char temp6[40];
char *ptrf;
char *ptrt;
int next_prot;
long i;
int remain;
protocol_type protokol;

/* this one loads the parameters from file into notebook2 (Gen-b page) */
int load_gen_b_data(GtkButton *button, FILE *file_p) {
				
	long int buff4[5];
        char buff[10];
        char buffc[11][200];
	int c, j, k;

	w3 = lookup_widget(GTK_WIDGET (button), "optionmenu9");
	w4 = lookup_widget(GTK_WIDGET (button), "entry109");
	w5 = lookup_widget(GTK_WIDGET (button), "entry110");
	w6 = lookup_widget(GTK_WIDGET(button), "checkbutton35");
	/* we read the file ohh python, where are you... */
	k = 0;
	j = 0;
	/* rules for config files:
	 * - comments start with #
	 * - there can be spaces and newlines
	 * - only digits and - are acceptable characters
	 * - ...
	 */
	/* we have to limit the lines we read paramters from */
	while ( (c = fgetc( file_p )) != EOF ) {
		/* all the comment lines, starting with # , no limit for comment lines*/
		if ( (j==0) && (c == 35)) {
			/* ok, read till the end of line */
			while ( getc(file_p) != 10);
			continue;
		}

		/* let's limit the size */
		if ( (j > 9) || (k > 2) )
			return -1;

		/* ok, it is not a comment line so the info: only digits and minus sign are acceptable */
		if ( (isdigit(c) != 0) || (c == 45) ) { 
			buff[j] = c;
			j++;
			buff[j] = '\0';
		}
		/* no digit is it a newline? */
		else if (c==10) {
			if (j==0)
				continue;
			if (strlen(buff) == 0)
				*buff = 0;
			buff4[k] = strtol(buff, (char **)NULL, 10);
			j = 0;
			strncpy(&buffc[k][j], buff, 9);
			k++;
		}
		/* not, ok this is an error */
		else {
			return -1;
		}
	}

	if (buff4[0] == 1)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w2), 1);
	else if (buff4[0] == 0)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w1), 1);
	else {
		return -1;
	}

	/* adjusting parameters...
	if ( (buff4[1] >= 0) && (buff4[1] <= 4) )
		gtk_option_menu_set_history (GTK_OPTION_MENU (w3), buff4[1]);
	else {
		return -1;
	} */
	
	if (buff4[1] == - 3) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w6), 1);
		gtk_entry_set_text(GTK_ENTRY(w4), "");
		gtk_widget_set_sensitive (w4, FALSE);
	}
	else if ( (buff4[1] > 0) && (buff4[1] <= 9999999) ) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w6), 0);
		gtk_widget_set_sensitive (w4, TRUE);
		gtk_entry_set_text(GTK_ENTRY(w4), &buffc[1][0]);
	}
	else {
		return -1;
	}

	if (buff4[2] == 0) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w7), 1);
		gtk_entry_set_text(GTK_ENTRY(w5), "");
		gtk_widget_set_sensitive (w5, FALSE);
	}
	else if ( (buff4[2] >= 1) && (buff4[2] <= 999999999)  ) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w7), 0);
		gtk_widget_set_sensitive (w5, TRUE);
		gtk_entry_set_text(GTK_ENTRY(w5), &buffc[2][0]);
	}
	else {
		return -1;
	}
	
	return 1;
}



/* this one loads the parameters from file into notebook2 (Gen-s page) */
int load_gen_s_data(GtkButton *button, FILE *file_p) {

	long int buff4[5];
        char buff[100];
        char buffc[11][200];
	int c, j, k;
	char *ptr = NULL, *ptr2 = NULL;
        long int cc;


	k = 0;
	j = 0;
	/* rules for config files:
	 * - comments start with #
	 * - there can be spaces and newlines
	 * - only digits and - are acceptable characters
	 * - ...
	 */
	while ( (c = fgetc( file_p )) != EOF ) {
		/* all the comment lines, starting with # */
		if ( (j==0) && (c == 35)) {
			while ( getc(file_p) != 10);
			continue;
		}
		/* all blank lines */
		if ( (j==0) && (c == 10))
			continue;
		/* read the whole lines */
		if ((isascii(c) != 0) && (j<200) && (c!=10) && (k<11)) {
			buffc[k][j] = c;
			j++;
			buffc[k][j] = '\0';
		}
		/* , or \n mean end of string */
		else if (c==10) {
			j=0;
			k++;
		}
		else {
			return -1;
		     }
	}

	w1 = lookup_widget(GTK_WIDGET (button), "radiobutton36");
	w2 = lookup_widget(GTK_WIDGET (button), "radiobutton37");
	w4 = lookup_widget(GTK_WIDGET (button), "entry151");
	w5 = lookup_widget(GTK_WIDGET (button), "entry152");
	w6 = lookup_widget(GTK_WIDGET(button), "checkbutton36");

	/* first line should have three parameters */
	/* first is absolute or relative delay, allowed values 0 and 1 */
	if (strncmp(&buffc[0][0], "1", 1) == 0)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w1), 1);
	else if (strncmp(&buffc[0][0], "0", 1) == 0)
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w2), 1);
	else {
		return -1;
	}

	/* second is number of packets: -3 means infinite, or 1 till 9999999) */
	if (strncmp(&buffc[0][2], "-3", 2) == 0) {
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w6), 1);
		gtk_entry_set_text(GTK_ENTRY(w4), "");
		gtk_widget_set_sensitive (w4, FALSE);
		ptr = &buffc[0][4];
	}
	else {
		if ( (ptr = strchr(&buffc[0][2], 44)) == NULL) {
			return -1;
	 	}
		*ptr = '\0';
		buff4[0] = strtol(&buffc[0][2], (char **)NULL, 10);

		if ( (buff4[0] >= 0) && (buff4[0] <= 9999999) ) {
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w6), 0);
			gtk_widget_set_sensitive (w4, TRUE);
			gtk_entry_set_text(GTK_ENTRY(w4), &buffc[0][2]);
		}
		else {
			return -1;
		}
	}

	/* last parameter is delay between sequences */
	buff4[0] = strtol(ptr+1, (char **)NULL, 10);

	if ( (buff4[0] >= 0) && (buff4[0] <= 999999999) ) {
		gtk_entry_set_text(GTK_ENTRY(w5), ptr+1);
	}
	else {
		return -1;
	}

	/* we have to clean everything */
	for (j = 0; j < 10; j++) {
		snprintf(buff, 10, "entry%d", 111+j);
		w2 = lookup_widget(GTK_WIDGET (button), buff);
		gtk_entry_set_text(GTK_ENTRY(w2), "");
		snprintf(buff, 100, "entry%d", 121+j);
		w3 = lookup_widget(GTK_WIDGET (button), buff);
		gtk_entry_set_text(GTK_ENTRY(w3), "");
		snprintf(buff, 100, "entry%d", 131+j);
		w3 = lookup_widget(GTK_WIDGET (button), buff);
		gtk_entry_set_text(GTK_ENTRY(w3), "");
		snprintf(buff, 100, "entry%d", 141+j);
		w3 = lookup_widget(GTK_WIDGET (button), buff);
		gtk_entry_set_text(GTK_ENTRY(w3), "");
		snprintf(buff, 100, "checkbutton%d", 25+j);
		w2 = lookup_widget(GTK_WIDGET(button), buff);
		gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w2), 0);
	}

	/* and now all the rest */
	for (j = 1; j < k; j++) {
		/* first is packet name */
		if ( (ptr2 = strchr(&buffc[j][0], 44)) == NULL)
			continue;
		*ptr2 = '\0';
		if ( (strlen(&buffc[j][0]) > 0 ) && (strlen(&buffc[j][0]) < 70) ) {
			snprintf(buff, 10, "entry%d", 110+j);
			w2 = lookup_widget(GTK_WIDGET (button), buff);
			gtk_entry_set_text(GTK_ENTRY(w2), &buffc[j][0]);
		}
		else {
			return -1;
		}
		/* number of packets */
		ptr = ptr2; ptr++;
		if ( (ptr2 = strchr(ptr, 44)) == NULL) {
			return -1;
		}
		*ptr2 = '\0';
		cc = strtol(ptr, (char **)NULL, 10);
		if ( (cc < 0) || (cc > 9999999) ) {
			return -1;
		}
		snprintf(buff, 100, "entry%d", 120+j);
		w3 = lookup_widget(GTK_WIDGET (button), buff);
		gtk_entry_set_text(GTK_ENTRY(w3), ptr);

		/* delay between packets */
		ptr = ptr2; ptr++;
		if ( (ptr2 = strchr(ptr, 44)) == NULL) {
			return -1;
		}
		*ptr2 = '\0';
		cc = strtol(ptr, (char **)NULL, 10);
		if ( (cc < 0) || (cc > 999999999) ) {
			return -1;
		}
		snprintf(buff, 100, "entry%d", 130+j);
		w3 = lookup_widget(GTK_WIDGET (button), buff);
		gtk_entry_set_text(GTK_ENTRY(w3), ptr);

		/* delay to next */
		ptr = ptr2; ptr++;
		if ( (ptr2 = strchr(ptr, 44)) == NULL) {
			return -1;
		}
		*ptr2 = '\0';
		cc = strtol(ptr, (char **)NULL, 10);
		if ( (cc < 0) || (cc > 999999999) ) {
			return -1;
		}
		snprintf(buff, 100, "entry%d", 140+j);
		w3 = lookup_widget(GTK_WIDGET (button), buff);
		gtk_entry_set_text(GTK_ENTRY(w3), ptr);

		/* enable or disable */
		ptr = ptr2; ptr++;
		snprintf(buff, 100, "checkbutton%d", 24+j);
		w2 = lookup_widget(GTK_WIDGET(button), buff);
		if (*ptr == '1')
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w2), 0);
		else if (*ptr == '0')
			gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(w2), 1);
		else {
		      return -1;
		}

	}

	return 1;

}

/* opens the pcap file. 
 * if we call this function from the builder window only one - first, packet will be read 
 * from the Genp window, packets will be loaded untill EOF is reached */
int load_data(GtkButton *button, FILE *file_p, int whocalled, int howmanypackets) {
	
	struct pcap_hdr fh;
	struct pcaprec_hdr ph;
	struct clist_hdr clh;
	int j, ji, freads;
	guint32 secu = 0, secb = 0;
	guint32 usecu = 0, usecb = 0;
	double timediff = 0;
	double timebeg= 0;
	char pkt_temp[31000];
	GtkWidget *clis;

	/* first we read the pcap file header */
	freads = fread(pkt_temp, sizeof(fh), 1, file_p);
	/* if EOF, exit */
	if (freads == 0)
		return 1;

	memcpy(&fh, pkt_temp, 24);

	/* if magic number in NOK, exit */
	if (fh.magic != PCAP_MAGIC) 
		return -1;

	/* hm, I  forgot a little bit, but I assume 1 means builder here */
	if (whocalled == 1) {
		
		/* next the  pcap packet header */
		freads = fread(pkt_temp, sizeof(ph), 1, file_p);
		
		/* if EOF, exit */
		if (freads == 0)
			return 1;
		memcpy(&ph, pkt_temp, 16);

		/* and the packet itself, but only up to the capture length */
		freads = fread(pkt_temp+sizeof(ph), ph.incl_len, 1, file_p);

		/* if EOF, exit */
		if (freads == 0)
			return 1;

		/* convert the packet information from int to hex */
		for(ji=0; ji<(sizeof(ph)+ph.incl_len); ji++)
			c8(&field[2*ji], *(pkt_temp+ji)); 
		field[2*ji+2] = '\0';
		
		load_packet_disector(button, field, 1, &clh, ph.incl_len);			

		return 1; 
	}

	else { 
	
		clis = lookup_widget(GTK_WIDGET (button), "clist2");
		gtk_clist_clear(GTK_CLIST(clis));
	
		for (j=0; j<howmanypackets; j++) {
	
			/* next the  pcap packet header */
			freads = fread(pkt_temp, sizeof(ph), 1, file_p);

			/* if EOF, exit */
			if (freads == 0)
				return 1;

			/* copy the 16 bytes into ph structure */
			memcpy(&ph, pkt_temp, 16);

			if ((sizeof(ph)+ph.incl_len)>9200) {
				error("Packets longer than 9200 bytes in pcap file");
				continue;
			}

			/* and the packet itself, but only up to the capture length */
			freads = fread(pkt_temp+sizeof(ph), ph.incl_len, 1, file_p);

			/* if EOF, exit */
			if (freads == 0)
				return 1;

			/* convert the packet information from int to hex */
			for(ji=0; ji<(sizeof(ph)+ph.incl_len); ji++)
				c8(&field[2*ji], *(pkt_temp+ji)); 
			field[2*ji+2] = '\0';
		
			/* we have to dissect the packet to get information for the list */
			load_packet_disector(button, field, 2, &clh, ph.incl_len);			

			/* calculate the time information */
			if (j==0) { 
				timediff = 0;
				timebeg = 0;
				secb = ph.ts_sec;
				usecb = ph.ts_usec;
			}
			else { 
				timediff = ((double)((double)ph.ts_sec - (double)secu)*1000000 + 
								(double)((double)ph.ts_usec - (double)usecu)) / 1000000;
				timebeg = ((double)((double)ph.ts_sec - (double)secb)*1000000 + 
								(double)((double)ph.ts_usec - (double)usecb)) / 1000000;
			}

			secu = ph.ts_sec;
			usecu = ph.ts_usec;

			/* insert a new row into clist */
			load_gen_p_data(button, clis, field, &ph, j+1, &clh, timediff, timebeg);
		}
		if (j == howmanypackets) 
			error("Only first 1000 packets loaded!\nTo change this modify #define on top of callbacks.c");
	}

	return 1;

}
	

/* this one loads the parameters from file into notebook2 (Genp page) */
int load_gen_p_data(GtkButton *button, GtkWidget *clis, char *fieldek, struct pcaprec_hdr *ph2, 
					int pkt_nr, struct clist_hdr *clptr, double timediff, double timebeg) {

	gchar *datap[8];
	gchar fieldp[7][41];
	gchar field_p[1][31000];

	datap[0]=&fieldp[0][0];
	datap[1]=&fieldp[1][0];
	datap[2]=&fieldp[2][0];
	datap[3]=&fieldp[3][0];
	datap[4]=&fieldp[4][0];
	datap[5]=&fieldp[5][0];
	datap[6]=&fieldp[6][0];
	datap[7]=&field_p[0][0];

	//printf("TUKAJ1:%s\n", fieldek);
	g_snprintf(fieldp[0], 20, "%d", pkt_nr);
	g_snprintf(fieldp[1], 20, "%f", timebeg);
	g_snprintf(fieldp[2], 20, "%f", timediff);

	if ( (*ph2).incl_len == (*ph2).orig_len )
		g_snprintf(fieldp[3], 20, "%d", (*ph2).incl_len);
	else
		g_snprintf(fieldp[3], 20, "%d !", (*ph2).incl_len);

	g_snprintf(fieldp[4], 40, "%s", clptr->src);
	g_snprintf(fieldp[5], 40, "%s", clptr->dst);

	switch (protokol) {
		case ETH_II: {
			g_snprintf(fieldp[6], 20, "Ethernet II");
			break;
		}
		case ETH_802_3: {
			g_snprintf(fieldp[6], 20, "Ethernet 802.3");
			break;
		}
		case ARP: {
			g_snprintf(fieldp[6], 20, "ARP");
			break;
		}
		case IPv4: {
			g_snprintf(fieldp[6], 20, "IPv4");
			break;
		}
		case IPv6: {
			g_snprintf(fieldp[6], 20, "IPv6");
			break;
		}
		case TCP: {
			g_snprintf(fieldp[6], 20, "TCP");
			break;
		}
		case UDP: {
			g_snprintf(fieldp[6], 20, "UDP");
			break;
		}
		case IGMP: {
			g_snprintf(fieldp[6], 20, "IGMP");
			break;
		}
		case ICMP: {
			g_snprintf(fieldp[6], 20, "ICMP");
			break;
		}
		case ICMPv6: {
			g_snprintf(fieldp[6], 20, "ICMPv6");
			break;
		}
	}

	g_snprintf(field_p[0], 2*(32+(*ph2).incl_len), "%s", fieldek);
		
	gtk_clist_append(GTK_CLIST(clis), datap);
	
	return 1;

}

/* this routine was changed. it loads the packet into notebook2 (Builder page) or it checks the file containing the packets
 * for loading into Genp window
 * if who called = 1 - we load the contents into builder field
 * if who called = 2 - we load the contenst into Genp window but we need the information for filling in the clist 
 */
int load_packet_disector(GtkButton *button, char *fieldek, int whocalled, struct clist_hdr *clptr, int dolpaketa) {

	int c;

	ptrf = fieldek;
	ptrt = temp;

	//printf("\n:\n%s\n", fieldek);
	//convert8field(ptrt, ptrf);    insint(button, "entry179", ptrt, 8); ptrt = temp; ptrf = ptrf-8;
	//convert8field(ptrt, ptrf+8);  insint(button, "entry180", ptrt, 8); ptrt = temp; ptrf = ptrf-8;
	//convert8field(ptrt, ptrf+16); insint(button, "entry181", ptrt, 8); ptrt = temp; ptrf = ptrf-8;
	//convert8field(ptrt, ptrf+24); insint(button, "entry182", ptrt, 8); ptrt = temp; ptrf = ptrf-8;
	remain = dolpaketa;
	ptrf = ptrf + 32;

	/* what is the shortest length we still allow?
	 * we don't care if the packet is shorter than actually allowed to go on ethernet
	 * maybe the user just wanted to save packet even if it is to short, so why not load it?
	 * what we do demand is, that every layer must be completed 
	 * ok, here at least 14 bytes: 6 dest mac, 6 source mac and 2 for type or length*/
	if (remain < 14) {
		error("Can't load packet: Ethernet header is not long enough!");
		return -1;
	}

	/* first there is destination mac */
	w1 = lookup_widget(GTK_WIDGET(button), "L_dst_mac");
	for (i=1; i<=18; i++, ptrt++) {
		if (i%3 == 0) 
			*ptrt = ':';
		else {
			*ptrt = *ptrf++;
		}
	}
	*(ptrt-1) = '\0';

	if (whocalled == 1)
		gtk_entry_set_text(GTK_ENTRY(w1), temp);
	else 
		memcpy(clptr->dst, temp, 20);

	/* and source mac */
	ptrt = temp;
	w2 = lookup_widget(GTK_WIDGET(button), "L_src_mac");
	for (i=1; i<=18; i++, ptrt++) {
		if (i%3 == 0) 
			*ptrt = ':';
		else {
			*ptrt = *ptrf++;
		}
	}
	*(ptrt-1) = '\0';

	if (whocalled == 1)
		gtk_entry_set_text(GTK_ENTRY(w2), temp);
	else 
		memcpy(clptr->src, temp, 20);

	/* next there is type or length field or 802.1q or QinQ! */
	i = char2x(ptrf)*256 + char2x(ptrf+2);

	remain = remain - 14;

	/* in case of a vlan tag 0x8100 == 33024) */
	w1 = lookup_widget(GTK_WIDGET(button), "bt_8021q");
	w2 = lookup_widget(GTK_WIDGET(button), "frame6");

	if ((i == 33024) || (i==34984) || (i==37120) || (i==37376)) {
		w3 = lookup_widget(GTK_WIDGET(button), "L_optmenu2_bt");
		w4 = lookup_widget(GTK_WIDGET(button), "checkbutton39");
		w5 = lookup_widget(GTK_WIDGET(button), "checkbutton40");
		w6 = lookup_widget(GTK_WIDGET(button), "L_vlan_id");
		w7 = lookup_widget(GTK_WIDGET(button), "entry165");
		w8 = lookup_widget(GTK_WIDGET(button), "optionmenu21");
		
	        //if we have 8100 after the next 4 bytes we do QinQ	
		if ( ((char2x(ptrf+8)*256 + char2x(ptrf+10))==33024) && remain>=8) 
		{
			ptrf = ptrf + 4;
			
			if (whocalled == 1) {
				gtk_widget_set_sensitive (w7, TRUE);
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w5), TRUE);
				if (i==33024)
					gtk_option_menu_set_history (GTK_OPTION_MENU (w8), 0);
				else if (i==34984)
					gtk_option_menu_set_history (GTK_OPTION_MENU (w8), 3);
				else if (i==37120)
					gtk_option_menu_set_history (GTK_OPTION_MENU (w8), 1);
				else if (i==37376)
					gtk_option_menu_set_history (GTK_OPTION_MENU (w8), 2);

				inspar(button, "entry165", ptrf, 4);
			}
			else
				ptrf = ptrf +3;

			i = char2x(ptrf)*256 + char2x(ptrf+2);
		}	
		else {
			if (whocalled == 1) {
				gtk_widget_set_sensitive (w7, FALSE);
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w5), FALSE);
			}	

		}

		if (remain < 4) {
			error("Can't load packet: Ethernet VLAN field is not long enough!");
			return -1;
		}
		remain = remain -4;

		ptrf = ptrf + 4;
		*ptrt++ = '0';
		*ptrt-- = *ptrf++;
		i = char2x(ptrt);

		if (whocalled == 1) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
			gtk_widget_set_sensitive (w2, TRUE);
		
			gtk_option_menu_set_history (GTK_OPTION_MENU (w3), (i>>1));

			if ( (i%2) == 0)
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w4), FALSE);
			else
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w4), TRUE);

			inspar(button, "L_vlan_id", ptrf, 3);
		}
		else
			ptrf = ptrf+3;

		i = char2x(ptrf)*256 + char2x(ptrf+2);

	}
	else {
		if (whocalled == 1) {
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), FALSE);

			gtk_widget_set_sensitive (w2, FALSE);
		}	
	}
	
	/* c will tell us which ethernet type we have */
	c = i;

	/* ok, from now one, we split the dissection in different routines, depending on what values */
	/* now if length is <= 1500, we have 802.3 ethernet and this value means length of ethernet packet */
	if (i <= 1500) 
		next_prot = ethernet_8023(button, whocalled);
	/* Values between 1500 and 1536 are forbidden */
	else if ( (i>1500) && (i<1536) ) {
		error("Can't load packet: Wrong ethernet length/type field");
		return -1;
	}
	/* if i >= 1536 - ethernet ver II */
	else
		next_prot = ethernet_verII(button, whocalled);


	/* ok, so we have dissected the ethernet layer and now move on two the next layer.
	 * if the ethernet dissector returns -1, this means an error and we quit
	 * otherwise, the return value can be 2048 == 0x0800 and this means the ipv4
	 * so we try to dissect ipv4 header. in case it is ok, we activate the ippkt_radibt
	 * and this one then calls the callback which fills in ethernet ver II type field
	 * and PID field in 802.3 LLC/SNAP field. It is the same for arp packets
	 * for other packets we will try to open the userdefined window */

	/* we got an error? */
	if (next_prot == -1) 
		return -1;

	/* ipv4 */
	else if (next_prot == 2048) {
		/* ok, ipv4 should follow, so we call the routine for parsing ipv4 header. */
		next_prot = ipv4_header(button, whocalled, clptr);
		if (next_prot == -1)
			return -1;

		/* if the return value from parsing ipv4 header was != 0, then the header parameters 
		 * are ok and we can open ipv4 notebook page activate toggle button (button calls 
		 * the callback then!!! */
		w1 = lookup_widget(GTK_WIDGET(button), "ippkt_radibt");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);

		/* here we do the further parsing: tcp, udp, icmp, ...*/
		if (next_prot == 1) {
			/* try to parse icmp header */
			next_prot = icmp_header(button, whocalled);
			/* not ok, return an error */
			if (next_prot == -1)
				return -1;
			/* ok, lets activate the icmp notebook */
			else {
				w1 = lookup_widget(GTK_WIDGET(button), "icmp_bt");
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
			}
		}
		else if (next_prot == 2) {
			/* try to parse igmp header */
			next_prot = igmp_header(button, whocalled);
			/* not ok, return an error */
			if (next_prot == -1)
				return -1;
			/* ok, lets activate the igmp notebook */
			else {
				w1 = lookup_widget(GTK_WIDGET(button), "igmp_bt");
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
			}
		}
		else if (next_prot == 6) {
			/* try to parse tcp header */
			next_prot = tcp_header(button, whocalled);
			/* not ok, return an error */
			if (next_prot == -1)
				return -1;
			/* ok, lets activate the tcp notebook */
			else {
				w1 = lookup_widget(GTK_WIDGET(button), "tcp_bt");
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
			}

			/* protocols on top of tcp would follow here */

		}	
		else if (next_prot == 17) {
			/* try to parse udp header */
			next_prot = udp_header(button, whocalled);
			/* not ok, return an error */
			if (next_prot == -1)
				return -1;
			/* ok, lets activate the udp notebook */
			else {
				w1 = lookup_widget(GTK_WIDGET(button), "udp_bt");
				gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
			}

			/* protocols on top of udp would follow here */
		}	
		/* protocol we do not support yet; user defined window */
		else {
			next_prot = usedef_insert(button, "text2", whocalled);
			w1 = lookup_widget(GTK_WIDGET(button), "ip_user_data_bt");
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		}
	}
	/*arp */
	else if (next_prot == 2054) {
		/* ok, arp header follows */
		next_prot = arp_header(button, whocalled);
		if (next_prot == -1)
			return -1;

		w1 = lookup_widget(GTK_WIDGET(button), "arppkt_radiobt");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
	}

	/* when ipv6 will be added, activate ipv6 button instead of userdef button */
	else if (next_prot == 34525) {

		/* ok, ipv6 should follow, so we call the routine for parsing ipv6 header. */
                next_prot = ipv6_header(button, whocalled, clptr);
                if (next_prot == -1)
                        return -1;

		w1 = lookup_widget(GTK_WIDGET(button), "IPv6_rdbt");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);

                /* here we do the further parsing: tcp, udp, icmp, ...*/
                if (next_prot == 58) {
                        /* try to parse icmpv6 header */
                        next_prot = icmpv6_header(button, whocalled);
                        /* not ok, return an error */
                        if (next_prot == -1)
                                return -1;
                        /* ok, lets activate the icmpv6 notebook */
                        else {
                                w1 = lookup_widget(GTK_WIDGET(button), "radiobutton69");
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
                        }
                }
                else if (next_prot == 6) {
                        /* try to parse tcp header */
                        next_prot = tcp_header(button, whocalled);
                        /* not ok, return an error */
                        if (next_prot == -1)
                                return -1;
                        /* ok, lets activate the tcp notebook */
                        else {
                                w1 = lookup_widget(GTK_WIDGET(button), "radiobutton68");
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
                        }
		}
		else if (next_prot == 17) {
                        /* try to parse udp header */
                        next_prot = udp_header(button, whocalled);
                        /* not ok, return an error */
                        if (next_prot == -1)
                                return -1;
                        /* ok, lets activate the udp notebook */
                        else {
                                w1 = lookup_widget(GTK_WIDGET(button), "radiobutton67");
                                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
                        }
                }
                /* protocol we do not support yet; user defined window */
                else {
                        next_prot = usedef_insert(button, "text2", whocalled);
                        w1 = lookup_widget(GTK_WIDGET(button), "radiobutton71");
                        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
                }

	}
	/* anything else - user defined */
	else {
		/* setting "usedef2_radibt" toggle button to true will call the callback which will clear 
		eth II type field and 802.3 pid field, so we have to fill this later */
		w1 = lookup_widget(GTK_WIDGET(button), "usedef2_radibt");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		
		/* we still have c to distinguish between ver II and 802.3 */
		/* ver II */
		if (c >= 1536) {
			ptrf = ptrf - 4;
   			inspar(button, "L_ethtype", ptrf, 4);
		}
		/* 802.3 and with LLC SNAP */
		else if (next_prot != -2) {
			ptrf = ptrf - 4;
			inspar(button, "L_pid", ptrf, 4);
		}		

		next_prot = usedef_insert(button, "text1", whocalled);
	}

	return 1;
}


int arp_header(GtkButton *button, int whocalled) {

	char tmp[5];
	int x;

	if (whocalled==2) {
		protokol = ARP;
		return 1;
	}

	/* arp header length == 28; but packet can be longer, f.e. to satisfy the min packet length */
	if (remain < 28) {
		error("Can't load packet: Packet length shorter than ARP header length!");
		return -1;
	}

	remain = remain - 28;

	/* hardware type */
	inspar(button, "A_hwtype", ptrf, 4);

	/* protocol type */
	inspar(button, "A_prottype", ptrf, 4);

	/* hardware size */
	inspar(button, "A_hwsize", ptrf, 2);

	/* protocol size */
	inspar(button, "A_protsize", ptrf, 2);

	/* opcode is next */
	if ( (*ptrf == '0') && (*(ptrf+1) == '0') && (*(ptrf+2) == '0') && (*(ptrf+3) == '1') ) {
		w1 = lookup_widget(GTK_WIDGET(button), "radiobutton10");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		ptrf = ptrf + 4;
	}
	else if ( (*ptrf == '0') && (*(ptrf+1) == '0') && (*(ptrf+2) == '0') && (*(ptrf+3) == '2') ) {
		w1 = lookup_widget(GTK_WIDGET(button), "radiobutton11");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		ptrf = ptrf + 4;
	}
	else {
		w1 = lookup_widget(GTK_WIDGET(button), "radiobutton17");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		inspar(button, "entry81", ptrf, 4);
	}

	/* sender mac */
	ptrt = temp;
	w1 = lookup_widget(GTK_WIDGET(button), "A_sendermac");
	for (i=1; i<=18; i++, ptrt++) {
		if (i%3 == 0) 
			*ptrt = ':';
		else {
			*ptrt = *ptrf++;
		}
	}
	*ptrt = '\0';
	gtk_entry_set_text(GTK_ENTRY(w1), temp);

	/* sender ip */
	ptrt = temp;
	memset(temp, 0, 20);
	w1 = lookup_widget(GTK_WIDGET(button), "A_senderip");
	for (i=1; i<=12; i++, ptrt++) {
		if (i%3 == 0) {			
			x = char2x(tmp);
			if (i==12)
				snprintf(tmp, 4, "%d", x);		
			else
				snprintf(tmp, 5, "%d.", x);		
			strcat(temp, tmp);
		}
		else {
			tmp[(i-1)%3] = *ptrf++;
		}
	}
	gtk_entry_set_text(GTK_ENTRY(w1), temp);

	/* target mac */
	ptrt = temp;
	w1 = lookup_widget(GTK_WIDGET(button), "A_targetmac");
	for (i=1; i<=18; i++, ptrt++) {
		if (i%3 == 0) 
			*ptrt = ':';
		else {
			*ptrt = *ptrf++;
		}
	}
	*ptrt = '\0';
	gtk_entry_set_text(GTK_ENTRY(w1), temp);

	/* target ip */
	ptrt = temp;
	memset(temp, 0, 20);
	w1 = lookup_widget(GTK_WIDGET(button), "A_targetip");
	for (i=1; i<=12; i++, ptrt++) {
		if (i%3 == 0) {			
			x = char2x(tmp);
			if (i==12)
				snprintf(tmp, 4, "%d", x);		
			else
				snprintf(tmp, 5, "%d.", x);		
			strcat(temp, tmp);
		}
		else {
			tmp[(i-1)%3] = *ptrf++;
		}
	}
	gtk_entry_set_text(GTK_ENTRY(w1), temp);

	return 1;

}


int igmp_header(GtkButton *button, int whocalled) {

	int x, x1;
	char tmp[5];

	if (whocalled==2) {
		protokol = IGMP;
		return 1;
	}

	/* well normal igmp type should have at least 8 bytes, so this is min for us */
	if (remain < 8) {
		error("Can't load packet: Packet length shorter than IGMP header length!");
		return -1;
	}

	remain = remain -8;

	/* igmp type */
	x = char2x(ptrf);
	/* insert version */
	inspar(button, "entry166", ptrf, 2);

	w1 = lookup_widget(GTK_WIDGET(button), "optionmenu20");
	w2 = lookup_widget(GTK_WIDGET(button), "notebook8");
	if (x == 17) {
		if (remain > 4) {
	        	gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 1);
			gtk_notebook_set_page(GTK_NOTEBOOK(w2), 1);
			}
		else	{
	        	gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 0);
			gtk_notebook_set_page(GTK_NOTEBOOK(w2), 0);
			}
	}
	else if (x == 18) {
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 2);
		gtk_notebook_set_page(GTK_NOTEBOOK(w2), 0);
		}
	else if (x == 22) {
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 3);
		gtk_notebook_set_page(GTK_NOTEBOOK(w2), 0);
		}
	else if (x == 34) {
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 4);
		gtk_notebook_set_page(GTK_NOTEBOOK(w2), 2);
		}
	else if (x == 23) {
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 5);
		gtk_notebook_set_page(GTK_NOTEBOOK(w2), 0);
		}
	else	{
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 6);
		gtk_notebook_set_page(GTK_NOTEBOOK(w2), 0);
		}

	inspar(button, "entry167", ptrf, 2);

	/* set checksum button on auto */
	w2 = lookup_widget(GTK_WIDGET(button), "checkbutton41");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w2), TRUE);
	ptrf = ptrf + 4;


	if ( (x == 17) && (remain>4) ) { /* IGMP V3 query */
		/*insert group ip */
		ptrt = temp;
		memset(temp, 0, 20);
		w1 = lookup_widget(GTK_WIDGET(button), "entry169");
		for (i=1; i<=12; i++, ptrt++) {
			if (i%3 == 0) {			
				x = char2x(tmp);
				if (i==12)
					snprintf(tmp, 4, "%d", x);		
				else
					snprintf(tmp, 5, "%d.", x);		
				strcat(temp, tmp);
			}
			else {
				tmp[(i-1)%3] = *ptrf++;
			}
		}
		gtk_entry_set_text(GTK_ENTRY(w1), temp);

		inspar(button, "entry171", ptrf, 4);
		x1 = (int)retint2(ptrf, 4);
		inspar(button, "entry172", ptrf, 4);
		/*#inspar(button, "entry173", ptrf, x1);*/
		inspar(button, "entry173", ptrf, remain);
		
	}
	else if (x==22) { /*IGMP V3 report */
		inspar(button, "entry176", ptrf, 4);
		x1 = (int)retint2(ptrf, 4);
		inspar(button, "entry177", ptrf, 4);
		inspar(button, "entry178", ptrf, x1);
		
	}
	else { /*all the other versions */
		/*insert group ip */
		ptrt = temp;
		memset(temp, 0, 20);
		w1 = lookup_widget(GTK_WIDGET(button), "entry175");
		for (i=1; i<=12; i++, ptrt++) {
			if (i%3 == 0) {			
				x = char2x(tmp);
				if (i==12)
					snprintf(tmp, 4, "%d", x);		
				else
					snprintf(tmp, 5, "%d.", x);		
				strcat(temp, tmp);
			}
			else {
				tmp[(i-1)%3] = *ptrf++;
			}
		}
		gtk_entry_set_text(GTK_ENTRY(w1), temp);
			
	
	}	

	return 1;
}

int icmp_header(GtkButton *button, int whocalled) {

	int x;
	char tmp5[5];

	if (whocalled==2) {
		protokol = ICMP;
		return 1;
	}

	/* well normal icmp type should have at least 8 bytes, so this is min for us */
	if (remain < 8) {
		error("Can't load packet: Packet length shorter than ICMP header length!");
		return -1;
	}

	remain = remain -8;

	/* icmp type */
	x = char2x(ptrf);
	/* insert version */
	inspar(button, "entry57", ptrf, 2);

	w1 = lookup_widget(GTK_WIDGET(button), "optionmenu4");
	if (x == 0)
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 0);
	else if (x == 3) 
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 1);
	else if (x == 8) 
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 2);
	else
	        gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 3);


	if (x == 0) { /* echo reply */
		/* insert code, checksum, identifier and seq number and data if there is some */
		w1 = lookup_widget(GTK_WIDGET(button), "notebook5");
		gtk_notebook_set_page(GTK_NOTEBOOK(w1), 0);
		inspar(button, "entry62", ptrf, 2);
		//inspar(button, "entry63", ptrf, 4);
		ptrf = ptrf + 4;
		inspar(button, "entry64", ptrf, 4);
		inspar(button, "entry65", ptrf, 4);
		/* set checksum button on auto */
		w2 = lookup_widget(GTK_WIDGET(button), "checkbutton16");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w2), TRUE);

		if (remain > 0) {
			w1 = lookup_widget(GTK_WIDGET(button), "checkbutton17");
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		}
		else {
			w1 = lookup_widget(GTK_WIDGET(button), "checkbutton17");
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), FALSE);
		}
		inspar(button, "entry66", ptrf, 2);
		sprintf(tmp5, "%d", remain);
		inspar(button, "entry207", tmp5, 4);
		
	}
	else if (x == 3) { /* destination unreacheable */
		w1 = lookup_widget(GTK_WIDGET(button), "notebook5");
		gtk_notebook_set_page(GTK_NOTEBOOK(w1), 2);
		/* which code? */
		x = char2x(ptrf);
		/* insert code */
		inspar(button, "entry58", ptrf, 2);

		w1 = lookup_widget(GTK_WIDGET(button), "optionmenu5");
		if ( (x >= 0) && (x <= 15) )
			gtk_option_menu_set_history (GTK_OPTION_MENU (w1), x);
		else
			gtk_option_menu_set_history (GTK_OPTION_MENU (w1), 16);
		
		/* insert code, checksum, identifier and seq number and data if there is some */
		//inspar(button, "entry59", ptrf, 4);
		ptrf = ptrf + 4;
		inspar(button, "entry60", ptrf, 8);
		/* set checksum button on auto */
		w2 = lookup_widget(GTK_WIDGET(button), "checkbutton15");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w2), TRUE);

		if (remain > 0) {
			w1 = lookup_widget(GTK_WIDGET(button), "checkbutton24");
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		}
		else {
			w1 = lookup_widget(GTK_WIDGET(button), "checkbutton24");
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), FALSE);
		}

		inspar(button, "entry66", ptrf, 2);
		sprintf(tmp5, "%d", remain);
		inspar(button, "entry210", tmp5, 4);
	}
	else if (x == 8) { /* echo request */
		w1 = lookup_widget(GTK_WIDGET(button), "notebook5");
		gtk_notebook_set_page(GTK_NOTEBOOK(w1), 5);
		/* insert code, checksum, identifier and seq number and data if there is some */
		inspar(button, "entry74", ptrf, 2);
		//inspar(button, "entry77", ptrf, 4);
		ptrf = ptrf + 4;
		inspar(button, "entry75", ptrf, 4);
		inspar(button, "entry78", ptrf, 4);
		/* set checksum button on auto */
		w2 = lookup_widget(GTK_WIDGET(button), "checkbutton20");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w2), TRUE);

		if (remain > 0) {
			w1 = lookup_widget(GTK_WIDGET(button), "checkbutton19");
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		}
		else {
			w1 = lookup_widget(GTK_WIDGET(button), "checkbutton19");
			gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), FALSE);
		}
		inspar(button, "entry66", ptrf, 2);
		sprintf(tmp5, "%d", remain);
		inspar(button, "entry211", tmp5, 4);

	}
	else { /* all the rest */
		w1 = lookup_widget(GTK_WIDGET(button), "notebook5");
		gtk_notebook_set_page(GTK_NOTEBOOK(w1), 1);
		/* insert code, checksum and data if there is some */
		inspar(button, "entry157", ptrf, 2);
		//inspar(button, "entry158", ptrf, 4);
		ptrf = ptrf + 4;
		/* set checksum button on auto */
		w2 = lookup_widget(GTK_WIDGET(button), "checkbutton38");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w2), TRUE);
	}

	return 1;
}


int usedef_insert(GtkButton *button, char *entry, int whocalled) {

	int i, j;
	char tmp[31000];

	//if (whocalled == 1)
	//	return 1;

	/* get access to buffer of the text field */
	w2 = lookup_widget(GTK_WIDGET(button), entry);
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(w2));

	/* copy data to tmp field */
	for (i=0, j=1; (i < (remain * 3) ); i++, j++) {
		tmp[i] = *ptrf++; i++;
		tmp[i] = *ptrf++; i++;
		/* we allow only 16 bytes in each row - looks nicer */
		if ((j % 16) == 0 && (j > 1)) {
			tmp[i]='\n';
			j = 0;
		}
		else
			tmp[i] = ' ';
	}
	tmp[i] = '\0';

	/* insert the text in the text field */
	gtk_text_buffer_set_text(buffer,tmp,-1);

	return 1;


}


int tcp_header(GtkButton *button, int whocalled) {

	int x, i, j;
	char tmp[31000], tmp2[3], ch;

	if (whocalled==2) {
		protokol = TCP;
		return 1;
	}


	/* for standard header this is minimum length */
	if (remain < 20) {
		error("Can't load packet: Packet length shorter than TCP header length!");
		return -1;
	}

	/* ok, packet is long enough to fill in the standard header, but what is the header length?
	 * we insert this later but need now to see that the packet is long enough */
	x = retint(ptrf+24);
	if ( (x * 4) > remain ) {
		error("Can't load packet:\nPacket lenght shorter than TCP header length!");
		return -1;
	}
	if ( x < 5 ) {
		error("Can't load packet:\nTCP header length shorter than 20 bytes!");
		return -1;
	}

	/* source port */
	insint(button, "entry46", ptrf, 4);
	
	/* destination port */
	insint(button, "entry47", ptrf, 4);

	/* sequence number */
	insint(button, "entry48", ptrf, 8);

	/* acknowledgement number */
	insint(button, "entry49", ptrf, 8);
	
	/* now we insert value for length */
	snprintf(tmp2, 3, "%d", x*4);
	w1 = lookup_widget(GTK_WIDGET(button), "entry50");
	gtk_entry_set_text(GTK_ENTRY(w1), tmp2);

	/* increase by one for length and for another one for 4 bits that are reserved */
	ptrf = ptrf + 2;

	/* flags; next byte */	
	ch = char2x(ptrf) % 0x0100;

	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton22");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x80) > 0 ? TRUE : FALSE);
	
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton23");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x40) > 0 ? TRUE : FALSE);
	
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton7");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x20) > 0 ? TRUE : FALSE);
	
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton8");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x10) > 0 ? TRUE : FALSE);
	
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton9");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x08) > 0 ? TRUE : FALSE);
	
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton10");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x04) > 0 ? TRUE : FALSE);
	
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton11");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x02) > 0 ? TRUE : FALSE);
	
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton12");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), (ch & 0x01) > 0 ? TRUE : FALSE);
	
	ptrf = ptrf + 2;

	/* window size */
	insint(button, "entry51", ptrf, 4);
	
	/* checksum */
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton13");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
	//inspar(button, "entry52", ptrf, 4);
	ptrf = ptrf + 4;

	/* window size */
	insint(button, "entry53", ptrf, 4);
	
	/* any options ? */
	/* - 20 for standard header */
	inspar(button, "entry54", ptrf, ( (x*4) - 20) * 2);

	remain = remain - x*4;

	/* get access to buffer of the text field */
	w2 = lookup_widget(GTK_WIDGET(button), "text4");
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(w2));

	if (remain > 0) {
		w1 = lookup_widget(GTK_WIDGET(button), "checkbutton14");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
	
		/* copy data to tmp field */
		for (i=0, j=1; (i < (remain * 3) ); i++, j++) {
			tmp[i] = *ptrf++; i++;
			tmp[i] = *ptrf++; i++;
			/* we allow only 16 bytes in each row - looks nicer */
			if ((j % 16) == 0 && (j > 1)) {
				tmp[i]='\n';
				j = 0;
			}
			else
				tmp[i] = ' ';
		}
		tmp[i] = '\0';

		/* insert the text in the text field */
		gtk_text_buffer_set_text(buffer,tmp,-1);
	}
	else {	
		w1 = lookup_widget(GTK_WIDGET(button), "checkbutton14");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), FALSE);
	}

	/* since tcp does not have any protocol field we could return destination port value which 
	 * usually describes next layer protocol; currently we return 1 */

	return 1;
}

int udp_header(GtkButton *button, int whocalled) {

	int i, j;
	char tmp[31000];

	if (whocalled==2) {
		protokol = UDP;
		return 1;
	}

	/* for standard header this is minimum length */
	if (remain < 8) {
		error("Can't load packet: Packet length shorter than UDP header length!");
		return -1;
	}

	remain = remain - 8;

	/* source port */
	insint(button, "entry56", ptrf, 4);
	
	/* destination port */
	insint(button, "entry41", ptrf, 4);

	/* length */
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton3");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
	//insint(button, "entry42", ptrf, 4);
	ptrf = ptrf + 4;

	/* checksum */
	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton4");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
	//inspar(button, "entry43", "", 4);
	ptrf = ptrf + 4;

	/* get access to buffer of the text field */
	w2 = lookup_widget(GTK_WIDGET(button), "text3");
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(w2));

	if (remain > 0) {
		w1 = lookup_widget(GTK_WIDGET(button), "checkbutton5");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
	
		/* copy data to tmp field */
		for (i=0, j=1; (i < (remain * 3) ); i++, j++) {
			tmp[i] = *ptrf++; i++;
			tmp[i] = *ptrf++; i++;
			/* we allow only 16 bytes in each row - looks nicer */
			if ((j % 16) == 0 && (j > 1)) {
				tmp[i]='\n';
				j = 0;
			}
			else
				tmp[i] = ' ';
		}
		tmp[i] = '\0';

		/* insert the text in the text field */
		gtk_text_buffer_set_text(buffer,tmp,-1);
	}
	else {	
		w1 = lookup_widget(GTK_WIDGET(button), "checkbutton5");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), FALSE);
	}

	/* since udp does not have any protocol field we could return destination port value which 
	 * usually describes next layer protocol; currently we return 1 */
	return 1;
}


int ipv4_header(GtkButton *button, int whocalled, struct clist_hdr *clptr ) {

	char tmp[5];
	int x, header_l, prot;

	if (whocalled==2) {
		protokol = IPv4;
	}

	/* for standard header this is minimum length */
	if (remain < 20) {
		error("Can't load packet: IPv4 header field is not long enough!");
		return -1;
	}

	/* first comes version but we will first check the length and then insert version */
	ptrf++;

	/* check the header length */
	/* we don't need to check the return value here, it is already done when reading from file */
	header_l = retint(ptrf);
	/* header length is the number of 32-bit words in the header, including any options. 
	 * Since this is a 4-bit field, it limits the header to 60 bytes. So the remaining length 
	 * should be at least that long or we exit here */
	if ( (header_l * 4) < 20 ) {
		error("Can't load packet:\nIPv4 header length shorter than 20 bytes!");
		return -1;
	}
	if ( (header_l * 4) > remain ) {
		error("Can't load packet:\nPacket lenght shorter than IPv4 header length!");
		return -1;
	}
	ptrf--;

	if (whocalled==1) {
		/* insert version */
		inspar(button, "entry26", ptrf, 1);

		/* insert header length */
		inspar(button, "entry27", ptrf, 1);

		/* insert tos */
		inspar(button, "entry28", ptrf, 2);

		/* insert total length */
		w1 = lookup_widget(GTK_WIDGET(button), "checkbutton21");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		//insint(button, "entry29", ptrf, 4);
	}
	else
		ptrf = ptrf+4;

	ptrf = ptrf + 4;

	if (whocalled==1) {
		/* insert identification */
		inspar(button, "entry30", ptrf, 4);
	}
	else
		ptrf = ptrf+4;

	/* insert flags */
	*tmp = 0x30; /* 0x30 == 0 */
	*(tmp+1) = *ptrf;
	x = char2x(tmp);
	x = x >> 1; /* use only first 3 bits */
	
	if (whocalled==1) {
		w1 = lookup_widget(GTK_WIDGET(button), "entry31");
        	snprintf(tmp, 4, "%d", x);
        	gtk_entry_set_text(GTK_ENTRY(w1), tmp);
	}

	/* insert fragment offset */
	*tmp = 0x30; /* 0x30 == 0 */
	*(tmp+1) = *ptrf;
	x = (char2x(tmp)%2); /* need only last bit */
	if (x == 0)
		*tmp = 0x30;
	else
		*tmp = 0x31;
	strncpy(tmp+1, ptrf+1, 3);

	if (whocalled==1) {
		insint(button, "entry32", tmp, 4);
	
		/* insert ttl */
		insint(button, "entry44", ptrf, 2);
	}
	else
		ptrf = ptrf+6;

	prot = char2x(ptrf);

	if (whocalled==1) {
		/* insert protocol */
		insint(button, "entry34", ptrf, 2);

		/* insert header checksum */
		w1 = lookup_widget(GTK_WIDGET(button), "ip_header_cks_cbt");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		//inspar(button, "entry35", ptrf, 4);
	}
	else
		ptrf = ptrf+2;

	ptrf = ptrf + 4;

	/*insert source ip */
	ptrt = temp;
	memset(temp, 0, 20);
	if (whocalled==1)
		w1 = lookup_widget(GTK_WIDGET(button), "entry38");
	for (i=1; i<=12; i++, ptrt++) {
		if (i%3 == 0) {			
			x = char2x(tmp);
			if (i==12)
				snprintf(tmp, 4, "%d", x);		
			else
				snprintf(tmp, 5, "%d.", x);		
			strcat(temp, tmp);
		}
		else {
			tmp[(i-1)%3] = *ptrf++;
		}
	}

	if (whocalled==1)
		gtk_entry_set_text(GTK_ENTRY(w1), temp);
	else
		memcpy(clptr->src, temp, 20);

	/*insert destination ip */
	ptrt = temp;
	memset(temp, 0, 20);
	if (whocalled==1)
		w1 = lookup_widget(GTK_WIDGET(button), "entry37");
	for (i=1; i<=12; i++, ptrt++) {
		if (i%3 == 0) {			
			x = char2x(tmp);
			if (i==12)
				snprintf(tmp, 4, "%d", x);		
			else
				snprintf(tmp, 5, "%d.", x);		
			strcat(temp, tmp);
		}
		else {
			tmp[(i-1)%3] = *ptrf++;
		}
	}
	if (whocalled==1)
		gtk_entry_set_text(GTK_ENTRY(w1), temp);
	else
		memcpy(clptr->dst, temp, 20);

	/* insert ipv4 options 
	 * header_l * 4 == total header length, - 20 for standard header == options length in bytes*/
	if (whocalled==1)
		inspar(button, "entry39", ptrf, ( (header_l*4) - 20) * 2);

	remain = remain - (header_l * 4);
	
	return prot;
}


int ethernet_8023(GtkButton *button, int whocalled) {

	int dsap, lsap, ctrl;
	long pid;

	if (whocalled==2) {
		protokol = ETH_802_3;
		return 1;
	}

	if (remain < 6) {
		error("Can't load packet: Ethernet 802.3 LLC field is not long enough!");
		return -1;
	}
	remain = remain - 3;

	w1 = lookup_widget(GTK_WIDGET(button), "bt_8023");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);

	//w2 = lookup_widget(GTK_WIDGET(button), "frame7");
	//gtk_widget_set_sensitive (w2, TRUE);
	//gtk_notebook_set_page(GTK_NOTEBOOK(w3), 1);

	w1 = lookup_widget(GTK_WIDGET(button), "entry5");
	//inspar(button, "entry5", ptrf, 4);
	ptrf = ptrf + 4;
	gtk_widget_set_sensitive (w1, FALSE);

	w2 = lookup_widget(GTK_WIDGET(button), "checkbutton2");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w2), TRUE);
	
	/*now the LLC / LLC-SNAP part */
	/* we decode only RFC 1042 format, that means the following value:
		dsap == ssap == 0xAA
		ctrl == 0x03
		OUI  == 0x000000 
	*/
	dsap = char2x(ptrf);	
	inspar(button, "L_dsap", ptrf, 2);
	lsap = char2x(ptrf);	
	inspar(button, "L_ssap", ptrf, 2);
	ctrl = char2x(ptrf);	
	inspar(button, "L_ctrl", ptrf, 2);

	/* in case dsap != ssap != 0xAA or ctrl != 0x03 or remain length < 5 bytes, we have only 
	 * LLC without SNAP and we return value for user defined next layer */
	if ( (dsap != 170 ) || (lsap != 170) || (ctrl != 3) || (remain < 5) ) {
		w1 = lookup_widget(GTK_WIDGET(button), "L_8023_llc_tbt");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		w1 = lookup_widget(GTK_WIDGET(button), "L_oui");
		w2 = lookup_widget(GTK_WIDGET(button), "L_pid");
		gtk_widget_set_sensitive (w1, FALSE);
		gtk_widget_set_sensitive (w2, FALSE);
		/* this means we insert all the data as user defined field */
		return -2;
	}
	/* in this case everything is ok but oui in not 0 */
	/*	   <--------------this is oui--------------------->   */	
	else if ( (char2x(ptrf) + char2x(ptrf+2) + char2x(ptrf+4) != 0 ) ) {
		w1 = lookup_widget(GTK_WIDGET(button), "L_8023_llc_tbt");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
		w1 = lookup_widget(GTK_WIDGET(button), "L_oui");
		w2 = lookup_widget(GTK_WIDGET(button), "L_pid");
		gtk_widget_set_sensitive (w1, FALSE);
		gtk_widget_set_sensitive (w2, FALSE);
		/* this means we insert all the data as user defined field */
		return -2;
	}
	
	/* substract 3 for oui and 2 for pid */
	remain = remain - 5;

	/* ok, so we have dsap and ssap == 0xAA, Ctlr == 0x03, OUI == 0x0 and lenght is long enough */
	/* set llc-snap button */
	w1 = lookup_widget(GTK_WIDGET(button), "L_8023_llcsnap_tbt");
	gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);

	/* insert 0x00 into oui field */
	inspar(button, "L_oui", ptrf, 6);
	pid = char2x(ptrf)*256 + char2x(ptrf+2);

	ptrf = ptrf + 4;

	return pid;
}


int ethernet_verII(GtkButton *button, int whocalled) {

	int pid;
	
	if (whocalled==2) 
		protokol = ETH_II;

	if (whocalled==1) {
		w1 = lookup_widget(GTK_WIDGET(button), "bt_ver2");
		gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
	}

	pid = char2x(ptrf)*256 + char2x(ptrf+2);

	ptrf = ptrf + 4;

	return pid;
}


/* this one inserts (length) characters from (char *from) into entry named (char *entry). It adds \0 
at the end and in moves pointer ptrf (this one points the the next "data" to be inserted) by length */
void inspar(GtkButton *button, char *entry, char *from, int length) {

	GtkWidget *widg;
	//char tmp[81];
	char *ptr;

	ptr = malloc(length * sizeof(char) + 1);	

	widg = lookup_widget(GTK_WIDGET(button), entry);

	strncpy(ptr, from, length);
	ptr[length] = '\0';
	gtk_entry_set_text(GTK_ENTRY(widg), ptr);
	ptrf = ptrf + length;

	free(ptr);
} 


/* this one reads (length) characters strating at (char *from), converts them to int and inserts them 
into field (*entry) as integer. f.e: 0x56 == (int)86 => writes into (*entry) 86 
note that max size for length is 10!!! when calling this routine */
void insint(GtkButton *button, char *entry, char *from, int length) {

	GtkWidget *widg;
	char tmp[11];
	unsigned long value = 0;
	int i;
	unsigned char x = 0;

	widg = lookup_widget(GTK_WIDGET(button), entry);

	for (i = 0; i < length; i++) {
		if ( (*from >= '0') && (*from <= '9')) 
			x = ((*from) - 48);
		else if ((*from >= 'A') && (*from <= 'F')) 
			x = ((*from) - 55);
		else if ((*from >= 'a') && (*from <= 'f')) 
			x = ((*from) - 87);
		
		value = value + ((int)x) * ((unsigned long)1 << (4*(length-1-i)) );
		from++;
	}

	ptrf = ptrf + length;

	snprintf(tmp, 11, "%lu", value);
	gtk_entry_set_text(GTK_ENTRY(widg), tmp);
} 


/* from a character return int */
signed int retint(char *ch) {

	unsigned char x;

	if ( (*ch >= '0') && (*ch <= '9')) 
		x = ((*ch) - 48);
	else if ((*ch >= 'A') && (*ch <= 'F')) 
		x = ((*ch) - 55);
	else if ((*ch >= 'a') && (*ch <= 'f')) 
		x = ((*ch) - 87);
	else 
	        return -1;
	
	return (int)x;
	
}


/* this one reads (length) characters strating at (*from), and returns integer (max 10 char length) */
unsigned long retint2(char *from, int length) {

	unsigned long value = 0;
	int i;
	unsigned char x = 0;

	for (i = 0; i < length; i++) {
		if ( (*from >= '0') && (*from <= '9')) 
			x = ((*from) - 48);
		else if ((*from >= 'A') && (*from <= 'F')) 
			x = ((*from) - 55);
		else if ((*from >= 'a') && (*from <= 'f')) 
			x = ((*from) - 87);
		
		value = value + ((int)x) * ((unsigned long)1 << (4*(length-1-i)) );
		from++;
	}

	return value;
} 


/* i have newer really understood the endians... help appreciated... 
 * this routines just converts the contents of a char field of size 8 chars 
 * it works also, if destination and source are the same field*/

void convert8field(char *to, char *from) {

	char f1[8];

	/* we copy first the source contents */
	memcpy(f1, from, 8);

	memcpy(to+0, f1+6,1);
	memcpy(to+1, f1+7,1);
	memcpy(to+2, f1+4,1);
	memcpy(to+3, f1+5,1);
	memcpy(to+4, f1+2,1);
	memcpy(to+5, f1+3,1);
	memcpy(to+6, f1+0,1);
	memcpy(to+7, f1+1,1);
}

int ipv6_header(GtkButton *button, int whocalled, struct clist_hdr *clptr ) {

        //char tmp[5];
        //int x; 
	int prot, header_l=0;

        if (whocalled==2) {
                protokol = IPv6;
        }

        /* for standard header this is minimum length */
        if (remain < 40) {
                error("Can't load packet: IPv6 header field is not long enough!");
                return -1;
        }

        if (whocalled==1) {
                /* insert version */
                inspar(button, "entry195", ptrf, 1);

                /* insert traffic class */
                inspar(button, "entry196", ptrf, 2);

                /* insert tos */
                inspar(button, "entry197", ptrf, 5);

                /* insert total length */
                w1 = lookup_widget(GTK_WIDGET(button), "checkbutton43");
                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
                //insint(button, "entry29", ptrf, 4);
        }
        else
        	ptrf = ptrf + 8;

       	ptrf = ptrf + 4;


	prot = char2x(ptrf);

        if (whocalled==1) {
                /* insert next header */
                inspar(button, "entry199", ptrf, 2);
        }
        else
                ptrf = ptrf+2;

	 if (whocalled==1) {
                /* insert hop limit */
                insint(button, "entry200", ptrf, 2);
	}
        else
                ptrf = ptrf+2;

	/*insert source ip */
        ptrt = temp6;
        memset(temp6, 0, 40);

        if (whocalled==1)
                w1 = lookup_widget(GTK_WIDGET(button), "entry201");

        for (i=1; i<8; i++) {
		strncpy(ptrt, ptrf, 4);
		ptrt = ptrt + 4;
                strcat(ptrt, ":");
		ptrt++;
		ptrf = ptrf + 4;
        }
	strncpy(ptrt, ptrf, 4);
	ptrf = ptrf + 4;

        if (whocalled==1)
                gtk_entry_set_text(GTK_ENTRY(w1), temp6);
        else
                memcpy(clptr->src, temp6, 40);

	/*insert destination ip */
        ptrt = temp6;
        memset(temp6, 0, 40);
        if (whocalled==1)
                w1 = lookup_widget(GTK_WIDGET(button), "entry202");

        for (i=1; i<8; i++) {
		strncpy(ptrt, ptrf, 4);
		ptrt = ptrt + 4;
                strcat(ptrt, ":");
		ptrt++;
		ptrf = ptrf + 4;
        }
	strncpy(ptrt, ptrf, 4);
	ptrf = ptrf + 4;

        if (whocalled==1)
                gtk_entry_set_text(GTK_ENTRY(w1), temp6);
        else
                memcpy(clptr->dst, temp6, 40);

	//extension header
	while ( (prot==0) || (prot==43) || (prot==44) || (prot==51) || (prot==50) || (prot==60) ) {
		prot = char2x(ptrf);
		header_l = retint2(ptrf+2, 2);
		inspar(button, "entry203", ptrf, header_l);

	}

	remain = remain - 40 - header_l;

        return prot;
}

int icmpv6_header(GtkButton *button, int whocalled) {

	//char tmp5[5];

	if (whocalled==2) {
                protokol = ICMPv6;
                return 1;
        }
	
	/* for standard header this is minimum length */
        if (remain < 4) {
                error("Can't load packet: Packet length shorter than min ICMPv6 header length!");
                return -1;
        }

	remain = remain -4;

	inspar(button, "entry215", ptrf, 2);

	inspar(button, "entry216", ptrf, 2);

	w1 = lookup_widget(GTK_WIDGET(button), "checkbutton48");
        gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
        ptrf = ptrf + 4;

	if (remain >=511)	{
		inspar(button, "entry214", ptrf, 1024);
		//remain = remain -4;
	}
	else if (remain > 0) {
		inspar(button, "entry214", ptrf, remain*2);
	}
	else
		return 1;
	
	/*if (remain > 0) {
                w1 = lookup_widget(GTK_WIDGET(button), "checkbutton47");
                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), TRUE);
         	inspar(button, "entry212", ptrf, 2);
         	sprintf(tmp5, "%d", remain);
         	inspar(button, "entry213", tmp5, 4);
         }
         else {
                w1 = lookup_widget(GTK_WIDGET(button), "checkbutton47");
                gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (w1), FALSE);
         } */


	return 1;

}

