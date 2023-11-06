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
 * callback.c - all callback routines
 *
 */

#define MAXNUMLOADPACKETS 1000

#include <gtk/gtk.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "function.h"
#include "callbacks.h"
#include "interface.h"
#include "support.h"
#include "loadpacket.h"
#include "savepacket.h"

#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <ctype.h>
#include <math.h>
#include <net/if_arp.h>
#include <netinet/in.h>

#include <netinet/in.h>
#include <linux/sockios.h>
#include <arpa/inet.h>




static	GtkWidget *file_menu = NULL;
static	GtkWidget *save_file_menu = NULL;
static	GtkWidget *database_file_menu = NULL;
static	GtkWidget *interface_dialog_menu = NULL;
static	GtkWidget *error_dialog_menu = NULL;
static	GtkWidget *tos_dialog_menu = NULL;
static	GtkWidget *fragment_dialog_menu = NULL;
static	GtkWidget *selection1_dialog = NULL;
static	GtkWidget *udp_payload_dialog = NULL;
extern unsigned char packet[9300];
extern int number;
extern int stop_flag;
extern long desired_bw;
gint row_number;/* this is because i cant get the selected row number*/
gchar address_filename[100] = "addresslist";
static GtkWidget *entry_field;
static GtkWidget *entry_field_ip;
static GtkWidget *entry_field_ipv6;
static GtkWidget *entry_field_udp;
static GtkWidget *entry_field_tos;
static GtkWidget *entry_field_fragment;
static GtkButton *btx;
static gboolean IP_yes = FALSE;
static gboolean IPv6_yes = FALSE;
static gboolean MAC_yes = FALSE;
static int load_select_nr = 0;
int show_error_dialog = 1;

static char *ethernet_mactoa(struct sockaddr *addr) {
	
	static char buff[256];

        unsigned char *ptr = (unsigned char *) addr->sa_data;

        sprintf(buff, "%02X:%02X:%02X:%02X:%02X:%02X",
                (ptr[0] & 0xff), (ptr[1] & 0xff), (ptr[2] & 0xff),
                (ptr[3] & 0xff), (ptr[4] & 0xff), (ptr[5] & 0xff));

	return (buff);

}


void
IP_packet_toggled                      (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt2;
	GtkWidget *nt4;
	GtkWidget *rb1, *rb2, *rb3,/* *rb4,*/ *rb5;
	GtkWidget *option_menu, *opt_value;
	GtkWidget *option_menu2, *opt_value2;
	GtkWidget *cbt;
	
	cbt = lookup_widget("auto_get_mac_cbt");
	gtk_widget_set_sensitive (cbt, TRUE);

	/* eth II */
	option_menu = lookup_widget("L_optmenu1_bt");
	opt_value = lookup_widget("L_ethtype");
	gtk_combo_box_set_active (GTK_COMBO_BOX (option_menu), 0);
	gtk_entry_set_text(GTK_ENTRY(opt_value), "0800");

	/* eth 802.3 */
	option_menu2 = lookup_widget("optionmenu6");
	opt_value2 = lookup_widget("L_pid");
	gtk_combo_box_set_active (GTK_COMBO_BOX (option_menu2), 0);
	gtk_entry_set_text(GTK_ENTRY(opt_value2), "0800");

	/* open ipv4 page */
	nt2 = lookup_widget("notebook2");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt2), 0);

	/* what is next page */
	rb1 = lookup_widget("tcp_bt");
	rb2 = lookup_widget("udp_bt");
	rb3 = lookup_widget("icmp_bt");
	//rb4 = lookup_widget("ip_user_data_bt");
	rb5 = lookup_widget("igmp_bt");
	nt4 = lookup_widget("notebook4");

	gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(opt_value2), FALSE);

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb1))) 
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 1);
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb2))) 
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 0);
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb3))) 
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 2);
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb5))) 
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 4);
	else 
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 3);

}


void
on_arppkt_radiobt_toggled              (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt2, *nt4;
	GtkWidget *option_menu, *opt_value;
	GtkWidget *option_menu2, *opt_value2;
	GtkWidget *cbt;
	
	cbt = lookup_widget("auto_get_mac_cbt");
	gtk_widget_set_sensitive (cbt, TRUE);

	/* for eth II */
	option_menu = lookup_widget("L_optmenu1_bt");
	opt_value = lookup_widget("L_ethtype");
	gtk_combo_box_set_active (GTK_COMBO_BOX (option_menu), 2);
	gtk_entry_set_text(GTK_ENTRY(opt_value), "0806");

	/* for eth 802.3 */
	option_menu2 = lookup_widget("optionmenu6");
	opt_value2 = lookup_widget("L_pid");
	gtk_combo_box_set_active (GTK_COMBO_BOX (option_menu2), 2);
	gtk_entry_set_text(GTK_ENTRY(opt_value2), "0806");

	/* open arp notebook page and empty notebook page for 4 layer */
	nt2 = lookup_widget("notebook2");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt2), 3);
	nt4 = lookup_widget("notebook4");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 6);

	gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	gtk_editable_set_editable(GTK_EDITABLE(opt_value2), FALSE);
}


void
on_usedef2_radibt_toggled              (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt2, *nt4;
	GtkWidget *option_menu, *opt_value;
	
	/* for eth II */
	option_menu = lookup_widget("L_optmenu1_bt");
	gtk_combo_box_set_active (GTK_COMBO_BOX (option_menu), 3);
	opt_value = lookup_widget("L_ethtype");
	gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
	gtk_entry_set_text(GTK_ENTRY(opt_value), "");

	/* for eth 802.3 */
	option_menu = lookup_widget("optionmenu6");
	gtk_combo_box_set_active (GTK_COMBO_BOX (option_menu), 3);
	opt_value = lookup_widget("L_pid");
	gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
	gtk_entry_set_text(GTK_ENTRY(opt_value), "");

	/* set the correct notebooks */
	nt2 = lookup_widget("notebook2");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt2), 2);
	nt4 = lookup_widget("notebook4");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 6);

}


void
on_ver_II_bt_toggled                   (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt1;
	GtkWidget *fr7;
	nt1 = lookup_widget("notebook_ethtype");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt1), 0);
	fr7 = lookup_widget("frame7");
	gtk_widget_set_sensitive(fr7, FALSE);

}


void
on_802_3_bt_toggled                    (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt1;
	GtkWidget *fr7;
	nt1 = lookup_widget("notebook_ethtype");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt1), 1);
	fr7 = lookup_widget("frame7");
	gtk_widget_set_sensitive(fr7, TRUE);

}


void
on_802_1q_bt_clicked                   (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *fr6;
	fr6 = lookup_widget("frame6");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(button)))
		gtk_widget_set_sensitive(fr6, TRUE);
	else
		gtk_widget_set_sensitive(fr6, FALSE);
}


void
on_L_8023_llc_tbt_toggled              (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *l_oui, *l_pid, *lbl_oui, *lbl_pid, *opt;
	l_oui = lookup_widget("L_oui");
	l_pid = lookup_widget("L_pid");
	lbl_oui = lookup_widget("label_oui");
	lbl_pid = lookup_widget("label_pid");
	lbl_pid = lookup_widget("label_pid");
	opt = lookup_widget("optionmenu6");
	gtk_entry_set_text(GTK_ENTRY(l_oui), "");
	gtk_entry_set_text(GTK_ENTRY(l_pid), "");
	gtk_widget_set_sensitive(l_oui, FALSE);
	gtk_widget_set_sensitive(l_pid, FALSE);
	gtk_widget_set_sensitive(lbl_oui, FALSE);
	gtk_widget_set_sensitive(lbl_pid, FALSE);
	gtk_widget_set_sensitive(opt, FALSE);

}


void
on_L_8023_llcsnap_tbt_toggled          (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *l_oui, *l_pid, *lbl_oui, *lbl_pid, *opt;
	gint index;

	l_oui = lookup_widget("L_oui");
	l_pid = lookup_widget("L_pid");
	lbl_oui = lookup_widget("label_oui");
	lbl_pid = lookup_widget("label_pid");
	opt = lookup_widget("optionmenu6");

	gtk_widget_set_sensitive(l_oui, TRUE);
	gtk_widget_set_sensitive(l_pid, TRUE);
	gtk_widget_set_sensitive(lbl_oui, TRUE);
	gtk_widget_set_sensitive(lbl_pid, TRUE);
	gtk_entry_set_text(GTK_ENTRY(l_oui), "000000");
	index = gtk_combo_box_get_active (GTK_COMBO_BOX (opt));
	switch (index) {
		case 1: {
			gtk_entry_set_text(GTK_ENTRY(l_pid), "86DD");
			break;
			}
		case 2: {
			gtk_entry_set_text(GTK_ENTRY(l_pid), "0806");
			break;
			}
		case 3: {
			gtk_entry_set_text(GTK_ENTRY(l_pid), "");
			break;
			}
		default:
			gtk_entry_set_text(GTK_ENTRY(l_pid), "0800");
	}

	gtk_widget_set_sensitive(opt, TRUE);

}


void
on_exit1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	gtk_main_quit();

}


void
on_about1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	show_about_dialog();
}


void
on_window1_destroy                     (GtkWidget       *object,
                                        gpointer         user_data)
{
	gtk_main_quit();
}


void
on_fileselection1_destroy              (GtkWidget       *object,
                                        gpointer         user_data)
{
	file_menu = NULL;
}


/* button1 is the load button, so what this function will do depends on who called it: 
   it can be one of the 4 basic windows: builder, gen-b, gen-s or gen-k. 
   And there can be a call for this window from each of these windows too.
*/
void
on_ok_button1_clicked                  (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *notbk;
	gint page;
	FILE *file_p;
	gchar *fname /* , *fname2 */;
	char buff[101];

	fname = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(lookup_widget("fileselection1"))));
	//fname2 = g_strdup(gtk_entry_get_text(GTK_ENTRY(GTK_FILE_SELECTION (user_data)->selection_entry)));

	if((file_p = fopen(fname, "r")) == NULL) { 
                //printf("can not open file for reading\n");
                error("Error: can't open file for reading!");
                return;
        }
	
	/* now who called this function */
	switch (load_select_nr) {
		case 1: { /* this is the toolbar load button, we need to know which notebook is open */
			notbk = lookup_widget("notebook1");
        		page =  gtk_notebook_get_current_page(GTK_NOTEBOOK(notbk));

        		if (page == 0) { /* so we have the build notebook open */
				
				if (load_data(btx, file_p, 1, 1) == -1) {
					/* calling previous function with last argument =1 means loading for builder */
					error("Error: wrong file format!");
					fclose(file_p);
			 		return;
				}
				break;
			}
			else if (page == 1) { /* it is the send build generator */

				if (load_gen_b_data(btx, file_p) == -1) {
					error("Error: wrong file format!");
					fclose(file_p);
			 		return;
				}
				break;
			}

			/* page with sequence generator is open */
			else if (page == 2) { /* it is the send build generator */

				if (load_gen_s_data(btx, file_p) == -1) {
					error("Error: wrong file format!");
					fclose(file_p);
			 		return;
				}
				break;
			}
			else if (page == 3) { /* it is the send pcap file generator */

				if (load_data(btx, file_p, 2, MAXNUMLOADPACKETS) == -1) {
					error("Error: wrong file format!");
					fclose(file_p);
			 		return;
				}
				break;
			}
		}
		/* next are the select buttons on the gen-s window */
		case 2: ;
		case 3: ;
		case 4: ;
		case 5: ;
		case 6: ;
		case 7: ;
		case 8: ;
		case 9: ;
		case 10: 
		case 11: {
			//if (check_if_file_is_packet(file_p) == -1) {
			if (load_data(btx, file_p, 1, 1) == -1) {
				error("Error: wrong file format!");
				fclose(file_p);
				return;
			}
        		gtk_entry_set_text(GTK_ENTRY(entry_field), fname);
			break;
		}			

	}		

	fclose(file_p);

	snprintf(buff, 100, "  Parameters loaded from file %s", fname);
	statusbar_text(btx, buff);

	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));

}


void
on_cancel_button1_clicked              (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


void
on_Load_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data)
{
	statusbar_text(button, "");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 1;
}


void
on_Save_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data)
{
	statusbar_text(button, "");

	if (save_file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(save_file_menu));
		gdk_window_raise(gtk_widget_get_window(save_file_menu));
		return;
	}

	save_file_menu = create_fileselection2();
	gtk_widget_show(save_file_menu);

	btx = button;

}


/* pressing the ok button in the save dialog causes us to be here */
void
on_ok_button2_clicked                  (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *notbk;
	gint page;
	gchar *fname;
	FILE *file_p;
	char buff4[101];

	/* hm, first we should decide, what are we going to save: a packet, send_built parameters,
	 * send_sequence parameters or send kernel parameters. I last three cases we only save
	 * the values and not also the packets themself (only the names of the packet) 
	 * so let's check which notebook is open */

	notbk = lookup_widget("notebook1");
        page =  gtk_notebook_get_current_page(GTK_NOTEBOOK(notbk));

	fname = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(lookup_widget("fileselection2"))));
	
	/* lets check if the file exists and we don't allow to overwrite it
	 * is there any way to do this in a more elegant manner? */
	//if((file_p = fopen(fname, "r")) != NULL) { /* could be also some other failure??? */
	//	error("Error: wrong file name, file already exists!");
	//	return;
	//}
	
	if((file_p = fopen(fname, "w")) == NULL) {
		error("Error: can not open file for saving");
		return;
	}


	if (page == 0) { /* so we have the build notebook open, it means we save the packet */
		/* YYY ok, this is not yet implemented */
		/* you could also add possibility to save even with this button on??? */
		//bt1 = lookup_widget("auto_get_mac_cbt");
		//if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(bt1))) {
			//printf("Error: you can't save in a packet if auto get link layer is on!\n");
			//        error("Error: you can't save in a packet if auto get link layer is on!");
			//        return;
		//}

	        if (save_packet(btx, user_data, file_p) == -1) {
	                fclose(file_p);
			return;
	        }
	}

	else if (page == 1) { /* it is the send_built page */

	        if (save_gen_b(btx, file_p) == -1) {
	                fclose(file_p);
			return;
	        }
	}

	else if (page == 2) {

	        if (save_gen_s(btx, file_p) == -1) {
	                fclose(file_p);
			return;
	        }
	}

	else if (page == 3) {

	        if (save_gen_pcap(btx, file_p) == -1) {
	                fclose(file_p);
			return;
	        }
	}

	else
		return;

	fclose(file_p);
	snprintf(buff4, 100, "  Parameters saved in file %s", fname);
	statusbar_text(btx, buff4);

	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	//gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));

	return;
}


void
on_cancel_button2_clicked              (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));

}


void
on_fileselection2_destroy              (GtkWidget       *object,
                                        gpointer         user_data)
{
	save_file_menu = NULL;

}

/*
void
on_clist1_select_row	( GtkWidget *clist, gint row, gint column, GdkEventButton *event, gpointer data)
{
	GtkWidget *en_ip, *en_mac, *en_name;
	gchar *text_ip, *text_mac, *text_name;
	//gchar *textip, *textmac;

       	//textip = (gchar *)malloc(16*sizeof(gchar));
       	//textmac = (gchar *)malloc(18*sizeof(gchar));
	
	row_number = row;
	en_ip = lookup_widget("sel1_IP_entry");
	en_mac = lookup_widget("sel1_mac_entry");
	en_name = lookup_widget("entry153");
	gtk_clist_get_text(GTK_CLIST(clist), row, 0, &text_ip);
	gtk_clist_get_text(GTK_CLIST(clist), row, 1, &text_mac);
	gtk_clist_get_text(GTK_CLIST(clist), row, 2, &text_name);

	//strncpy(textip, text_ip, strlen(text_ip+1));
	//strncpy(textmac, text_mac, strlen(text_mac+1));
	
	gtk_entry_set_text(GTK_ENTRY(en_ip), text_ip);
	gtk_entry_set_text(GTK_ENTRY(en_mac), text_mac);
	gtk_entry_set_text(GTK_ENTRY(en_name), text_name);
	
	//free(textip);
	//free(textmac);

	//return;
}
*/

void
on_sel1_add_bt_clicked                 (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *clist, *en_ip, *en_mac, *en_name, *en_ipv6;
	gchar *en_ip_t, *en_mac_t, *en_name_t, *en_ipv6_t;
	gchar *text_ip, *text_mac, *text_name, *text_ipv6;
	gchar *tmp[4];
	//gint number;
	GtkTreeModel *treestore;
	GtkTreeIter toplevel;
	
	clist = lookup_widget("clist1");
	treestore = gtk_tree_view_get_model(GTK_TREE_VIEW(clist));

        en_ip = lookup_widget("sel1_IP_entry");
        en_ipv6 = lookup_widget("entry205");
        en_mac = lookup_widget("sel1_mac_entry");
	en_name = lookup_widget("entry153");
	
	/* is there any other elegant way to get the row number but with global variable? */
	en_ip_t = (char *)gtk_entry_get_text(GTK_ENTRY(en_ip));
	en_ipv6_t = (char *)gtk_entry_get_text(GTK_ENTRY(en_ipv6));
	en_mac_t = (char *)gtk_entry_get_text(GTK_ENTRY(en_mac));
	en_name_t = (char *)gtk_entry_get_text(GTK_ENTRY(en_name));

	/* we still have the value of the row number, so we can check wheather this is
	 * the same as in the entry fields. so in case the user selects an entry and then 
	 * presses add button we won't get duplicated entries */
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(clist));
	GtkTreeIter iter;
	gtk_tree_selection_get_selected(selection,&treestore,&iter);
	gtk_tree_model_get(treestore,&iter,0,&text_ip,1,&text_ipv6,2,&text_mac,3,&text_name,-1);	

	if ( (strlen(en_ip_t) == 0) && (strlen(en_ipv6_t) == 0) && (strlen(en_mac_t) == 0) )
		return;

	if ( (strcmp(en_ip_t, text_ip) == 0) && (strcmp(en_mac_t, text_mac) == 0) && 
			 (strcmp(en_ipv6_t, text_ipv6) == 0)	&& (strcmp(en_name_t, text_name) == 0)) {
		//printf("values are the same, we don't insert them!\n");
		error("Error: values are the same, we don't insert them!");
		return;
	}
	/* now we have to check if the values are ok */

	if ( (strlen(en_ip_t) != 0) && (check_ip_address(en_ip_t) == -1) ) {
		//printf("wrong ip entry in address list\n");
		error("Error: wrong ip entry in address list");
		return;
	}
	
	if ( (strlen(en_ipv6_t) != 0) && (check_ipv6_address(en_ipv6_t, 0) == -1) ) {
		//printf("wrong ip entry in address list\n");
		error("Error: wrong ipv6 entry in address list");
		return;
	}
	if ( (strlen(en_mac_t) != 0) && (check_mac_address(en_mac_t) == -1) ) {
		//printf("wrong mac entry in address list\n");
		error("Error: wrong mac entry in address list");
		return;
	}
	
       	tmp[0]= (gchar *)malloc(16*sizeof(gchar));
       	tmp[1]= (gchar *)malloc(40*sizeof(gchar));
       	tmp[2]= (gchar *)malloc(18*sizeof(gchar));
       	tmp[3]= (gchar *)malloc(50*sizeof(gchar));
	
	strcpy(tmp[0], en_ip_t);
	strcpy(tmp[1], en_ipv6_t);
	strcpy(tmp[2], en_mac_t);
	strcpy(tmp[3], en_name_t);
	
	gtk_tree_store_append(GTK_TREE_STORE(treestore),&toplevel,NULL);
	gtk_tree_store_set(GTK_TREE_STORE(treestore),&toplevel,0,tmp[0],1,tmp[1],2,tmp[2],3,tmp[3],-1);
	
	free(tmp[0]);
	free(tmp[1]);
	free(tmp[2]);
	free(tmp[3]);
		
}

void
on_sel1_delete_bt_clicked              (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *clist;
	
	GtkTreeModel *treestore;
        gchar *path;

        clist = lookup_widget("clist1");
        treestore = gtk_tree_view_get_model(GTK_TREE_VIEW(clist));
	
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(clist));
        GtkTreeIter iter;
	gtk_tree_selection_get_selected(selection,&treestore,&iter);

	path = gtk_tree_model_get_string_from_iter(treestore,&iter);
	if (*path != '0') {
		gtk_tree_store_remove(GTK_TREE_STORE(treestore),&iter);

		gtk_tree_model_get_iter_first(treestore,&iter);

		gtk_tree_selection_select_iter(selection,&iter);
	}

	g_free(path);
	
}


void
on_sel1_ok_bt_clicked                  (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *clist; // *en_ip, *en_mac;
	gchar *en_ip_t, *en_ipv6_t, *en_mac_t;
	gchar *text_ip, *text_ipv6, *text_mac, *text_name;
	gchar temp[100];
	FILE *fp;
	int i;
	
	/* so we want to insert the choosen values into the entry mac field.
	 * we have to check again, that the values are correct
	 * if they are not a warning should pop up and the window should stay open
	 * if they are ok, then the value is inserted and we try to write in the file */
	GtkTreeModel *treestore;
        //GtkTreeIter toplevel;

        clist = lookup_widget("clist1");
        treestore = gtk_tree_view_get_model(GTK_TREE_VIEW(clist));
	
	GtkTreeSelection *selection = gtk_tree_view_get_selection(GTK_TREE_VIEW(clist));
        GtkTreeIter iter;
        gtk_tree_selection_get_selected(selection,&treestore,&iter);
        gtk_tree_model_get(treestore,&iter,0,&en_ip_t,1,&en_ipv6_t,2,&en_mac_t,-1);	
	
	/* we need to access the L_dst_mac or L_src_mac entry in the main window! 
	 * that is why we putted it static global before */
	if (MAC_yes == TRUE) {
		if (check_mac_address(en_mac_t) == -1) {
			//printf("wrong mac entry in address list\n");
			error("Error: wrong mac entry in address list");
			return;
		}
		else
			gtk_entry_set_text(GTK_ENTRY(entry_field), en_mac_t);
	}

	/* in case we need to insert the IP value as well
	 * this is in case of an arp packet or ip packet, so we check the IP_yes value */
	if (IP_yes == TRUE) {
		if (check_ip_address(en_ip_t) == -1) { // ---
			//printf("wrong ip entry in address list\n");
			error("Error: wrong ip entry in address list");
			return;
		}
		else
			gtk_entry_set_text(GTK_ENTRY(entry_field_ip), en_ip_t);
	}
	/* in case we need to insert the IP value as well
	 * this is in case of an arp packet or ip packet, so we check the IP_yes value */
	else if (IPv6_yes == TRUE) {
		if (check_ipv6_address(en_ipv6_t, 0) == -1) { // ---
			//printf("wrong ip entry in address list\n");
			error("Error: wrong ipv6 entry in address list");
			return;
		}
		else
			gtk_entry_set_text(GTK_ENTRY(entry_field_ipv6), en_ipv6_t);
	}


	/* we need to reopen the file with datebase and overwrite it with
	 * the values in the clist field */
	if((fp = fopen(address_filename, "w")) == NULL) { /* could be also some other failure??? */
		//printf("file %s with database can't be opened!\n", address_filename);
		snprintf(temp, 100, "file %s with database can't be opened", address_filename);
		error(temp);
		/* YYY we could call a function where we could select the database file */
		return;
	}
	//GtkTreeIter iter2;
	gtk_tree_model_get_iter_first(treestore,&iter);
	for(i=0; ; i++) {
		gtk_tree_model_get(treestore,&iter,0,&text_ip,1,&text_ipv6,2,&text_mac,3,&text_name,-1);
		fputs(text_ip, fp);
		fputc(44, fp);
		fputs(text_ipv6, fp);
		fputc(44, fp);
		fputs(text_mac, fp);
		fputc(44, fp);
		fputs(text_name, fp);
		fputc(10, fp);
		if (gtk_tree_model_iter_next(treestore,&iter) == FALSE)
			break;
	}
	
	fclose(fp);
		
	gtk_grab_remove(GTK_WIDGET(selection1_dialog));
	gtk_widget_destroy(GTK_WIDGET(selection1_dialog));
	
}


void
on_sel1_cancel_bt_clicked              (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));

}


void
on_sel1_dialog_destroy                 (GtkWidget       *object,
                                        gpointer         user_data)
{
	selection1_dialog = NULL;
}


void
on_L_dst_select_bt_clicked             (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("L_dst_mac");
	IP_yes = FALSE;
	MAC_yes = TRUE;
	selection_dialog_show(button, user_data);
}


void
on_L_src_select_bt_clicked             (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("L_src_mac");
	IP_yes = FALSE;
	MAC_yes = TRUE;
	selection_dialog_show(button, user_data);

}

	
/* this one shows the addresslist dialog. it tries to open a file with addresses. It should return an error in case of file error or if the contents of the file does not hold the specified structure */
void
selection_dialog_show			(GtkButton	*button,
					gpointer user_data)
{
	
	FILE *fp;
	gchar *row[4], tmp[130] /*, temp[100]*/;
	int i=0, ch, first = 0, second = 0, third=0;
	GtkTreeStore *treestore;
	GtkTreeIter toplevel;

	treestore = gtk_tree_store_new(4,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING,G_TYPE_STRING);

	/* if there is a dialog already open, reopen it */
	if (selection1_dialog != NULL){
		gdk_window_show(gtk_widget_get_window(selection1_dialog));
		gdk_window_raise(gtk_widget_get_window(selection1_dialog));
		return;
	}
	/* if we can't open file then we raise an error dialog. user has to change the 
	 * address_filename variable using the File-> Select database option */
	if((fp = fopen(address_filename, "r")) == NULL) { 
		error("Error: Can't open selected address database!\n\n"
				"Restore file \"addresslist\"\n"
				"File format: <IP address>,<IPv6 address>,<MAC address>,<Name>");
		return;
	}
	   
	/* create this dialog */
	selection1_dialog = create_sel1_dialog();

	/* resrve place for ip address, mac address and name, and ipv6 address */
       	row[0]= (gchar *)malloc(16*sizeof(gchar));
       	row[1]= (gchar *)malloc(40*sizeof(gchar));
       	row[2]= (gchar *)malloc(18*sizeof(gchar));
       	row[3]= (gchar *)malloc(50*sizeof(gchar));

	/* now we have to append the saved values: */
	/* we make following presumption: all entries must be in following format:
	 * xxx.xxx.xxx.xxx,xx:xx:xx:xx:xx:xx,name
	 * that means first there is IP in dot format and then mac address with : and name in the end 
	 * there can be an entry only with either ip or mac address and without name. 
	 *  new lines and comments starting with # are allowed */
	
	for(;;) {
		/* we read the whole line and remember where the comma is 
		 * first is the place of the comma between ip and mac address
		 * second ipv6, third is the variable holding the position between mac address and name 
		 * the line can have max 122 characters: 15 for ip , 40 for ipv6, 18 for mac and 50 for name 
		 * commas are obligatory */
		for (i=1, first = 0, second = 0, third=0; (ch=getc(fp)) != '\n' && i<122 && ch != EOF ;i++ ) {
			if (ch == ',')  {
				if (first == 0)
					first = i;
				else if (second == 0)
					second = i;
				else if (third == 0)
					third = i;
			}
			tmp[i-1] = ch;
		}
		tmp[i-1] = '\0';
	
		/* if first and second and third are == 0 and ch== '\n' - new line, ok, skip this */  
		if ( (first==0) && (second==0) && (third==0) && (ch == '\n') && (i==1) ) 
			continue;
		
		/* we also allow comments lines starting with # */
		if ( (i>1) && (tmp[0] == '#') ) 
			continue;
		
		/* first > 16 - ip address can not be longer then 15 char including points
		 * second - first (mac address) exactly 18 char including : or 1 if without it
		 * second - i > 50 - name can only have max 50 chars 
		 * if first and second are == 0 and i>0 there was no commas -> error 
		 * */
		if (   ( (first>16) || ((second-first)>40) || ((third-second)>18) || ((i-third)>50) ) ||
			( (first==0) && (second==0) && (i>1))   ) {
			error("Error: Selected address database has wrong format!\n\n"
				"Restore file \"addresslist\"\n\n"
				"File format: <IP address>,<IPv6 address>,<MAC address>,<Name>");
			free(row[0]);
			free(row[1]);
			free(row[2]);
			free(row[3]);
			fclose(fp);
			selection1_dialog = NULL;
			return;
		}
		
		if (ch == EOF)
			break;
		
		tmp[first-1] = '\0';
		tmp[second-1] = '\0';
		tmp[third-1] = '\0';
	
		strncpy(row[0], tmp, first );
		strncpy(row[1], &tmp[first], (second-first));
		strncpy(row[2], &tmp[second], (third-second));
		strncpy(row[3], &tmp[third], (i-third));

		if ( (check_ip_address(row[0]) == -1) && (strlen(row[0]) !=0) ) {
			//printf("wrong ip entry in address list\n");
			error("Error: Wrong IP entry in address list!\n\n"
				"Restore file \"addresslist\"\n\n"
				"File format: <IP address>,<IPv6 address>,<MAC address>,<Name>");
			free(row[0]);
			free(row[1]);
			free(row[2]);
			free(row[3]);
			fclose(fp);
			selection1_dialog = NULL;
			return;
		}
		
		if ( (check_ipv6_address(row[1], 0) == -1) && (strlen(row[1]) !=0) ) {
			//printf("wrong ip entry in address list\n");
			error("Error: Wrong IPv6 entry in address list!\n\n"
				"Restore file \"addresslist\"\n\n"
				"File format: <IP address>,<IPv6 address>,<MAC address>,<Name>");
			free(row[0]);
			free(row[1]);
			free(row[2]);
			free(row[3]);
			fclose(fp);
			selection1_dialog = NULL;
			return;
		}
		
		if ( (check_mac_address(row[2]) == -1) && (strlen(row[2]) !=0) ) {
			//printf("wrong mac entry in address list\n");
			error("Error: Wrong MAC entry in address list\n\n"
				"Restore file \"addresslist\"\n\n"
				"File format: <IP address>,<IPv6 address>,<MAC address>,<Name>");
			free(row[0]);
			free(row[1]);
			free(row[2]);
			free(row[3]);
			fclose(fp);
			selection1_dialog = NULL;
			return;
		}
		gtk_tree_store_append(treestore,&toplevel,NULL);
		gtk_tree_store_set(treestore,&toplevel,0,row[0],1,row[1],2,row[2],3,row[3],-1);				

	}	
		
	free(row[0]);
	free(row[1]);
	free(row[2]);
	free(row[3]);

	gtk_widget_show(selection1_dialog);

	// GtkTreeView ...

	GtkTreeViewColumn *stolpec;
	GtkCellRenderer *renderer;

	stolpec = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(stolpec,"IPv4 address");
	gtk_tree_view_append_column(GTK_TREE_VIEW(lookup_widget("clist1")),stolpec);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(stolpec,renderer,TRUE);
	gtk_tree_view_column_add_attribute(stolpec,renderer,"text",0);

	stolpec = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(stolpec,"IPv6 address");
	gtk_tree_view_append_column(GTK_TREE_VIEW(lookup_widget("clist1")),stolpec);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(stolpec,renderer,TRUE);
	gtk_tree_view_column_add_attribute(stolpec,renderer,"text",1);

	stolpec = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(stolpec,"MAC value");
	gtk_tree_view_append_column(GTK_TREE_VIEW(lookup_widget("clist1")),stolpec);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(stolpec,renderer,TRUE);
	gtk_tree_view_column_add_attribute(stolpec,renderer,"text",2);

	stolpec = gtk_tree_view_column_new();
	gtk_tree_view_column_set_title(stolpec,"Name");
	gtk_tree_view_append_column(GTK_TREE_VIEW(lookup_widget("clist1")),stolpec);
	renderer = gtk_cell_renderer_text_new();
	gtk_tree_view_column_pack_start(stolpec,renderer,TRUE);
	gtk_tree_view_column_add_attribute(stolpec,renderer,"text",3);

	GtkTreeModel *model = GTK_TREE_MODEL(treestore);
	gtk_tree_view_set_model(GTK_TREE_VIEW(lookup_widget("clist1")),model);
	GtkTreeIter iter;
	gtk_tree_model_get_iter_first(model,&iter);
	g_object_unref(model);
	gtk_tree_selection_set_mode(gtk_tree_view_get_selection(GTK_TREE_VIEW(lookup_widget("clist1"))),GTK_SELECTION_SINGLE);
	gtk_tree_selection_select_iter(gtk_tree_view_get_selection(GTK_TREE_VIEW(lookup_widget("clist1"))),&iter);
	// ...
	
	fclose(fp);

}


void
on_auto_get_mac_cbt_clicked            (GtkButton       *button,
                                        gpointer         user_data)
{
	int s;
	struct ifreq buffer;
	struct arpreq       areq;
	struct sockaddr_in *sin;
	struct in_addr      ipaddr;
	char tmp7[20];
	char tmp8[20];

	GtkWidget *source_mac, *destination_mac, *destination_ip, *ipv4_rdbt;
	gchar *destination_ip_t;
	
	source_mac = lookup_widget("L_src_mac");
	ipv4_rdbt = lookup_widget("ippkt_radibt");
	destination_mac = lookup_widget("L_dst_mac");
	destination_ip = lookup_widget("entry37");
	destination_ip_t = (char *)gtk_entry_get_text(GTK_ENTRY(destination_ip));

	if (!gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(ipv4_rdbt))) {
		error("Auto mode works only for IPv4!");
		return;
	}

	/* first find the mac of local interface */
	s = socket(PF_INET, SOCK_DGRAM, 0);
	memset(&buffer, 0x00, sizeof(buffer));
	strcpy(buffer.ifr_name, iftext);
	ioctl(s, SIOCGIFHWADDR, &buffer);

 	close(s);

       	snprintf(tmp7, 19, "%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", 
			(unsigned char)buffer.ifr_hwaddr.sa_data[0],
			(unsigned char)buffer.ifr_hwaddr.sa_data[1],
			(unsigned char)buffer.ifr_hwaddr.sa_data[2],
			(unsigned char)buffer.ifr_hwaddr.sa_data[3],
			(unsigned char)buffer.ifr_hwaddr.sa_data[4],
			(unsigned char)buffer.ifr_hwaddr.sa_data[5]);

	gtk_entry_set_text(GTK_ENTRY(source_mac), tmp7);

	/* find out the remote mac */
        /* Get an internet domain socket.  */
        if ((s = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
                error("Can't open socket");
                return;
        }

        /* Make the ARP request. 
        */
        memset(&areq, 0, sizeof(areq));
        sin = (struct sockaddr_in *) &areq.arp_pa;
        sin->sin_family = AF_INET;

	if (inet_aton(destination_ip_t, &ipaddr) == 0) {
                error("Error: bad destination IP");
                return;
        }

        sin->sin_addr = ipaddr;
        sin = (struct sockaddr_in *) &areq.arp_ha;
        sin->sin_family = ARPHRD_ETHER;

        strncpy(areq.arp_dev, iftext, 15);

        if (ioctl(s, SIOCGARP, (caddr_t) &areq) == -1) {
                error("Error: unable to make ARP request\nCheck destination IP and interface!");
 		close(s);
                return;
        }

 	close(s);

	snprintf(tmp8, 19, "%s",  ethernet_mactoa(&areq.arp_ha));
	gtk_entry_set_text(GTK_ENTRY(destination_mac), tmp8);

}


void
on_tcp_bt_toggled                      (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1, *opt1;
	
	nt4 = lookup_widget("notebook4");
	en1 = lookup_widget("entry34");
	opt1 = lookup_widget("optionmenu3");
	
	gtk_combo_box_set_active (GTK_COMBO_BOX (opt1), 3);
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 1);
	gtk_entry_set_text(GTK_ENTRY(en1), "6");
	gtk_editable_set_editable(GTK_EDITABLE(en1), FALSE);

}


void
on_udp_bt_toggled                      (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1, *opt1;
	nt4 = lookup_widget("notebook4");
	en1 = lookup_widget("entry34");
	opt1 = lookup_widget("optionmenu3");
	
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 0);
	gtk_combo_box_set_active (GTK_COMBO_BOX (opt1), 4);
	gtk_entry_set_text(GTK_ENTRY(en1), "17");
	gtk_editable_set_editable(GTK_EDITABLE(en1), FALSE);

}


void
on_icmp_bt_toggled                     (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1, *opt1;
	
	nt4 = lookup_widget("notebook4");
	en1 = lookup_widget("entry34");
	opt1 = lookup_widget("optionmenu3");
	
	gtk_combo_box_set_active (GTK_COMBO_BOX (opt1), 1);
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 2);
	gtk_entry_set_text(GTK_ENTRY(en1), "1");
	gtk_editable_set_editable(GTK_EDITABLE(en1), FALSE);

}


void
on_igmp_bt_toggled                     (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{

	GtkWidget *nt4, *en1, *opt1;
	
	nt4 = lookup_widget("notebook4");
	en1 = lookup_widget("entry34");
	opt1 = lookup_widget("optionmenu3");
	
	gtk_combo_box_set_active (GTK_COMBO_BOX (opt1), 2);
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 4);
	gtk_entry_set_text(GTK_ENTRY(en1), "2");
	gtk_editable_set_editable(GTK_EDITABLE(en1), FALSE);
}


void
on_ip_user_data_bt_toggled             (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1, *opt1;
	
	nt4 = lookup_widget("notebook4");
	en1 = lookup_widget("entry34");
	opt1 = lookup_widget("optionmenu3");
	
	gtk_combo_box_set_active (GTK_COMBO_BOX (opt1), 5);
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 3);
	gtk_entry_set_text(GTK_ENTRY(en1), "");
	gtk_editable_set_editable(GTK_EDITABLE(en1), TRUE);

}


void
on_L_optmenu1_bt_clicked               (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *opt_value;
	gint active_index;

	opt_value = lookup_widget ("L_ethtype");
	active_index = gtk_combo_box_get_active (combo_box);

	if (active_index == 0) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0800");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 1) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "86DD");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 2) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0806");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 3) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
	}
}


void
on_optionmenu6_clicked                 (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *opt_value;
	gint active_index;

	opt_value = lookup_widget ("L_pid");
	active_index = gtk_combo_box_get_active (combo_box);


	if (active_index == 0) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0800");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 1) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "86DD");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 2) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0806");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 3) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
	}
}



void
on_IPv6_rdbt_toggled                   (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt2;
	GtkWidget *nt4;
	GtkWidget *option_menu, *opt_value;
	GtkWidget *rb1, *rb2, *rb3 /*, *rb4*/;
	
	//cbt = lookup_widget("auto_get_mac_cbt");
	//gtk_widget_set_sensitive (cbt, TRUE);
	option_menu = lookup_widget("L_optmenu1_bt");
	opt_value = lookup_widget("L_ethtype");
	nt2 = lookup_widget("notebook2");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt2), 1);
	gtk_combo_box_set_active (GTK_COMBO_BOX (option_menu), 1);
	gtk_entry_set_text(GTK_ENTRY(opt_value), "86DD");
	gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);

	/* what is next page */
	rb1 = lookup_widget("radiobutton67");
	rb2 = lookup_widget("radiobutton68");
	rb3 = lookup_widget("radiobutton69");
	//rb4 = lookup_widget("radiobutton71");
	nt4 = lookup_widget("notebook4");

	//gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	//gtk_editable_set_editable(GTK_EDITABLE(opt_value2), FALSE);

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb1)))
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 0);
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb2)))
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 1);
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb3)))
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 5);
	else
		gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 3);
}


void
on_Build_button_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *nt1;
	
	nt1 = lookup_widget("notebook1");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt1), 0);

        nt1 = lookup_widget("Load_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Save_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Reset_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("button62");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Interface_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Send_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Stop_button");
	gtk_widget_set_sensitive(nt1, TRUE);

	statusbar_text(button, "  Builder window opened");
}


void
on_Gen_button_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *ntbk2, *ntbk4;
	GtkWidget *nt1;
        GtkWidget *text_e;
	GtkWidget *crc_value;
	GtkWidget *ckbt61, *ckbt51, *ckbt52, *ckbt54, *ckbt55;
	GtkWidget *ckbt56, *ckbt57, *ckbt60, *ckbt62, *ckbt63, *ckbt64, *ckbt65;
	GtkWidget *hb1508, *hb1510, *hb1511, *hb1512;

	unsigned long crc32;
	char str_crc32[9];
	char tmp[31000];
	guint i, j, m, page1, page2;
	
	//ckbt50 = lookup_widget ("checkbutton50");
	ckbt51 = lookup_widget ("checkbutton51");
	ckbt52 = lookup_widget ("checkbutton52");
	//ckbt53 = lookup_widget ("checkbutton53");
	ckbt54 = lookup_widget ("checkbutton54");
	ckbt55 = lookup_widget ("checkbutton55");
	ckbt56 = lookup_widget ("checkbutton56");
	ckbt57 = lookup_widget ("checkbutton57");
	//ckbt58 = lookup_widget ("checkbutton58");
	//ckbt59 = lookup_widget ("checkbutton59");
	ckbt60 = lookup_widget ("checkbutton60");
	ckbt61 = lookup_widget ("checkbutton61");
	ckbt62 = lookup_widget ("checkbutton62");
	ckbt63 = lookup_widget ("checkbutton63");
	ckbt64 = lookup_widget ("checkbutton64");
	ckbt65 = lookup_widget ("checkbutton65");
	hb1508 = lookup_widget ("hbox1508");
	hb1510 = lookup_widget ("hbox1510");
	hb1511 = lookup_widget ("hbox1511");
	hb1512 = lookup_widget ("hbox1512");

	ntbk2 = lookup_widget ("notebook2");
	ntbk4 = lookup_widget ("notebook4");
	nt1 = lookup_widget("notebook1");
	crc_value = lookup_widget("entry164");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt1), 1);
	
        nt1 = lookup_widget("Load_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Save_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Reset_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("button62");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Interface_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Send_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Stop_button");
	gtk_widget_set_sensitive(nt1, TRUE);

	statusbar_text(button, "  Gen-b window opened.");

	/* get access to the buffer of text field */
	text_e = lookup_widget("text5");
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e)); 

	show_error_dialog = 0;

	if (make_packet(button, user_data) == -1) {
        	//error("Packet contents is not ok!\n");
		snprintf(&tmp[0], 200, "\n\n                   Packet constructed in Builder is not ok!");
		gtk_entry_set_text(GTK_ENTRY(crc_value), "");
        }
	else {
		/* copy data to tmp field */
		for (i=0, j=0, m=1; j < number; m++, j++) {
			snprintf(&tmp[i], 31000, "%02x", packet[j]);
			i++; i++;
			/* we allow only 16 bytes in each row - looks nicer */
			if ((m % 16) == 0 && (m > 1)) {
				tmp[i]='\n';
				m = 0;
			}
			else
				tmp[i] = ' '; 
			i++;
		}
		tmp[i] = '\0';

		crc32 = get_crc32(packet, number);
		snprintf(str_crc32, 9, "%08lX", crc32);
		gtk_entry_set_text(GTK_ENTRY(crc_value), str_crc32);
	}
      
        /* insert the text in the text field */
	gtk_text_buffer_set_text(buffer,tmp,-1);      

	/* first set all the options to be not sensitive and then anable only valid */
	//gtk_widget_set_sensitive(ckbt50, FALSE); //we make (in)sensitive entire hbox
	gtk_widget_set_sensitive(ckbt51, FALSE);
	gtk_widget_set_sensitive(ckbt52, FALSE);
	//gtk_widget_set_sensitive(ckbt53, FALSE); // we make (in)sensitive entire hbox
	gtk_widget_set_sensitive(ckbt54, FALSE);
	gtk_widget_set_sensitive(ckbt55, FALSE);
	gtk_widget_set_sensitive(ckbt56, FALSE);
	gtk_widget_set_sensitive(ckbt57, FALSE);
	//gtk_widget_set_sensitive(ckbt58, FALSE);
	//gtk_widget_set_sensitive(ckbt59, FALSE);
	gtk_widget_set_sensitive(ckbt60, FALSE);
	gtk_widget_set_sensitive(ckbt61, TRUE); //we always have mac addresses
	gtk_widget_set_sensitive(ckbt62, FALSE);
	gtk_widget_set_sensitive(ckbt63, FALSE);
	gtk_widget_set_sensitive(ckbt64, FALSE);
	gtk_widget_set_sensitive(ckbt65, FALSE);
	gtk_widget_set_sensitive(hb1508, TRUE); // we always allow to change certain fields
	gtk_widget_set_sensitive(hb1510, TRUE); // we always allow to change certain fields
	gtk_widget_set_sensitive(hb1511, FALSE);
	gtk_widget_set_sensitive(hb1512, FALSE);

        /* we want to set correct options in send built change while sending option menu */
	page1 = gtk_notebook_get_current_page(GTK_NOTEBOOK(ntbk2));
	page2 = gtk_notebook_get_current_page(GTK_NOTEBOOK(ntbk4));

	//user defined, nothing to enable 
	/* instead of checking which "page" is active, it would be easier to chech the
	   ip_proto_in_use and l4_proto in use which protocols are active */
	if (page1 == 2)
		;
	//arp
	else if (page1 == 3) 
		gtk_widget_set_sensitive(ckbt60, TRUE);
	
	//if not arp or user defined, then we have ipv4 or ipv6 next header
	else {
		//ipv6
		if (page1 == 1) {
			gtk_widget_set_sensitive(hb1512, TRUE);
			//gtk_widget_set_sensitive(ckbt63, TRUE);
		}
		//ipv4
		else if (page1 == 0) {
			gtk_widget_set_sensitive(hb1511, TRUE);
			gtk_widget_set_sensitive(ckbt62, TRUE);
		}

		//now check what is the L4 header
		//udp
		if (page2 == 0) {
			gtk_widget_set_sensitive(ckbt52, TRUE);
			gtk_widget_set_sensitive(ckbt54, TRUE);
			gtk_widget_set_sensitive(ckbt55, TRUE);
			gtk_widget_set_sensitive(ckbt56, TRUE);
			gtk_widget_set_sensitive(ckbt57, TRUE);
			gtk_widget_set_sensitive(ckbt64, TRUE);
		}	
		//tcp
		else if (page2 == 1) {
			gtk_widget_set_sensitive(ckbt51, TRUE);
			gtk_widget_set_sensitive(ckbt65, TRUE);
		}
		//icmp
		else if (page2 == 2) {
			gtk_widget_set_sensitive(ckbt63, TRUE);
		}
		else if (page2 == 5) {
			gtk_widget_set_sensitive(ckbt63, TRUE);
		}
		else
			//other
			;
	
	}
	
	show_error_dialog = 1;
}


void
on_Gen_s_bt_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *nt1;
	
	nt1 = lookup_widget("notebook1");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt1), 2);

        nt1 = lookup_widget("Load_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Save_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Reset_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("button62");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Interface_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Send_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Stop_button");
	gtk_widget_set_sensitive(nt1, TRUE);
	statusbar_text(button, "  Gen-s window opened");
	//on_button87_clicked(button, user_data);
}


void
on_Gen_k_bt_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *nt1;
	
	nt1 = lookup_widget("notebook1");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt1), 3);
}

void
on_Send_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data)
{

	if (send_packet(button, user_data) == -1) {
		//printf("problems sending packet; send_packet() returned -1\n");
		return;
	}
}


void
on_optionmenu3_clicked                 (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *opt_value;
	gint active_index;

	opt_value = lookup_widget ("entry34");
	active_index = gtk_combo_box_get_active (combo_box);

	if (active_index == 0) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 1) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "1");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 2) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "2");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 3) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "6");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 4) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "17");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 5) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
	}
}


void
on_ip_header_cks_cbt_toggled           (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry35");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_button24_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field_ip = lookup_widget("entry38");
	IP_yes = TRUE;
	MAC_yes = FALSE;
	selection_dialog_show(button, user_data);

}


void
on_button25_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field_ip = lookup_widget("entry37");
	IP_yes = TRUE;
	MAC_yes = FALSE;
	selection_dialog_show(button, user_data);

}


void
on_checkbutton13_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry52");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_checkbutton4_toggled                (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry43");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_optionmenu4_clicked                 (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *opt_value, *ntbk5;
	gint active_index;

	opt_value = lookup_widget ("entry57");
	ntbk5 = lookup_widget ("notebook5");
	active_index = gtk_combo_box_get_active (combo_box);

	if (active_index == 0) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "00");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 0);
	}
	else if (active_index == 1) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "03");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 2);
	}
	else if (active_index == 2) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "08");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 5);
	}
	else  {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 1);
	}
}


void
on_checkbutton16_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry63");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_optionmenu5_clicked                 (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *opt_value;
	gint active_index;

	opt_value = lookup_widget ("entry58");
	active_index = gtk_combo_box_get_active (combo_box);
	
	if (active_index == 0) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "00");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 1) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "01");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 2) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "02");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 3) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "03");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 4) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "04");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 5) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "05");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 6) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "06");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 7) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "07");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 8) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "08");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 9) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "09");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 10) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0a");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 11) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0b");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 12) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0c");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 13) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0d");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 14) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0e");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 15) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0f");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 16) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
	}
}


void
on_checkbutton15_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry59");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_checkbutton20_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry77");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_checkbutton2_toggled                (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry5");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_N_apply_pattern_clicked             (GtkButton       *button,
                                        gpointer         user_data)
{
        GtkWidget *en1, *en2, *text_e;
	long length;
	char *en1_t, *en2_t;
	char tmp[31000], ch1, ch2;
	guint i, j;
	
        en1 = lookup_widget("entry79");
        en2 = lookup_widget("entry80");
	text_e = lookup_widget("text1");
	en1_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));
	en2_t = (char *)gtk_entry_get_text(GTK_ENTRY(en2));

	length = strtol(en2_t, (char **)NULL, 10);

	/* we chech the pattern */
        if (char2x(en1_t) == -1) {
                //printf("Error: nok network pattern field\n");
                error("Error: nok network pattern field");
                return;
        }

	/* get access to the buffer of the text field */
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e));

	/* apply the new pattern */
	ch1 = *en1_t;
	en1_t++;
	ch2 = *en1_t;

	/* copy data to tmp field */
	for (i=0, j=1; (i < (length*3) ); i++, j++) {
		tmp[i] = ch1; i++;
		tmp[i] = ch2; i++;
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


void
on_N_select_payload_clicked            (GtkButton       *button,
                                        gpointer         user_data)
{

}


void
on_button33_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("A_sendermac");
	entry_field_ip = lookup_widget("A_senderip");
	IP_yes = TRUE;
	MAC_yes = TRUE;
	selection_dialog_show(button, user_data);

}


void
on_button34_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
        GtkWidget *s_mac, *s_ip;
	
        s_mac = lookup_widget("A_sendermac");
        s_ip = lookup_widget("A_senderip");
	
	gtk_entry_set_text(GTK_ENTRY(s_mac), "00:E0:00:98:60:13");
	gtk_entry_set_text(GTK_ENTRY(s_ip), "10.1.4.107");

}


void
on_button35_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("A_targetmac");
	entry_field_ip = lookup_widget("A_targetip");
	IP_yes = TRUE;
	MAC_yes = TRUE;
	selection_dialog_show(button, user_data);

}


void
on_button36_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
        GtkWidget *t_mac, *t_ip;
	
        t_mac = lookup_widget("A_targetmac");
        t_ip = lookup_widget("A_targetip");

	gtk_entry_set_text(GTK_ENTRY(t_mac), "FF:FF:FF:FF:FF:FF");
	gtk_entry_set_text(GTK_ENTRY(t_ip), "0.0.0.0");
}




void
on_button37_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field_tos = lookup_widget("entry28");

	if (tos_dialog_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(tos_dialog_menu));
		gdk_window_raise(gtk_widget_get_window(tos_dialog_menu));
		return;
	}
	tos_dialog_menu = create_tos_dialod();
	gtk_widget_show(tos_dialog_menu);
}


void
on_button39_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
        GtkWidget *en1, *en2, *text_e;
	long length;
	char *en1_t, *en2_t;
	char tmp[31000], ch1, ch2;
	guint i, j;
	
        en1 = lookup_widget("entry82");
        en2 = lookup_widget("entry83");
	text_e = lookup_widget("text2");
	en1_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));
	en2_t = (char *)gtk_entry_get_text(GTK_ENTRY(en2));

	/* we chech the pattern */
        if (char2x(en1_t) == -1) {
                //printf("Error: transport layer user defined pattern field\n");
                error("Error: transport layer user defined pattern field");
                return;
        }

	length = strtol(en2_t, (char **)NULL, 10);

	/* get access to the buffer of the text field */
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e)); 

	/* apply the new pattern */
	ch1 = *en1_t;
	en1_t++;
	ch2 = *en1_t;

	/* copy data to tmp field */
	for (i=0, j=1; (i < (length*3) ); i++, j++) {
		tmp[i] = ch1; i++;
		tmp[i] = ch2; i++;
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


void
on_button38_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{

}


void
on_checkbutton21_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry29");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_checkbutton3_toggled                (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("entry42");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_Interface_button_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *combo;

	struct ifconf       Ifc;
	struct ifreq        IfcBuf[512];
	//struct ifreq        *pIfr;
	struct if_nameindex *pif;
	struct if_nameindex *head;
	head = pif = if_nameindex();
	//int num_ifreq;
	int fd, length;
	char buff[1000];
	char *ptr;

	statusbar_text(button, "");

	if (interface_dialog_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(interface_dialog_menu));
		gdk_window_raise(gtk_widget_get_window(interface_dialog_menu));
		return;
	}
	interface_dialog_menu = create_interface_dialog();

	combo = lookup_widget("combo1");

	Ifc.ifc_len = sizeof(IfcBuf);
	Ifc.ifc_buf = (char *) IfcBuf;

	if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
		//printf("socket error\n");
		error("Error: socket error");
		return;
	}

	if ( ioctl(fd, SIOCGIFCONF, &Ifc) < 0) {
		//printf("ioctl SIOCGIFCONF error\n");
		error("Error: ioctl SIOCGIFCONF error");
		return;
	}

	//num_ifreq = Ifc.ifc_len / sizeof(struct ifreq);

	ptr = buff;
	while (pif->if_index) {
		snprintf(ptr, 100, "%s", pif->if_name);
		gtk_combo_box_text_append_text(GTK_COMBO_BOX_TEXT(combo), ptr);
		ptr = ptr + strlen(pif->if_name) + 1;
		length = length + strlen(pif->if_name) + 1;
		pif++;
	}
       /*

	for ( pIfr = Ifc.ifc_req, i = 0, length = 0 ; i < num_ifreq; pIfr++, i++ ) {
		if ( (length + strlen(pIfr->ifr_name) + 1) < 100) {
			snprintf(ptr, 100, "%s", pIfr->ifr_name);
			glist = g_list_append(glist, ptr);
			ptr = ptr + strlen(pIfr->ifr_name) + 1;
			length = length + strlen(pIfr->ifr_name) + 1;
		}
		else
			break;
	}
	*/
	if_freenameindex(head);

	gtk_entry_set_text(GTK_ENTRY(gtk_bin_get_child(GTK_BIN(combo))), iftext);

	gtk_widget_show(interface_dialog_menu);

}


void
on_button50_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *combo;

	combo = lookup_widget("combo1");

	snprintf(iftext, 19, "%s", gtk_combo_box_text_get_active_text(GTK_COMBO_BOX_TEXT(combo)));

	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


void
on_button51_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));

}


void
on_interface_dialog_destroy            (GtkWidget       *object,
                                        gpointer         user_data)
{
	interface_dialog_menu = NULL;
}


void
on_button52_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


void
on_error_dialog_destroy                (GtkWidget       *object,
                                        gpointer         user_data)
{
	error_dialog_menu = NULL;
}

void error(gchar *error_type)
{
	GtkWidget *label;
	
	if ( show_error_dialog == 0)
		return;

	if (error_dialog_menu != NULL) {
		label = lookup_widget("label165");
		gtk_label_set_text(GTK_LABEL(label), error_type);
		gdk_window_show(gtk_widget_get_window(error_dialog_menu));
		gdk_window_raise(gtk_widget_get_window(error_dialog_menu));
		return;
	}
	else {
		error_dialog_menu = create_error_dialog();
		label = lookup_widget("label165");
		gtk_label_set_text(GTK_LABEL(label), error_type);
		gtk_widget_show(error_dialog_menu);
	}
}



void
on_udp_apply_pattern_button_clicked    (GtkButton       *button,
                                        gpointer         user_data)
{
        GtkWidget *en1, *en2, *text_e;
	long length;
	gchar *en1_t, *en2_t;
	char tmp[31000], ch1, ch2;
	guint i, j;
	
        en1 = lookup_widget("entry89");
        en2 = lookup_widget("entry90");
	text_e = lookup_widget("text3");
	en1_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));
	en2_t = (char *)gtk_entry_get_text(GTK_ENTRY(en2));

	/* we chech the pattern */
        if (char2x(en1_t) == -1) {
                //printf("Error: udp payload pattern field\n");
                error("Error: udp payload pattern field");
                return;
        }

	length = strtol(en2_t, (char **)NULL, 10);

	/* get access to buffer of the text field */
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e));	

	/* apply the new pattern */
	ch1 = *en1_t;
	en1_t++;
	ch2 = *en1_t;

	/* copy data to tmp field */
	for (i=0, j=1; (i < (length*3) ); i++, j++) {
		tmp[i] = ch1; i++;
		tmp[i] = ch2; i++;
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


void
on_udp_select_payload_button_clicked   (GtkButton       *button,
                                        gpointer         user_data)
{
	if (udp_payload_dialog != NULL) {
		gdk_window_show(gtk_widget_get_window(udp_payload_dialog));
		gdk_window_raise(gtk_widget_get_window(udp_payload_dialog));
		return;
	}

	entry_field_udp = lookup_widget("text3");

	udp_payload_dialog = create_udp_payload_dialog();
	gtk_widget_show(udp_payload_dialog);
}


void
on_rtp_apply_button_clicked            (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *freq_entry, *alaw_bt, /**ulaw_bt,*/ *length_entry, /**apply_bt,*/ *payload_entry;
	GtkWidget *amp;
	gint amp_index;
	gchar *freq_entry_t, *length_entry_t;
	int length, frequency;

	freq_entry = lookup_widget("entry104");
	length_entry = lookup_widget("entry106");
	payload_entry = lookup_widget("entry103");
	alaw_bt= lookup_widget("radiobutton33");
	//ulaw_bt = lookup_widget("radiobutton32");
	//apply_bt = lookup_widget("rtp_apply_button");
	amp = lookup_widget("optionmenu12");

	freq_entry_t = (char *)gtk_entry_get_text(GTK_ENTRY(freq_entry));
	length_entry_t = (char *)gtk_entry_get_text(GTK_ENTRY(length_entry));

	
	/* next we need the amplitude */
	amp_index = gtk_combo_box_get_active (GTK_COMBO_BOX (amp));

	/* frequency; there can be rubbish in this field */
        if (check_digit(freq_entry_t, strlen(freq_entry_t),
                                                "Error: apply frequency field values") == -1)
                                return;

        frequency = strtol(freq_entry_t, (char **)NULL, 10);
        if ( (frequency >= 4000 ) || (frequency < 0) ) {
                //printf("Error: RTP frequency range\n");
                error("Error: RTP frequency range ( 0 <= f < 3999 )");
                return;
        }

        /* length */
        if (check_digit(length_entry_t, strlen(length_entry_t),
                                                "Error: apply length field values") == -1)
                                return;

	/* length */
	length = strtol(length_entry_t, (char **)NULL, 10);
	if ( (length >= 1460 ) || (length <= 0) ) {
		//printf("Error: RTP length range\n");
		error("Error: RTP length range ( 0 < length < 1460 )");
		return;
	}

	/* call the function */
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(alaw_bt)))  {
		if (insert_frequency(1, frequency, length, payload_entry, amp_index) == 0) {
			//printf("Error: Problem inserting RTP alaw payload frequency\n");
			error("Error: Problem inserting RTP alaw payload frequency");
			return;
		}
	}
	else {
		if (insert_frequency(0, frequency, length, payload_entry, amp_index) == 0) {
			//printf("Error: Problem inserting RTP ulaw payload frequency\n");
			error("Error: Problem inserting RTP ulaw payload frequency");
			return;
		}
	}

}


void
on_udp_payload_dialog_destroy          (GtkWidget       *object,
                                        gpointer         user_data)
{
	udp_payload_dialog = NULL;	
}


void
on_cancel_rtp_bt_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
        gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


void
on_rtp_ok_bt_clicked                   (GtkButton       *button,
                                        gpointer         user_data)
{
	char tmp[31000], tmp2[31000];
	int ij = 0, i, j;
	GtkWidget *version, *csrc_nr, *payload_type, *seq_nr, *timestamp, *ssrc, *csrc, *extension;
	GtkWidget *padding_switch, *extension_switch, *marker_switch;
	GtkWidget *rtp_payload;
	gchar *vers_t, *csrc_nr_t, *payload_type_t, *seq_nr_t, *timestamp_t, *ssrc_t;
	gchar *csrc_t, *extension_t, *rtp_payload_t;
	int sum, intversion, intpadding, intmarker, intextension, intcsrc, inttype;
	guint16 intseq;
	guint32 inttimestamp, intssrc; 

	version = lookup_widget("entry91");
	csrc_nr = lookup_widget("entry92");
	payload_type = lookup_widget("entry102");
	seq_nr = lookup_widget("entry101");
	timestamp = lookup_widget("entry97");
	ssrc = lookup_widget("entry96");
	csrc = lookup_widget("entry98");
	extension = lookup_widget("entry99");
	padding_switch = lookup_widget("padding_switch");
	extension_switch = lookup_widget("extension_switch");
	marker_switch = lookup_widget("marker_switch");
	rtp_payload = lookup_widget("entry103");

	vers_t = (char *)gtk_entry_get_text(GTK_ENTRY(version));
	csrc_nr_t = (char *)gtk_entry_get_text(GTK_ENTRY(csrc_nr));
	payload_type_t = (char *)gtk_entry_get_text(GTK_ENTRY(payload_type));
	seq_nr_t = (char *)gtk_entry_get_text(GTK_ENTRY(seq_nr));
	timestamp_t = (char *)gtk_entry_get_text(GTK_ENTRY(timestamp));
	ssrc_t = (char *)gtk_entry_get_text(GTK_ENTRY(ssrc));
	csrc_t = (char *)gtk_entry_get_text(GTK_ENTRY(csrc));
	extension_t = (char *)gtk_entry_get_text(GTK_ENTRY(extension));
	rtp_payload_t = (char *)gtk_entry_get_text(GTK_ENTRY(rtp_payload));

	/* what numbers should we allow? only 2? */
	intversion = strtol(vers_t, (char **)NULL, 10);
	if ( (intversion > 3) || (intversion < 0) ) {
		//printf("Error: RTP version type\n");
		error("Error: RTP version type");
		return;
	}

	/* there can be rubbish in this field */
	if (check_digit(vers_t, strlen(vers_t), "Error: RTP version value") == -1)
		return;

	/* should we add paddind automaticaly or not? no we do not do it */
	if (gtk_switch_get_active(GTK_SWITCH(padding_switch)))
		intpadding = 1;
	else
		intpadding = 0;

	if (gtk_switch_get_active(GTK_SWITCH(extension_switch)))
		intextension = 1;
	else
		intextension = 0;

	/* what numbers should we allow? between 0 and 15? */
	intcsrc = strtol(csrc_nr_t, (char **)NULL, 10);
	if ( (intcsrc > 15) || (intcsrc < 0) ) {
		//printf("Error: RTP csrc count field\n");
		error("Error: RTP csrc count field");
		return;
	}

	/* there can be rubbish in this field */
	if (check_digit(csrc_nr_t, strlen(csrc_nr_t), "Error: rtp csrc value") == -1)
		return;

	/* first byte is version + padding + extension + csrc */
	tmp[ij] = c4((intversion*4 + intpadding*2 + intextension)); ij++;
	tmp[ij] = c4(intcsrc); ij++;

	/* next byte */	
	if (gtk_switch_get_active(GTK_SWITCH(marker_switch)))
		intmarker = 1;
	else
		intmarker = 0;

	inttype = strtol(payload_type_t, (char **)NULL, 10);
	if ( (inttype > 127) || (inttype < 0) ) {
		//printf("Error: RTP payload type number\n");
		error("Error: RTP payload type number");
		return;
	}

	/* there can be rubbish in this field */
        if (check_digit(payload_type_t, strlen(payload_type_t),
                                                "Error: rtp payload type value") == -1)
                                return;

	snprintf(&(tmp[ij]), 3, "%02x", (intmarker*128) + inttype);
	ij = ij + 2;
				
	/* next 2 bytes sequence number */	
	intseq = strtoul(seq_nr_t, (char **)NULL, 10);

	/* there can be rubbish in this field */
        if (check_digit(seq_nr_t, strlen(seq_nr_t), "Error: rtp sequence number value") == -1)
                                return;

	if ( atol(seq_nr_t) > 65535) {
                //printf("Error: rtp sequence number value\n");
                error("Error: rtp sequence number value");
                return ;
        }

	snprintf(&(tmp[ij]), 5, "%04x", intseq);
	ij = ij + 4;

	/* next 4 bytes timestamp */
	inttimestamp = strtoul(timestamp_t, (char **)NULL, 10);

	/* there can be rubbish in this field */
        if (check_digit(timestamp_t, strlen(timestamp_t), "Error: rtp timestamp value") == -1)
                                return;

	if ( atoll(timestamp_t) > 0xFFFFFFFF) {
		//printf("Error: rtp timestamp value\n");
		error("Error: rtp timestamp value");
		return ;
	}

	snprintf(&(tmp[ij]), 9, "%08x", inttimestamp);
	ij = ij + 8;

	/* next 4 bytes ssrc */
	intssrc = strtoul(ssrc_t, (char **)NULL, 10);

	/* there can be rubbish in this field */
        if (check_digit(ssrc_t, strlen(ssrc_t), "Error: rtp ssrc value") == -1)
                                return;

	if ( atoll(timestamp_t) > 0xFFFFFFFF) {
                //printf("Error: rtp ssrc value\n");
                error("Error: rtp ssrc value");
                return ;
        }

	snprintf(&(tmp[ij]), 9, "%08x", intssrc);
	ij = ij + 8;

	/* csrc identifiers */
	if ( (strlen(csrc_t)%8) != 0) {
		//printf("Error: rtp csrc identifiers field (length mod 8 should equal 0)\n");
		error("Error: rtp csrc identifiers field      \n(length mod 8 should equal 0)");
		return;
	}

	/* there can be rubbish in this field */
	if ( (strlen(csrc_t) == 0))
		;
        else if (check_hex(csrc_t, strlen(csrc_t), "Error: rtp crsc identifiers field") == -1)
                                return;

	strncpy(&tmp[ij], csrc_t, strlen(csrc_t));
	ij = ij + strlen(csrc_t);
	
	/* extension field */
	if ( (strlen(extension_t)%8) != 0) {
		//printf("Error: RTP extension field (length mod 8 should equal 0)\n");
		error("Error: rtp extension value      \n(length mod 8 should equal 0)");
		return;
	}

	/* there can be rubbish in this field */
	if ( (strlen(extension_t) == 0) )
		;
	else if (check_hex(extension_t, strlen(extension_t), "Error: rtp extension value") == -1)
                                return;

	strncpy(&tmp[ij], extension_t, strlen(extension_t));
	ij = ij + strlen(extension_t);
	
	if ( (strlen(rtp_payload_t)> 2920) || (strlen(rtp_payload_t)%2 != 0) ) {
		//printf("Error: RTP payload length\n");
		error("Error: RTP payload length");
		return;
	}
	strncpy(&tmp[ij], rtp_payload_t, strlen(rtp_payload_t));
	ij = ij + strlen(rtp_payload_t);
	
	/* copy data to tmp2 field */ 
	for (i=0, j=1, sum = 0; (sum < ij ); sum++, i++, j++) {
		tmp2[i] = tmp[sum]; i++; sum++;
		tmp2[i] = tmp[sum]; i++; 
		if ((j % 16) == 0 && (j > 1)) {
			tmp2[i]='\n';
			j = 0;
		}
		else
			tmp2[i] = ' '; 
	}
	tmp2[i] = '\0';
	
	/* get access to buffer of the text field */
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(entry_field_udp));

	/* insert the text in the text field */
	gtk_text_buffer_set_text(buffer,tmp2,-1);
	
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
        gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));

}


void
on_apply_tcp_pattern_bt_clicked        (GtkButton       *button,
                                        gpointer         user_data)
{
        GtkWidget *en1, *en2, *text_e;
	long length;
	gchar *en1_t, *en2_t;
	char tmp[31000], ch1, ch2;
	guint i, j;
	
        en1 = lookup_widget("entry107");
        en2 = lookup_widget("entry108");
	text_e = lookup_widget("text4");
	en1_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));
	en2_t = (char *)gtk_entry_get_text(GTK_ENTRY(en2));

	length = strtol(en2_t, (char **)NULL, 10);

	/* we chech the pattern */
        if (char2x(en1_t) == -1) {
                //printf("Error: tcp pattern field\n");
                error("Error: tcp pattern field");
                return;
        }

	/* get access to buffer of the text field */
	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e));

	/* apply the new pattern */
	ch1 = *en1_t;
	en1_t++;
	ch2 = *en1_t;

	/* copy data to tmp field */
	for (i=0, j=1; (i < (length*3) ); i++, j++) {
		tmp[i] = ch1; i++;
		tmp[i] = ch2; i++;
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


void
on_select_tpc_payload_bt_clicked       (GtkButton       *button,
                                        gpointer         user_data)
{

}

void
on_button61_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	//GtkWidget *toolbar, *stopbt/*, *notebk*/;

	//toolbar = lookup_widget("toolbar1");
        //stopbt = lookup_widget("button61");

	//gtk_widget_set_sensitive (toolbar, TRUE);
        //gtk_widget_set_sensitive (stopbt, FALSE);

	stop_flag = 1;

}






void
on_checkbutton35_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry109");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_button65_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry111");
	
	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 2;
}


void
on_button66_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry112");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 3;
}


void
on_button67_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry113");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 4;
}


void
on_button68_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry114");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 5;
}


void
on_button69_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry115");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 6;
}


void
on_button70_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry116");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 7;
}


void
on_button71_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry117");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 8;
}

void
on_button72_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry118");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 9;
}


void
on_button73_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry119");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 10;
}


void
on_button74_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field = lookup_widget("entry120");

	if (file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(file_menu));
		gdk_window_raise(gtk_widget_get_window(file_menu));
		return;
	}

	file_menu = create_fileselection1();
	gtk_widget_show(file_menu);

	btx = button;
	load_select_nr = 11;
}



void
on_select_database1_activate           (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{
	if (database_file_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(database_file_menu));
		gdk_window_raise(gtk_widget_get_window(database_file_menu));
		return;
	}

	if (selection1_dialog != NULL){
		gdk_window_show(gtk_widget_get_window(selection1_dialog));
		gdk_window_raise(gtk_widget_get_window(selection1_dialog));
		return;
	}

	database_file_menu = create_fileselection3();
	gtk_widget_show(database_file_menu);
}


void
on_ok_button3_clicked                  (GtkButton       *button,
                                        gpointer         user_data)
{
	FILE *file_p;
	gchar *fname;
	size_t fname_len;

	fname = g_strdup(gtk_file_chooser_get_filename(GTK_FILE_CHOOSER(lookup_widget("fileselection3"))));
	fname_len = strlen(fname);

	if (fname_len == 0)
		return;	

	if (fname_len >= sizeof(address_filename)) {
		error("Error: database file name too long (>=100 chars)");
		return;	
	}

	strncpy(address_filename, fname, sizeof(address_filename));

	if((file_p = fopen(fname, "a")) == NULL) { 
                //printf("can not open or create database file\n");
                error("Error: can't open or create database file");
        }
        else
		fclose(file_p);

	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


void
on_cancel_button3_clicked              (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


void
on_fileselection3_destroy              (GtkWidget       *object,
                                        gpointer         user_data)
{
	database_file_menu = NULL;
}




void
on_tos_dialod_destroy                  (GtkWidget       *object,
                                        gpointer         user_data)
{
	tos_dialog_menu = NULL;
}


/* inside tos dialog */
void
on_radiobutton38_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *fr1, *fr2;

	fr1 = lookup_widget("frame42");
	fr2 = lookup_widget("frame43");
	gtk_widget_set_sensitive(fr1, TRUE);
	gtk_widget_set_sensitive(fr2, FALSE);
}


/* inside tos dialog */
void
on_radiobutton39_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *fr1, *fr2;

	fr1 = lookup_widget("frame42");
	fr2 = lookup_widget("frame43");
	gtk_widget_set_sensitive(fr1, FALSE);
	gtk_widget_set_sensitive(fr2, TRUE);
}


/* ok button for tos dialog */
void
on_button76_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *tbt1, *w1, *w2, *w3, *w4, *w5, *en1;
	gint tos_value;
	gchar *en_t;
	gchar tmp[3];

	tbt1 = lookup_widget("radiobutton38");

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(tbt1))) {
		w1 = lookup_widget("optionmenu13");
		w2 = lookup_widget("radiobutton48");
		w3 = lookup_widget("radiobutton50");
		w4 = lookup_widget("radiobutton52");
		w5 = lookup_widget("radiobutton54");

		tos_value = gtk_combo_box_get_active (GTK_COMBO_BOX (w1));
		tos_value = tos_value << 5;

		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w2))) 
			tos_value = tos_value + 16;
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w3))) 
			tos_value = tos_value + 8;
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w4))) 
			tos_value = tos_value + 4;
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w5))) 
			tos_value = tos_value + 2;
        }
        else {
        	en1 = lookup_widget("entry154");
		en_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));
		tos_value = (guchar)strtol(en_t, (char **)NULL, 10);
		if ((tos_value<0) || (tos_value>63)) {
			//printf("wrong DSCP value\n");
			error("Error: wrong DSCP value");
			return;
		}
		else {
			tos_value = tos_value << 2;
		

		en1 = lookup_widget("checkbutton44");
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(en1)))
			tos_value = tos_value + 2;
		en1 = lookup_widget("checkbutton45");
		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(en1)))
			tos_value = tos_value + 1;
		}	
	}

	c8(tmp, tos_value);
	gtk_entry_set_text(GTK_ENTRY(entry_field_tos), tmp);

	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


/* cancel button for tos dialog */
void
on_button77_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


/* in this routine, when user types into the entry field, we insert ** at the bytes 
which will be changed. Due to many combinations this is temporary disabled */
void
on_entry160_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{

	/*
	GtkWidget *en5, *en6, *text_e;
	gchar *en5_t, *en6_t;
	int length, i, j, m, value, yvalue;
	char tmp[31000];

	en5 = lookup_widget("entry160");
        en5_t = (char *)gtk_entry_get_text(GTK_ENTRY(en5));
	length = strlen(en5_t);

	for(i=0; i<length; i++) {
		if (isdigit(*(en5_t+i)) == 0) {
                	error("Error: Wrong byte x entry!");
                	return;
		}
	}
        value =  strtol(en5_t, (char **)NULL, 10);

        if (number < value) {
                error("Error: Wrong byte x offset!");
                return;
        }

	text_e = lookup_widget("text5");

	en6 = lookup_widget("entry162");
        en6_t = (char *)gtk_entry_get_text(GTK_ENTRY(en6));
	yvalue = strtol(en6_t, (char **)NULL, 10);

	for (i=0, j=0, m=1; j < number; m++, j++) {
		if ((j+1) != value)
			snprintf(&tmp[i], 31000, "%02x", packet[j]);
		else
			snprintf(&tmp[i], 31000, "**");

		i++; i++;

		if ((m % 16) == 0 && (m > 1)) {
			tmp[i]='\n';
			m = 0;
		}
		else
			tmp[i] = ' '; 
		i++;
	}
	tmp[i] = '\0';

	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e));
	gtk_text_buffer_set_text(buffer,tmp,-1);
        */
}


/* in this routine, when user types into the entry field, we insert ** at the bytes 
which will be changed. Due to many combinations this is temporary disabled */
void
on_entry162_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	/*
	GtkWidget *en5, *en6, *text_e;
	gchar *en5_t, *en6_t;
	int length, i, j, m, value, xvalue;
	char tmp[31000];

	en5 = lookup_widget("entry162");
        en5_t = (char *)gtk_entry_get_text(GTK_ENTRY(en5));
	length = strlen(en5_t);

	for(i=0; i<length; i++) {
		if (isdigit(*(en5_t+i)) == 0) {
                	error("Error: Wrong byte y entry!");
                	return;
		}
	}
        value =  strtol(en5_t, (char **)NULL, 10);

        if (number < value) {
                error("Error: Wrong byte y offset!");
                return;
        }

	text_e = lookup_widget("text5");

	en6 = lookup_widget("entry160");
        en6_t = (char *)gtk_entry_get_text(GTK_ENTRY(en6));
	xvalue = strtol(en6_t, (char **)NULL, 10);

	for (i=0, j=0, m=1; j < number; m++, j++) {
		if ((j+1) != value)
			snprintf(&tmp[i], 31000, "%02x", packet[j]);
		else
			snprintf(&tmp[i], 31000, "**");

		i++; i++;

		if ((m % 16) == 0 && (m > 1)) {
			tmp[i]='\n';
			m = 0;
		}
		else
			tmp[i] = ' '; 
		i++;
	}
	tmp[i] = '\0';

	GtkTextBuffer *buffer = gtk_text_view_get_buffer(GTK_TEXT_VIEW(text_e));
	gtk_text_buffer_set_text(buffer,tmp,-1);
	*/
}


void
on_optionmenu14_clicked                (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *en;
	gint active_index;

	en = lookup_widget ("entry161");
	
	active_index = gtk_combo_box_get_active (combo_box);

	if ((active_index == 0) || (active_index == 3) || (active_index == 4) || (active_index == 5))
		gtk_widget_set_sensitive (en, FALSE);
	else 
		gtk_widget_set_sensitive (en, TRUE);
}


void
on_optionmenu15_clicked                (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *en;
	gint active_index;

	en = lookup_widget ("entry163");
	
	active_index = gtk_combo_box_get_active (combo_box);

	if ((active_index == 0) || (active_index == 3) || (active_index == 4) || (active_index == 5))
		gtk_widget_set_sensitive (en, FALSE);
	else 
		gtk_widget_set_sensitive (en, TRUE);
}



void
on_button78_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field_fragment = lookup_widget("entry31");

	if (fragment_dialog_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(fragment_dialog_menu));
		gdk_window_raise(gtk_widget_get_window(fragment_dialog_menu));
		return;
	}
	fragment_dialog_menu = create_fragmentation_dialog();
	gtk_widget_show(fragment_dialog_menu);
}


void
on_button79_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *w1, *w2;
	gboolean a1, a2;
	gchar tmp[2];

	bzero(tmp,2);

	w1 = lookup_widget("radiobutton55");
	a1 = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w1));

	w2 = lookup_widget("radiobutton57");
	a2 = gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(w2));

	if (a1 && a2)
		tmp[0] = '3';
	else if (a1 && !a2)
		tmp[0] = '2';
	else if (!a1 && a2)
		tmp[0] = '1';
	else
		tmp[0] = '0';

	gtk_entry_set_text(GTK_ENTRY(entry_field_fragment),tmp);

	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));
}


void
on_button80_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	gtk_grab_remove(gtk_widget_get_toplevel(GTK_WIDGET(button)));
	gtk_widget_destroy(gtk_widget_get_toplevel(GTK_WIDGET(button)));

}


void
on_fragmentation_dialog_destroy        (GtkWidget       *object,
                                        gpointer         user_data)
{
	fragment_dialog_menu = NULL;
}


/* this one loads parameters from file .default... */
void
on_Reset_button_clicked                (GtkButton       *button,
                                         gpointer         user_data)
{ 
	GtkWidget *notbk;
	gint page;
	FILE *file_p;

	statusbar_text(button, "");

	notbk = lookup_widget("notebook1");
	page =  gtk_notebook_get_current_page(GTK_NOTEBOOK(notbk));

	
	if (page == 0) { /* so we have the build notebook open */
		if((file_p = fopen(".defaultBuilder", "r")) == NULL) { 
			error("Can't open file with default parameters: \".defaultBuilder\"");
			return;
		}
		
		if (load_data(button, file_p, 1, 1) == -1) 
			;//error("Data in file \".defaultBuilder\" has wrong format");
		fclose(file_p);
	}
	
	else if (page == 1) { /* so we have the Gen-b notebook open */
		if((file_p = fopen(".defaultGen-b", "r")) == NULL) { 
			error("Can't open file with default parameters: \".defaultGen-b\"");
			return;
		}
		
		if (load_gen_b_data(button, file_p) == -1) 
			;//error("Data in file \".defaultGen-b\" has wrong format");
		fclose(file_p);
	}
	
	else if (page == 2) { /* so we have the Gen-s notebook open */
		if((file_p = fopen(".defaultGen-s", "r")) == NULL) { 
			error("Can't open file with default parameters: \".defaultGen-s\"");
			return;
		}
		
		if (load_gen_s_data(button, file_p) == -1) 
			//error("Data in file \".defaultGen-s\" has wrong format");
			;
		//fclose(file_p);
		//YYY : the above line causes a crash, I don't know why...
	}
	
	statusbar_text(button, "  Loaded default parameters");

	return;
}


/* this sets the default parameters */
void
on_button62_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *notbk;
	gint page;
	FILE *file_p;

	statusbar_text(button, "");

	notbk = lookup_widget("notebook1");
	page =  gtk_notebook_get_current_page(GTK_NOTEBOOK(notbk));
	
	if (page == 0) { /* we have the build notebook open */
		if((file_p = fopen(".defaultBuilder", "w")) == NULL) {
			error("Can't save parameters in file: \".defaultBuilder\"");
			return;
		}

		if (save_packet(button, user_data, file_p) == -1) {
                        fclose(file_p);
                        return;
                }
	}
	
	else if (page == 1) { /* we have the Gen-b notebook open */
		if((file_p = fopen(".defaultGen-b", "w")) == NULL) {
			error("Can't save parameters in file: \".defaultGen-b\"");
			return;
		}

		if (save_gen_b(button, file_p) == -1) {
                        fclose(file_p);
                        return;
                }
	}
	
	else if (page == 2) { /* we have the Gen-s notebook open */
		if((file_p = fopen(".defaultGen-s", "w")) == NULL) {
			error("Can't save parameters in file: \".defaultGen-s\"");
			return;
		}

		if (save_gen_s(button, file_p) == -1) {
                        fclose(file_p);
                        return;
                }
	}
	
	else
		return;

	fclose(file_p);

	statusbar_text(button, "  Parameters set as default parameters");

	return;

}


void
on_checkbutton40_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *txt6;
	txt6 = lookup_widget("entry165");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton)))
		gtk_widget_set_sensitive(txt6, TRUE);
	else
		gtk_widget_set_sensitive(txt6, FALSE);
}


void
on_igmpmessage_type_clicked            (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *opt_value, *ntbk5;
	gint active_index;

	opt_value = lookup_widget ("entry166");
	ntbk5 = lookup_widget ("notebook8");
	active_index = gtk_combo_box_get_active (combo_box);

	if (active_index == 0) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "11");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 0);
	}
	else if (active_index == 1) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "11");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 1);
	}
	else if (active_index == 2) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "12");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 0);
	}
	else if (active_index == 3) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "16");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 0);
	}
	else if (active_index == 4) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "22");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 2);
	}
	else if (active_index == 5) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "17");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 0);
	}
	else  {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
		gtk_notebook_set_current_page(GTK_NOTEBOOK(ntbk5), 0);
	}
}


void
on_igmp_checksum_bt_toggled            (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry168");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


/* this is the apply button inside IGMP header field */
void
on_button81_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
        GtkWidget *en1;
	gchar *dst_ip_t;
	int i, j, mc;
	char tmpmac[20], tmp[5];
	
        en1 = lookup_widget("entry39");
	gtk_entry_set_text(GTK_ENTRY(en1), "94040000");
	
        en1 = lookup_widget("entry44");
	gtk_entry_set_text(GTK_ENTRY(en1), "1");
	
        en1 = lookup_widget("entry27");
	gtk_entry_set_text(GTK_ENTRY(en1), "6");
	
        en1 = lookup_widget("entry37");
	dst_ip_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));

	/* check destination ip address */
        if (check_ip_address(dst_ip_t) == -1) {
                //printf("Error: Wrong destination ipv4 address format\n");
                error("Error: Wrong destination ipv4 address format");
                return;
        }

	memset(tmpmac, 0, 20);
	strcat(tmpmac, "01:00:5E:");

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

		if (i==0) 
			continue;
		else if (i==1) {
                       	mc = atoi(tmp);
			mc = mc & 0x7f;
			c8(tmp, mc);
			strcat(tmpmac, tmp);
			strcat(tmpmac, ":");
		}
		else if (i==2){
                       	mc = atoi(tmp);
			c8(tmp, mc);
			strcat(tmpmac, tmp);
			strcat(tmpmac, ":");
		}
		else {
                       	mc = atoi(tmp);
			c8(tmp, mc);
			strcat(tmpmac, tmp);
		}
        }

        en1 = lookup_widget("L_dst_mac");
	gtk_entry_set_text(GTK_ENTRY(en1), tmpmac);
}




void
on_Gen_p_clicked                       (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *nt1;
	
	nt1 = lookup_widget("notebook1");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt1), 3);

        nt1 = lookup_widget("Load_button");
        gtk_widget_set_sensitive(nt1, TRUE);
        nt1 = lookup_widget("Save_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Reset_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("button62");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Interface_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Send_button");
        gtk_widget_set_sensitive(nt1, FALSE);
        nt1 = lookup_widget("Stop_button");
	gtk_widget_set_sensitive(nt1, FALSE);

	statusbar_text(button, "  Open a Pcap file. Selected packet will be shown in Builder!");

}


void
on_clist2_selection_changed            (GtkTreeSelection *treeselection,
                                        gpointer          user_data)
{
	GtkTreeModel *model;
	GtkTreeIter   iter;
	const gchar *length_text;
	gchar *text;
	gchar tmp[5];
	int length;

	if (!gtk_tree_selection_get_selected (treeselection, &model, &iter)) {
		return;
	}

	gtk_tree_model_get (model, &iter,
	                    /*COL_LENGTH*/3, &length_text,
	                    /*COL_INFO*/7, &text,
	                    -1);

	/* set \0 inside the tmp field, get the length, remove the ! if present
	 * and convert to int, and pass to load_packet_disector() */
	memset(tmp, 0, 5);
	memccpy(tmp, length_text, 32, 4);
	length = strtol(tmp, (char **)NULL, 10);

	load_packet_disector(btx, text, 1, NULL, length);
}


void
on_button84_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{

}

/* calculate button clicked on Gen-s page */
void
on_button87_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{

	GtkWidget *en1;
	GtkWidget *rb1, *rb2, *rb3, *rb4 /*,*rb5*/;
	FILE *file_p;
        gchar *mbps_t;
	double bw[10];
	long pkts[10], pktnr[10];
	long long int deltapkt[10], deltastr[10];
	long long nsdelta = 0;
	int i, mode=0, active=0;
	long totalpkt=0, minpkts=1500000, pktlen;
	char ime[100];

	desired_bw = 0;

	/* dodat moraš če je slučajno prazen, al pa disablan */
	for(i=0; i<10; i++) {
		bw[i]= -1; pkts[i]= -1; pktnr[i]= -1;

		/* skip is disable button is clicked */
 		sprintf(ime, "checkbutton%d", i+25);
		en1 = lookup_widget(ime);
 		if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(en1)))
 			continue;

		/* get the bandwidth values */
		sprintf(ime, "entry%d", i+185);
        	en1 = lookup_widget(ime);
        	mbps_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));

		/* if there is nothing inside Mbit/s field, just skip */
		if(strlen(mbps_t)==0)
			continue;

		/* remember bw */
		bw[i] = strtod((mbps_t), NULL);

		if (bw[i]==0)
			return;
		else
			desired_bw = desired_bw + 1000*bw[i];

		sprintf(ime, "entry%d", i+111);
        	en1 = lookup_widget(ime);
        	mbps_t = (char *)gtk_entry_get_text(GTK_ENTRY(en1));

		/* if the file is not ready for opening, return error */
		if((file_p = fopen(mbps_t, "r")) == NULL) { 
        	        error("Error: can't open file for reading!");
        	        return;
        	}
		fseek(file_p, 0 , SEEK_END);
		pktlen = ftell(file_p)-40; /* 40 bytes is the pcap header, not nice I know, but... */
		fclose(file_p);

		/* number of packets per second */
		pkts[i]=bw[i]*1000000/(pktlen*8);

		/* remember the min value of packets per second */
		if (pkts[i] < minpkts )
			minpkts = pkts[i];

		totalpkt = totalpkt + pkts[i];
		active++;

	}


	rb1 = lookup_widget("radiobutton74");
	rb2 = lookup_widget("radiobutton75");
	rb3 = lookup_widget("radiobutton76");
	rb4 = lookup_widget("radiobutton77");
	//rb5 = lookup_widget("radiobutton78");

	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb1))) 
		mode = 1;
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb2))) 
		mode = 2;
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb3))) 
		mode = 3;
	else if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(rb4))) 
		mode = 4;
	else  
		mode = 5;


	switch (mode) {
		// case 1: max burst: send all the packets as fast as possible and wait till next burst
		case 1: {
			for(i=0; i<10; i++) {
				if (bw[i] == -1 ) { 
					pktnr[i]=0;
					deltapkt[i]=0;
					deltastr[i]=0;
				}
				else {
					pktnr[i] = pkts[i];	
					deltapkt[i] = 1;
					deltastr[i] = 1;
					//hm... approx 1000000us - 1us for each packet
					//time to send 1 packet on the link... zanemarimo
				}
				nsdelta = 1000000000 - totalpkt;
			}
			break;
		}
		// case 2: stream burst: send all the packets of one burst, wait a little, then another...
		case 2: {
			for(i=0; i<10; i++) {
				if (bw[i] == -1 ) { 
					pktnr[i]=0;
					deltapkt[i]=0;
					deltastr[i]=0;
				}
				else {
					pktnr[i] = pkts[i];	
					deltapkt[i] = 1;
					deltastr[i] = 1000000000/active;
					nsdelta = 1000000000/active;
				}
			}
			break;
		}
		// case 3: cont burst: send all the packets of one burst, then another, with equal delta...
		case 3: {
			for(i=0; i<10; i++) {
				if (bw[i] == -1 ) { 
					pktnr[i]=0;
					deltapkt[i]=0;
					deltastr[i]=0;
				}
				else {
					pktnr[i] = pkts[i];	
					deltapkt[i] = 1000000000/totalpkt;
					deltastr[i] = 1000000000/totalpkt;
					nsdelta = 0;
				}
			}
			break;
		}
		// case 4: cont 1: send all the packets of one stream, wait delta, then another stream...
		case 4: {
			int inc=1;
			float tmp[10], value;
			float percent1=0.95, percent2=1.05; //acceptable tolerance within specified bw
			for(i=0; i<10; i++) {
				if (bw[i] == -1 )  
					tmp[i]=0; //0 packets for emtpy streams
				else
					tmp[i]=(float)pkts[i]/minpkts; 
			}
			//check if the rounded pkt/s is inside boundaries, if not multiple with 2, 3, 4, until does.
			for(inc=1; inc<minpkts; inc++) {
				for(i=0; i<10; i++) {
					value = (round(tmp[i]*inc))/(tmp[i]*inc);	
					if ((value<percent1) || (value>percent2)) {
						break;
					}
					else {
						pkts[i]=round(tmp[i]*inc);
						//printf("value %f in tokle je inc %d pa še i %d pa še zmnožek %d\n", value, inc, i, pkts[i]);
					}
				}
				if (i==10) 
					break;
			}
			
			//assign values for each row
			for(i=0; i<10; i++) {
				// empty row
				if (bw[i] == -1 ) { 
					pktnr[i]=0;
					deltapkt[i]=0;
					deltastr[i]=0;
				}
				// active rows, delta time is equal for all packets and streams
				else {
					pktnr[i] = pkts[i];	
					deltapkt[i] = 1000000000/totalpkt;
					deltastr[i] = 1000000000/totalpkt;
					nsdelta = 0;
				}
			}
			break;
		}
		// case 5: random as random :)...
		case 5: {
			int inc=1;
			float tmp[10], value;
			float percent1=0.95, percent2=1.05; //acceptable tolerance within specified bw

			//check if the rounded pkt/s is inside boundaries, if not multiple with 2, 3, 4, until does.
			for(i=0; i<10; i++) {
				if (bw[i] == -1 )  
					tmp[i]=0; //0 packets for emtpy streams
				else
					tmp[i]=(float)pkts[i]/minpkts; 
			}
			for(inc=1; inc<minpkts; inc++) {
				for(i=0; i<10; i++) {
					value = (round(tmp[i]*inc))/(tmp[i]*inc);	
					if ((value<percent1) || (value>percent2)) {
						break;
					}
					else {
						pkts[i]=round(tmp[i]*inc);
					}
				}
				if (i==10) 
					break;
			}

			//assign values for each row
			for(i=0; i<10; i++) {
				if (bw[i] == -1 ) { 
					pktnr[i]=0;
					deltapkt[i]=0;
					deltastr[i]=0;
				}
				else {
					pktnr[i] = pkts[i];	
					deltapkt[i] = -1;
					deltastr[i] = -1;
					nsdelta = 1000000/totalpkt;
				}
			}
			break;
		}
	}


	for(i=0; i<10; i++) {

		sprintf(ime, "entry%d", i+121);
       		en1 = lookup_widget(ime);
		snprintf(ime, 9, "%ld", pktnr[i]);
       		gtk_entry_set_text(GTK_ENTRY(en1), ime);

		sprintf(ime, "entry%d", i+131);
       		en1 = lookup_widget(ime);
		if (deltapkt[i] == -1)
			snprintf(ime, 11, "0");
		else
			snprintf(ime, 11, "%lld", deltapkt[i]);
       		gtk_entry_set_text(GTK_ENTRY(en1), ime);

		sprintf(ime, "entry%d", i+141);
       		en1 = lookup_widget(ime);
		if (deltapkt[i] == -1)
			snprintf(ime, 11, "0");
		else
			snprintf(ime, 11, "%lld", deltastr[i]);
       		gtk_entry_set_text(GTK_ENTRY(en1), ime);
					
	}
	//delay between cycles
	en1 = lookup_widget("entry152");
	snprintf(ime, 11, "%lld", nsdelta);
       	gtk_entry_set_text(GTK_ENTRY(en1), ime);


}


void
on_radiobutton61_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	int i;
	char ime[10];

	for(i=0; i<10; i++) {
		sprintf(ime, "entry%d", i+185);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, TRUE);

		sprintf(ime, "entry%d", i+121);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, FALSE);

		sprintf(ime, "entry%d", i+131);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, FALSE);

		sprintf(ime, "entry%d", i+141);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, FALSE);

        	en1 = lookup_widget("button87");
        	gtk_widget_set_sensitive(en1, TRUE);
	}

        en1 = lookup_widget("entry152");
        gtk_widget_set_sensitive(en1, FALSE);
        en1 = lookup_widget("label379");
        gtk_widget_set_sensitive(en1, TRUE);
        en1 = lookup_widget("radiobutton74");
        gtk_widget_set_sensitive(en1, TRUE);
        en1 = lookup_widget("radiobutton75");
        gtk_widget_set_sensitive(en1, TRUE);
        en1 = lookup_widget("radiobutton76");
        gtk_widget_set_sensitive(en1, TRUE);
        en1 = lookup_widget("radiobutton77");
        gtk_widget_set_sensitive(en1, TRUE);
        en1 = lookup_widget("radiobutton78");
        gtk_widget_set_sensitive(en1, TRUE);

}


void
on_radiobutton62_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	int i;
	char ime[10];

	for(i=0; i<10; i++) {
		sprintf(ime, "entry%d", i+185);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, FALSE);

		sprintf(ime, "entry%d", i+121);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, TRUE);

		sprintf(ime, "entry%d", i+131);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, TRUE);

		sprintf(ime, "entry%d", i+141);
        	en1 = lookup_widget(ime);
        	gtk_widget_set_sensitive(en1, TRUE);
	}

       en1 = lookup_widget("button87");
       gtk_widget_set_sensitive(en1, FALSE);

       en1 = lookup_widget("entry152");
       gtk_widget_set_sensitive(en1, TRUE);

       en1 = lookup_widget("label379");
       gtk_widget_set_sensitive(en1, FALSE);
       en1 = lookup_widget("radiobutton74");
       gtk_widget_set_sensitive(en1, FALSE);
       en1 = lookup_widget("radiobutton75");
       gtk_widget_set_sensitive(en1, FALSE);
       en1 = lookup_widget("radiobutton76");
       gtk_widget_set_sensitive(en1, FALSE);
       en1 = lookup_widget("radiobutton77");
       gtk_widget_set_sensitive(en1, FALSE);
       gtk_toggle_button_set_active(GTK_TOGGLE_BUTTON(en1), TRUE );
       en1 = lookup_widget("radiobutton78");
       gtk_widget_set_sensitive(en1, FALSE);

}


void
on_radiobutton67_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1;
	nt4 = lookup_widget("notebook4");
	en1 = lookup_widget("entry199");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 0);
	gtk_entry_set_text(GTK_ENTRY(en1), "11");
}


void
on_radiobutton68_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1;
	nt4 = lookup_widget("notebook4");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 1);
	en1 = lookup_widget("entry199");
	gtk_entry_set_text(GTK_ENTRY(en1), "06");

}


void
on_radiobutton69_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1;
	nt4 = lookup_widget("notebook4");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 5);
	en1 = lookup_widget("entry199");
	gtk_entry_set_text(GTK_ENTRY(en1), "3A");

}


void
on_radiobutton71_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *nt4, *en1;
	nt4 = lookup_widget("notebook4");
	gtk_notebook_set_current_page(GTK_NOTEBOOK(nt4), 3);
	en1 = lookup_widget("entry199");
	gtk_entry_set_text(GTK_ENTRY(en1), "");

}


void
on_checkbutton43_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("entry198");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, FALSE);
		gtk_entry_set_text(GTK_ENTRY(en1), "");
	}
	else 
		gtk_widget_set_sensitive(en1, TRUE);
}


void
on_radiobutton72_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("entry151");
       	gtk_widget_set_sensitive(en1, TRUE);

        en1 = lookup_widget("entry204");
       	gtk_widget_set_sensitive(en1, FALSE);

}


void
on_radiobutton73_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("entry204");
       	gtk_widget_set_sensitive(en1, TRUE);

        en1 = lookup_widget("entry151");
       	gtk_widget_set_sensitive(en1, FALSE);

}


void
on_radiobutton79_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("entry204");
       	gtk_widget_set_sensitive(en1, FALSE);

        en1 = lookup_widget("entry151");
       	gtk_widget_set_sensitive(en1, FALSE);

}




void
on_entry185_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);
}


void
on_entry186_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry187_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry188_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry189_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry190_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry191_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry192_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry193_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_entry194_changed                    (GtkEditable     *editable,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_radiobutton76_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

        en1 = lookup_widget("label270");
	gtk_label_set_text(GTK_LABEL(en1), "Delay between cycles (us)");

}


void
on_radiobutton77_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

        en1 = lookup_widget("label270");
	gtk_label_set_text(GTK_LABEL(en1), "Delay between cycles (us)");

}


void
on_radiobutton74_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

        en1 = lookup_widget("label270");
	gtk_label_set_text(GTK_LABEL(en1), "Delay between cycles (us)");

}


void
on_radiobutton75_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

        en1 = lookup_widget("label270");
	gtk_label_set_text(GTK_LABEL(en1), "Delay between cycles (us)");

}


void
on_radiobutton78_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

        en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

        en1 = lookup_widget("label270");
	gtk_label_set_text(GTK_LABEL(en1), "Delay between packets (us)");

}


void
on_optionmenu22_changed                (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	gint active_index;

	en1 = lookup_widget("entry154");

	active_index = gtk_combo_box_get_active (combo_box);
	switch (active_index) {
		case 0: /* 0 */
			gtk_entry_set_text(GTK_ENTRY(en1), "0");
			break;
		case 1: /* CS1 */
			gtk_entry_set_text(GTK_ENTRY(en1), "8");
			break;
		case 2: /* CS2 */
			gtk_entry_set_text(GTK_ENTRY(en1), "16");
			break;
		case 3: /* CS3 */
			gtk_entry_set_text(GTK_ENTRY(en1), "24");
			break;
		case 4: /* CS4 */
			gtk_entry_set_text(GTK_ENTRY(en1), "32");
			break;
		case 5: /* CS5 */
			gtk_entry_set_text(GTK_ENTRY(en1), "40");
			break;
		case 6: /* CS6 */
			gtk_entry_set_text(GTK_ENTRY(en1), "48");
			break;
		case 7: /* CS7 */
			gtk_entry_set_text(GTK_ENTRY(en1), "56");
			break;
		case 8: /* AF11 */
			gtk_entry_set_text(GTK_ENTRY(en1), "10");
			break;
		case 9: /* AF12 */
			gtk_entry_set_text(GTK_ENTRY(en1), "12");
			break;
		case 10: /* AF13 */
			gtk_entry_set_text(GTK_ENTRY(en1), "14");
			break;
		case 11: /* AF21 */
			gtk_entry_set_text(GTK_ENTRY(en1), "18");
			break;
		case 12: /* AF22 */
			gtk_entry_set_text(GTK_ENTRY(en1), "20");
			break;
		case 13: /* AF23 */
			gtk_entry_set_text(GTK_ENTRY(en1), "22");
			break;
		case 14: /* AF31 */
			gtk_entry_set_text(GTK_ENTRY(en1), "26");
			break;
		case 15: /* AF32 */
			gtk_entry_set_text(GTK_ENTRY(en1), "28");
			break;
		case 16: /* AF33 */
			gtk_entry_set_text(GTK_ENTRY(en1), "30");
			break;
		case 17: /* AF41 */
			gtk_entry_set_text(GTK_ENTRY(en1), "34");
			break;
		case 18: /* AF42 */
			gtk_entry_set_text(GTK_ENTRY(en1), "36");
			break;
		case 19: /* AF43 */
			gtk_entry_set_text(GTK_ENTRY(en1), "38");
			break;
		case 20: /* EF */
			gtk_entry_set_text(GTK_ENTRY(en1), "46");
			break;
		default:
			break;
	}
}


void
on_button90_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field_tos = lookup_widget("entry196");

	if (tos_dialog_menu != NULL) {
		gdk_window_show(gtk_widget_get_window(tos_dialog_menu));
		gdk_window_raise(gtk_widget_get_window(tos_dialog_menu));
		return;
	}
	tos_dialog_menu = create_tos_dialod();
	gtk_widget_show(tos_dialog_menu);

}


void
on_button88_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field_ipv6 = lookup_widget("entry201");
	IPv6_yes = TRUE;
	IP_yes = FALSE;
	MAC_yes = FALSE;
	selection_dialog_show(button, user_data);

}


void
on_button89_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{
	entry_field_ipv6 = lookup_widget("entry202");
	IPv6_yes = TRUE;
	IP_yes = FALSE;
	MAC_yes = FALSE;
	selection_dialog_show(button, user_data);

}


void
on_button92_clicked                    (GtkButton       *button,
                                        gpointer         user_data)
{

	//GError *error;

        //error = NULL;
        //gtk_show_uri (gdk_screen_get_default(),"http://packeth.sourceforge.net",gtk_get_current_event_time (),  &error);

}


void
on_radiobutton80_activate              (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *en3, *hb1, *hb2, *cb1;
	GtkWidget *rb2, *rb3, *rb5, *rb6;
        en1 = lookup_widget("entry206");
        en2 = lookup_widget("entry110");
        en3 = lookup_widget("entry221");
        hb1 = lookup_widget("hbox1519");
        hb2 = lookup_widget("vbox93");
        cb1 = lookup_widget("checkbutton66");
        rb2 = lookup_widget("radiobutton83");
        rb3 = lookup_widget("radiobutton84");
        rb5 = lookup_widget("radiobutton85");
        rb6 = lookup_widget("radiobutton86");
        gtk_widget_set_sensitive(en1, TRUE);
        gtk_widget_set_sensitive(en2, FALSE);
        gtk_widget_set_sensitive(en3, FALSE);
        gtk_widget_set_sensitive(hb1, FALSE);
        gtk_widget_set_sensitive(hb2, TRUE);
        gtk_widget_set_sensitive(rb2, TRUE);
        gtk_widget_set_sensitive(rb3, TRUE);
        gtk_widget_set_sensitive(rb5, FALSE);
        gtk_widget_set_sensitive(rb6, FALSE);
        gtk_widget_set_sensitive(cb1, TRUE);
	//gtk_entry_set_text(GTK_ENTRY(en2), "");
}


void
on_radiobutton81_activate              (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *en3, *hb1, *hb2, *cb1;
	GtkWidget *rb2, *rb3, *rb5, *rb6;
        en1 = lookup_widget("entry206");
        en2 = lookup_widget("entry110");
        en3 = lookup_widget("entry221");
        hb1 = lookup_widget("hbox1519");
        hb2 = lookup_widget("vbox93");
        cb1 = lookup_widget("checkbutton66");
        rb2 = lookup_widget("radiobutton83");
        rb3 = lookup_widget("radiobutton84");
        rb5 = lookup_widget("radiobutton85");
        rb6 = lookup_widget("radiobutton86");
        gtk_widget_set_sensitive(en1, FALSE);
        gtk_widget_set_sensitive(en2, TRUE);
        gtk_widget_set_sensitive(en3, FALSE);
        gtk_widget_set_sensitive(hb1, FALSE);
        gtk_widget_set_sensitive(hb2, TRUE);
        gtk_widget_set_sensitive(rb2, FALSE);
        gtk_widget_set_sensitive(rb3, FALSE);
        gtk_widget_set_sensitive(rb5, TRUE);
        gtk_widget_set_sensitive(rb6, TRUE);
        gtk_widget_set_sensitive(cb1, TRUE);
}


void
on_radiobutton82_activate              (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *en3, *hb1, *hb2, *cb1;
	GtkWidget *rb2, *rb3, *rb5, *rb6;
        en1 = lookup_widget("entry206");
        en2 = lookup_widget("entry110");
        en3 = lookup_widget("entry221");
        hb1 = lookup_widget("hbox1519");
        hb2 = lookup_widget("vbox93");
        cb1 = lookup_widget("checkbutton66");
        rb2 = lookup_widget("radiobutton83");
        rb3 = lookup_widget("radiobutton84");
        rb5 = lookup_widget("radiobutton85");
        rb6 = lookup_widget("radiobutton86");
        gtk_widget_set_sensitive(en1, FALSE);
        gtk_widget_set_sensitive(en2, FALSE);
        gtk_widget_set_sensitive(en3, FALSE);
        gtk_widget_set_sensitive(hb1, FALSE);
        gtk_widget_set_sensitive(hb2, TRUE);
        gtk_widget_set_sensitive(rb2, FALSE);
        gtk_widget_set_sensitive(rb3, FALSE);
        gtk_widget_set_sensitive(rb5, FALSE);
        gtk_widget_set_sensitive(rb6, FALSE);
        gtk_widget_set_sensitive(cb1, TRUE);
}


void
on_radiobutton87_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *en3, *hb1, *hb2, *cb1;
	GtkWidget *rb2, *rb3, *rb5, *rb6;
        en1 = lookup_widget("entry206");
        en2 = lookup_widget("entry110");
        en3 = lookup_widget("entry221");
        hb1 = lookup_widget("hbox1519");
        hb2 = lookup_widget("vbox93");
        cb1 = lookup_widget("checkbutton66");
        rb2 = lookup_widget("radiobutton83");
        rb3 = lookup_widget("radiobutton84");
        rb5 = lookup_widget("radiobutton85");
        rb6 = lookup_widget("radiobutton86");
        gtk_widget_set_sensitive(en1, FALSE);
        gtk_widget_set_sensitive(en2, FALSE);
        gtk_widget_set_sensitive(en3, TRUE);
        gtk_widget_set_sensitive(hb1, FALSE);
        gtk_widget_set_sensitive(hb2, TRUE);
        gtk_widget_set_sensitive(rb2, FALSE);
        gtk_widget_set_sensitive(rb3, FALSE);
        gtk_widget_set_sensitive(rb5, FALSE);
        gtk_widget_set_sensitive(rb6, FALSE);
        gtk_widget_set_sensitive(cb1, TRUE);
}


void
on_Do_nothing1_activate                (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_MAC_set_random_source_address_activate
                                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_change_value_for_byte_x1_activate   (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_change_value_for_byte_x_and_y1_activate
                                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_ipv6_set_random_source_address_1_activate
                                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data)
{

}


void
on_optionmenu7_clicked                 (GtkComboBox     *combo_box,
                                        gpointer         user_data)
{
	GtkWidget *opt_value;
	gint active_index;

	opt_value = lookup_widget ("entry102");
	active_index = gtk_combo_box_get_active (combo_box);

	if (active_index == 0) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "8");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 1) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "0");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 2) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "4");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 3) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "18");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), FALSE);
	}
	else if (active_index == 4) {
		gtk_entry_set_text(GTK_ENTRY(opt_value), "");
		gtk_editable_set_editable(GTK_EDITABLE(opt_value), TRUE);
	}
}

void
on_checkbutton25_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);
}


void
on_checkbutton26_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton27_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton28_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton29_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton30_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton31_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton32_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton33_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}


void
on_checkbutton34_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;

	en1 = lookup_widget("button87");
	on_button87_clicked(GTK_BUTTON(en1), user_data);

}





void
on_radiobutton89_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *txt1, *txt2;
        en1 = lookup_widget("entry109");
        en2 = lookup_widget("entry222");
        txt1 = lookup_widget("label409");
        txt2 = lookup_widget("label408");
        gtk_widget_set_sensitive(en1, TRUE);
        gtk_widget_set_sensitive(en2, FALSE);
        gtk_widget_set_sensitive(txt1, TRUE);
        gtk_widget_set_sensitive(txt2, FALSE);
}


void
on_radiobutton90_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *txt1, *txt2;
        en1 = lookup_widget("entry109");
        en2 = lookup_widget("entry222");
        txt1 = lookup_widget("label409");
        txt2 = lookup_widget("label408");
        gtk_widget_set_sensitive(en1, FALSE);
        gtk_widget_set_sensitive(en2, TRUE);
        gtk_widget_set_sensitive(txt1, FALSE);
        gtk_widget_set_sensitive(txt2, TRUE);
}


void
on_radiobutton91_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *txt1, *txt2;
        en1 = lookup_widget("entry109");
        en2 = lookup_widget("entry222");
        txt1 = lookup_widget("label409");
        txt2 = lookup_widget("label408");
        gtk_widget_set_sensitive(en1, FALSE);
        gtk_widget_set_sensitive(en2, FALSE);
        gtk_widget_set_sensitive(txt1, FALSE);
        gtk_widget_set_sensitive(txt2, FALSE);

}


void
on_radiobutton95_clicked               (GtkButton       *button,
                                        gpointer         user_data)
{
	GtkWidget *en1, *en2, *en3, *hb1, *hb2, *cb1;
	GtkWidget *rb2, *rb3, *rb5, *rb6;
        en1 = lookup_widget("entry206");
        en2 = lookup_widget("entry110");
        en3 = lookup_widget("entry221");
        hb1 = lookup_widget("hbox1519");
        hb2 = lookup_widget("vbox93");
        cb1 = lookup_widget("checkbutton66");
        rb2 = lookup_widget("radiobutton83");
        rb3 = lookup_widget("radiobutton84");
        rb5 = lookup_widget("radiobutton85");
        rb6 = lookup_widget("radiobutton86");
        gtk_widget_set_sensitive(en1, FALSE);
        gtk_widget_set_sensitive(en2, FALSE);
        gtk_widget_set_sensitive(en3, FALSE);
        gtk_widget_set_sensitive(hb1, TRUE);
        gtk_widget_set_sensitive(hb2, FALSE);
        gtk_widget_set_sensitive(rb2, FALSE);
        gtk_widget_set_sensitive(rb3, FALSE);
        gtk_widget_set_sensitive(rb5, FALSE);
        gtk_widget_set_sensitive(rb6, FALSE);
        gtk_widget_set_sensitive(cb1, FALSE);
}


void
on_checkbutton66_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{
	GtkWidget *en1;
	en1 = lookup_widget("hbox1520");
	if (gtk_toggle_button_get_active(GTK_TOGGLE_BUTTON(togglebutton))) {
		gtk_widget_set_sensitive(en1, TRUE);
	}
	else 
		gtk_widget_set_sensitive(en1, FALSE);
}


void
on_checkbutton67_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data)
{

}
