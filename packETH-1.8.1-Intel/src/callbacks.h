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
 *
 */
#include <gtk/gtk.h>
// moj del:
//GtkWidget *clist1;
void selection_dialog_show(GtkButton *button, gpointer user_data);
void on_optionmenu7_clicked(GtkButton *button, gpointer user_data);
void error(gchar *error_type);
//

void
on_window1_destroy                     (GtkObject       *object,
                                        gpointer         user_data);

void
on_select_database1_activate           (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_exit1_activate                      (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_about1_activate                     (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_Build_button_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_Gen_button_clicked                  (GtkButton       *button,
                                        gpointer         user_data);

void
on_Gen_s_bt_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_Gen_k_bt_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_Load_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_Save_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_Reset_button_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_button62_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_Interface_button_clicked            (GtkButton       *button,
                                        gpointer         user_data);

void
on_Send_button_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_button61_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_auto_get_mac_cbt_toggled            (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_ver_II_bt_toggled                   (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_802_3_bt_toggled                    (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_802_1q_bt_clicked                   (GtkButton       *button,
                                        gpointer         user_data);

void
on_L_dst_select_bt_clicked             (GtkButton       *button,
                                        gpointer         user_data);

void
on_L_src_select_bt_clicked             (GtkButton       *button,
                                        gpointer         user_data);

void
on_L_optmenu1_bt_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton2_toggled                (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton40_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_L_8023_llc_tbt_toggled              (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_L_8023_llcsnap_tbt_toggled          (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_optionmenu6_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
IP_packet_toggled                      (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_IPv6_rdbt_toggled                   (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_arppkt_radiobt_toggled              (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_usedef2_radibt_toggled              (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button37_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton21_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button78_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_optionmenu3_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_ip_header_cks_cbt_toggled           (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button24_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button25_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_udp_bt_toggled                      (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_tcp_bt_toggled                      (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_icmp_bt_toggled                     (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_igmp_bt_toggled                     (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_ip_user_data_bt_toggled             (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button33_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button34_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button36_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button35_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_N_apply_pattern_clicked             (GtkButton       *button,
                                        gpointer         user_data);

void
on_N_select_payload_clicked            (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton3_toggled                (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton4_toggled                (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_udp_apply_pattern_button_clicked    (GtkButton       *button,
                                        gpointer         user_data);

void
on_udp_select_payload_button_clicked   (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton13_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_apply_tcp_pattern_bt_clicked        (GtkButton       *button,
                                        gpointer         user_data);

void
on_select_tpc_payload_bt_clicked       (GtkButton       *button,
                                        gpointer         user_data);

void
on_optionmenu4_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton16_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_optionmenu5_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton15_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton20_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button39_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button38_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_igmpmessage_type_clicked            (GtkButton       *button,
                                        gpointer         user_data);

void
on_igmp_checksum_bt_toggled            (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button81_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton35_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton37_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_optionmenu9_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_optionmenu16_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_optionmenu17_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_optionmenu18_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_optionmenu19_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_entry160_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_optionmenu14_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_entry162_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_optionmenu15_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton36_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button65_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button66_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button67_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button68_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button69_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button70_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button71_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button72_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button73_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button74_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_fileselection1_destroy              (GtkObject       *object,
                                        gpointer         user_data);

void
on_ok_button1_clicked                  (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_button1_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_fileselection2_destroy              (GtkObject       *object,
                                        gpointer         user_data);

void
on_ok_button2_clicked                  (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_button2_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_sel1_dialog_destroy                 (GtkObject       *object,
                                        gpointer         user_data);

void
on_sel1_add_bt_clicked                 (GtkButton       *button,
                                        gpointer         user_data);

void
on_sel1_delete_bt_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_sel1_ok_bt_clicked                  (GtkButton       *button,
                                        gpointer         user_data);

void
on_sel1_cancel_bt_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_interface_dialog_destroy            (GtkObject       *object,
                                        gpointer         user_data);

void
on_button50_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button51_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_error_dialog_destroy                (GtkObject       *object,
                                        gpointer         user_data);

void
on_button52_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_udp_payload_dialog_destroy          (GtkObject       *object,
                                        gpointer         user_data);

void
on_rtp_apply_button_clicked            (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_rtp_bt_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_rtp_ok_bt_clicked                   (GtkButton       *button,
                                        gpointer         user_data);

void
on_fileselection3_destroy              (GtkObject       *object,
                                        gpointer         user_data);

void
on_ok_button3_clicked                  (GtkButton       *button,
                                        gpointer         user_data);

void
on_cancel_button3_clicked              (GtkButton       *button,
                                        gpointer         user_data);

void
on_about_dialog_destroy                (GtkObject       *object,
                                        gpointer         user_data);

void
on_button75_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_tos_dialod_destroy                  (GtkObject       *object,
                                        gpointer         user_data);

void
on_radiobutton38_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton39_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_button76_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button77_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_fragmentation_dialog_destroy        (GtkObject       *object,
                                        gpointer         user_data);

void
on_button79_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button80_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_0x1_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_0x2_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_0x3_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_0x4_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_Gen_p_clicked                       (GtkButton       *button,
                                        gpointer         user_data);

void
on_clist2_select_row                   (GtkCList        *clist,
                                        gint             row,
                                        gint             column,
                                        GdkEvent        *event,
                                        gpointer         user_data);

void
on_button84_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button87_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton61_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton62_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton61_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton62_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton67_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton68_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton69_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton71_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton43_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_entry186_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry185_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry186_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry185_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_radiobutton72_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton73_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton72_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton73_clicked               (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton72_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton73_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton79_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_entry185_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry186_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry187_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry188_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry189_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry190_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry191_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry192_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry193_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_entry194_changed                    (GtkEditable     *editable,
                                        gpointer         user_data);

void
on_radiobutton76_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton77_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton74_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton75_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton78_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_0_activate                          (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cs1_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cs2_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cs3_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cs4_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cs5_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cs6_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_cs7_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af11_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af12_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af13_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af21_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_a22_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af23_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af31_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af32_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af33_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af41_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af42_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_af43_activate                       (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_ef1_activate                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_button90_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button88_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button89_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_button92_clicked                    (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton80_activate              (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton81_activate              (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton82_activate              (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton80_activate              (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton81_activate              (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton82_activate              (GtkButton       *button,
                                        gpointer         user_data);

void
on_auto_get_mac_cbt_clicked            (GtkButton       *button,
                                        gpointer         user_data);

void
on_Do_nothing1_activate                (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_MAC_set_random_source_address_activate
                                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_change_value_for_byte_x1_activate   (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_change_value_for_byte_x_and_y1_activate
                                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_ipv6_set_random_source_address_1_activate
                                        (GtkMenuItem     *menuitem,
                                        gpointer         user_data);

void
on_optionmenu23_clicked                (GtkButton       *button,
                                        gpointer         user_data);

void
on_checkbutton25_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton26_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton27_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton28_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton29_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton30_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton31_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton32_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton33_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_checkbutton34_toggled               (GtkToggleButton *togglebutton,
                                        gpointer         user_data);

void
on_radiobutton87_activate              (GtkButton       *button,
                                        gpointer         user_data);

void
on_radiobutton87_clicked               (GtkButton       *button,
                                        gpointer         user_data);
