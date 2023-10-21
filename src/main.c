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
 */

#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <gtk/gtk.h>

#include "interface.h"
#include "support.h"

GtkBuilder *builder;

int
main (int argc, char *argv[])
{
  GtkWidget *window1;
/*  GtkWidget *fileselection1;
  GtkWidget *fileselection2;
  GtkWidget *sel1_dialog;
  GtkWidget *interface_dialog;
  GtkWidget *error_dialog;
  GtkWidget *udp_payload_dialog;
  GtkWidget *fileselection3;
  GtkWidget *tos_dialod;
  GtkWidget *fragmentation_dialog; */

#ifdef ENABLE_NLS
  bindtextdomain (GETTEXT_PACKAGE, PACKAGE_LOCALE_DIR);
  bind_textdomain_codeset (GETTEXT_PACKAGE, "UTF-8");
  textdomain (GETTEXT_PACKAGE);
#endif

  gtk_init (&argc, &argv);

  builder = gtk_builder_new ();

  /*
   * The following code was added by Glade to create one of each component
   * (except popup menus), just so that you see something after building
   * the project. Delete any components that you don't want shown initially.
   */
  window1 = create_window1 ();
  gtk_widget_show (window1);
/*  fileselection1 = create_fileselection1 ();
  gtk_widget_show (fileselection1);
  fileselection2 = create_fileselection2 ();
  gtk_widget_show (fileselection2);
  sel1_dialog = create_sel1_dialog ();
  gtk_widget_show (sel1_dialog);
  interface_dialog = create_interface_dialog ();
  gtk_widget_show (interface_dialog);
  error_dialog = create_error_dialog ();
  gtk_widget_show (error_dialog);
  udp_payload_dialog = create_udp_payload_dialog ();
  gtk_widget_show (udp_payload_dialog);
  fileselection3 = create_fileselection3 ();
  gtk_widget_show (fileselection3);
  show_about_dialog ();
  tos_dialod = create_tos_dialod ();
  gtk_widget_show (tos_dialod);
  fragmentation_dialog = create_fragmentation_dialog ();
  gtk_widget_show (fragmentation_dialog); */

  gtk_main();

  return 0;
}
