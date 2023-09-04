#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <gdk/gdkkeysyms.h>
#include <gtk/gtk.h>

#include "callbacks.h"
#include "interface.h"
#include "support.h"

static GtkWidget*
load_widget_from_ui_file (const gchar *ui_file, const gchar *name)
{
  GError *error = NULL;

  if (!builder)
  {
    return NULL;
  }

  if (!gtk_builder_add_from_file (builder, ui_file, &error))
  {
    g_critical ("Failed to load from file %s: %s.", ui_file, error->message);
    g_error_free (error);
    return NULL;
  }
  gtk_builder_connect_signals (builder, NULL);

  return GTK_WIDGET (gtk_builder_get_object (builder, name));
}

/* For unknown reason GtkComboBoxText.active property doesn't activate item */
static void
activate_first_combo_box_item (const gchar *name)
{
  GtkWidget *combo_box;

  combo_box = lookup_widget (NULL, name);
  if (combo_box)
  {
    gtk_combo_box_set_active (GTK_COMBO_BOX (combo_box), 0);
  }
}

/* For unknown reason GtkToggleButton.active property doesn't activate item */
static void
activate_toggle_button (const gchar *name)
{
  GtkWidget *toggle_button;

  toggle_button = lookup_widget (NULL, name);
  if (toggle_button)
  {
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (toggle_button), TRUE);
  }
}

GtkWidget*
create_window1 (void)
{
  GtkWidget *window1;

  window1 = load_widget_from_ui_file (PKGDATADIR "/ui/window1.ui", "window1");
  if (window1)
  {
    activate_first_combo_box_item ("L_optmenu1_bt");
    activate_first_combo_box_item ("optionmenu21");
    activate_first_combo_box_item ("L_optmenu2_bt");
    activate_first_combo_box_item ("optionmenu6");
    activate_first_combo_box_item ("optionmenu3");
    activate_first_combo_box_item ("optionmenu4");
    activate_first_combo_box_item ("optionmenu5");
    activate_first_combo_box_item ("optionmenu20");
    activate_first_combo_box_item ("optionmenu14");
    activate_first_combo_box_item ("optionmenu15");
  }

  return window1;
}

GtkWidget*
create_sel1_dialog (void)
{
  GtkWidget *sel1_dialog;

  sel1_dialog = load_widget_from_ui_file (PKGDATADIR "/ui/sel1_dialog.ui", "sel1_dialog");

  return sel1_dialog;
}

GtkWidget*
create_interface_dialog (void)
{
  GtkWidget *interface_dialog;

  interface_dialog = load_widget_from_ui_file (PKGDATADIR "/ui/interface_dialog.ui", "interface_dialog");

  return interface_dialog;
}

GtkWidget*
create_error_dialog (void)
{
  GtkWidget *error_dialog;

  error_dialog = load_widget_from_ui_file (PKGDATADIR "/ui/error_dialog.ui", "error_dialog");

  return error_dialog;
}

GtkWidget*
create_udp_payload_dialog (void)
{
  GtkWidget *udp_payload_dialog;

  udp_payload_dialog = load_widget_from_ui_file (PKGDATADIR "/ui/udp_payload_dialog.ui", "udp_payload_dialog");
  if (udp_payload_dialog)
  {
    activate_first_combo_box_item ("optionmenu7");
    activate_first_combo_box_item ("optionmenu12");
  }

  return udp_payload_dialog;
}

GtkWidget*
create_about_dialog (void)
{
  GtkWidget *about_dialog;

  about_dialog = load_widget_from_ui_file (PKGDATADIR "/ui/about_dialog.ui", "about_dialog");

  return about_dialog;
}

GtkWidget*
create_tos_dialod (void)
{
  GtkWidget *tos_dialod;

  tos_dialod = load_widget_from_ui_file (PKGDATADIR "/ui/tos_dialog.ui", "tos_dialog");
  if (tos_dialod)
  {
    activate_first_combo_box_item ("optionmenu13");
    activate_first_combo_box_item ("optionmenu22");
    activate_toggle_button ("radiobutton39");
  }

  return tos_dialod;
}

GtkWidget*
create_fragmentation_dialog (void)
{
  GtkWidget *fragmentation_dialog;

  fragmentation_dialog = load_widget_from_ui_file (PKGDATADIR "/ui/fragmentation_dialog.ui", "fragmentation_dialog");

  return fragmentation_dialog;
}

GtkWidget*
create_fileselection1 (void)
{
  GtkWidget *fileselection1;

  fileselection1 = load_widget_from_ui_file (PKGDATADIR "/ui/fileselection1.ui", "fileselection1");

  return fileselection1;
}

GtkWidget*
create_fileselection2 (void)
{
  GtkWidget *fileselection2;

  fileselection2 = load_widget_from_ui_file (PKGDATADIR "/ui/fileselection2.ui", "fileselection2");

  return fileselection2;
}

GtkWidget*
create_fileselection3 (void)
{
  GtkWidget *fileselection3;

  fileselection3 = load_widget_from_ui_file (PKGDATADIR "/ui/fileselection3.ui", "fileselection3");

  return fileselection3;
}
