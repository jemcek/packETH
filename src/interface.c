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

#define RESOURCE_PATH_UI "/org/packeth/ui"

static GtkWidget*
load_widget_from_resource (const gchar *resource, const gchar *name)
{
  GError *error = NULL;

  if (!builder)
  {
    return NULL;
  }

  if (!gtk_builder_add_from_resource (builder, resource, &error))
  {
    g_critical ("Failed to load from resource %s: %s.", resource, error->message);
    g_error_free (error);
    return NULL;
  }
  gtk_builder_connect_signals (builder, NULL);

  return GTK_WIDGET (gtk_builder_get_object (builder, name));
}

/* For unknown reason GtkToggleButton.active property doesn't activate item */
static void
activate_toggle_button (const gchar *name)
{
  GtkWidget *toggle_button;

  toggle_button = lookup_widget (name);
  if (toggle_button)
  {
    gtk_toggle_button_set_active (GTK_TOGGLE_BUTTON (toggle_button), TRUE);
  }
}

GtkWidget*
create_window1 (void)
{
  GtkWidget *window1;

  window1 = load_widget_from_resource (RESOURCE_PATH_UI "/window1.ui", "window1");

  return window1;
}

GtkWidget*
create_sel1_dialog (void)
{
  GtkWidget *sel1_dialog;

  sel1_dialog = load_widget_from_resource (RESOURCE_PATH_UI "/sel1_dialog.ui", "sel1_dialog");

  return sel1_dialog;
}

GtkWidget*
create_interface_dialog (void)
{
  GtkWidget *interface_dialog;

  interface_dialog = load_widget_from_resource (RESOURCE_PATH_UI "/interface_dialog.ui", "interface_dialog");

  return interface_dialog;
}

GtkWidget*
create_error_dialog (void)
{
  GtkWidget *error_dialog;

  error_dialog = load_widget_from_resource (RESOURCE_PATH_UI "/error_dialog.ui", "error_dialog");

  return error_dialog;
}

GtkWidget*
create_udp_payload_dialog (void)
{
  GtkWidget *udp_payload_dialog;

  udp_payload_dialog = load_widget_from_resource (RESOURCE_PATH_UI "/udp_payload_dialog.ui", "udp_payload_dialog");

  return udp_payload_dialog;
}

GtkWidget*
create_tos_dialod (void)
{
  GtkWidget *tos_dialod;

  tos_dialod = load_widget_from_resource (RESOURCE_PATH_UI "/tos_dialog.ui", "tos_dialog");
  if (tos_dialod)
  {
    activate_toggle_button ("radiobutton39");
  }

  return tos_dialod;
}

GtkWidget*
create_fragmentation_dialog (void)
{
  GtkWidget *fragmentation_dialog;

  fragmentation_dialog = load_widget_from_resource (RESOURCE_PATH_UI "/fragmentation_dialog.ui", "fragmentation_dialog");

  return fragmentation_dialog;
}

GtkWidget*
create_fileselection1 (void)
{
  GtkWidget *fileselection1;

  fileselection1 = load_widget_from_resource (RESOURCE_PATH_UI "/fileselection1.ui", "fileselection1");

  return fileselection1;
}

GtkWidget*
create_fileselection2 (void)
{
  GtkWidget *fileselection2;

  fileselection2 = load_widget_from_resource (RESOURCE_PATH_UI "/fileselection2.ui", "fileselection2");

  return fileselection2;
}

GtkWidget*
create_fileselection3 (void)
{
  GtkWidget *fileselection3;

  fileselection3 = load_widget_from_resource (RESOURCE_PATH_UI "/fileselection3.ui", "fileselection3");

  return fileselection3;
}

void
show_about_dialog (void)
{
  const gchar *authors[] = {
    "Miha Jemec <jemcek@gmail.com>",
    NULL
  };

  gtk_show_about_dialog (NULL,
                         "authors", authors,
                         "comments", "ethernet packet generator",
                         "copyright", "Copyright \302\251 2003 - 2023",
                         "logo-icon-name", "application-x-executable",
                         "program-name", PACKAGE_NAME,
                         "version", PACKAGE_VERSION,
                         "website", PACKAGE_URL,
                         NULL);
}
