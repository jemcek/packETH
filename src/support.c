#ifdef HAVE_CONFIG_H
#  include <config.h>
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>

#include <gtk/gtk.h>

#include "support.h"

GtkWidget*
lookup_widget                          (const gchar     *widget_name)
{
  GtkWidget *found_widget;

  if (!builder)
    {
      g_warning ("Builder not found");
      return NULL;
    }

  found_widget = GTK_WIDGET (gtk_builder_get_object (builder, widget_name));
  if (!found_widget)
    g_warning ("Widget not found: %s", widget_name);
  return found_widget;
}
