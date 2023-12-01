#ifndef __INTERFACE_H__
#define __INTERFACE_H__

#include <gtk/gtk.h>

GtkWidget* create_window1 (void);
GtkWidget* create_sel1_dialog (void);
GtkWidget* create_interface_dialog (void);
GtkWidget* create_error_dialog (void);
GtkWidget* create_udp_payload_dialog (void);
GtkWidget* create_tos_dialod (void);
GtkWidget* create_fragmentation_dialog (void);
GtkWidget* create_fileselection1 (void);
GtkWidget* create_fileselection2 (void);
GtkWidget* create_fileselection3 (void);
void show_about_dialog (void);

#endif /* __INTERFACE_H__ */
