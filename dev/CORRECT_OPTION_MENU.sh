#!/bin/bash

sed -n -i -e '/return window1/r options-menu_diff-create_window1' -e 1x -e '2,${x;p}' -e '${x;p}' ../src/interface.c
sed -n -i -e '/return udp_payload_dialog/r options-menu_diff-create_udp_payload_dialog' -e 1x -e '2,${x;p}' -e '${x;p}' ../src/interface.c
