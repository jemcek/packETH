# packETH  

packETH is GUI and CLI packet generator tool for ethernet. It allows you to create and send any possible packet or sequence of packets on the ethernet link. It is very simple to use, powerful and supports many adjustments of parameters while sending packets. It runs on Linux.  

With the GUI version (packETH) you can create and send packets. With the CLI version (packETHcli) you can only send already stored packets from pcap file. The CLI version also has a receiver mode, that can count packets and check if all packets that were sent were also received.

Some more information about installation, usage, GUI and CLI version and FAQ can also be found [here](https://packeth.sourceforge.net/packeth/Home.html).

[Blog](https://packeth.wordpress.com) with some use cases.

## NEWS

### OCT&NOV 2023

- migrated to GTK3 (many thanks to @qarkai) 
- vlan id field now accepts interger instead of HEX value

### JUL 2019  

- packETHcli added burst mode (-m -6)

### 27.11.2018

- packETHcli added receiver option (mode -m -9) to count received packets
- packETHcli added option to incluce pattern (predifined or custom) which can be checked by packETHcli in receiver mode if all packets that were sent were also correctly received at the receiver site
- packETHcli - nanoseconds support
- [Receiver mode](https://packeth.wordpress.com/2018/12/05/reciver-mode-check-for-dropped-packets/)
- [CLI tips](https://packeth.wordpress.com/2018/11/12/packethcli-some-practical-tips-1/)

## INSTALLATION  

### GUI  

```sh
git clone https://github.com/jemcek/packETH.git

cd packETH  
./autogen.sh      # you will need aclocal, autoconf, autoheader and automake installed to run this
autoreconf -f -i  # optional - in case you get automake version mismatch, missing files etc...
./configure  
make  
make install      # optional
./packETH
```

Depending on your Linux distribution and type of installation additional packages may be needed. For example:

#### Centos 7.4 (minimal)

```sh
yum groupinstall 'Development Tools'  
yum install gtk3-devel.x86_64  
yum install dbus-x11
```

#### Ubuntu 18.04 server

```sh
sudo apt-get install build-essential  
sudo apt-get install autoconf  
sudo apt-get install pkg-config  
sudo apt-get install libgtk-3-dev
sudo apt-get install dbus-x11
```

### CLI (you can also only compile cli version if you want)

```sh
cd cli  
make  
```

## USAGE  

### GUI version

`./packETH` (or `packETH` if you did the `make install`)

The usage of the program should be pretty straightforward. As you will see, there are 4 main windows (first four buttons from the left side). I call them:

- Builder - the page where you build the packet and send it once  
- Gen-b - generator for sending packet currently build inside Builder with many options how to send it  
- Gen-s - generator that allows you to select up to 10 previosly built packets and send them in different manner  
- Pcap window - open a tcpdump/wireshark capture file and load the selected packet into builder  

To send the packets you need the SuperUser rights.  

### CLI version  

Type `./packETHcli -h` for available options.

### RECEIVER mode  

packETHcli also has a reveiver mode (-m 9). In this mode packEThcli counts packets and displays statistics. If you add a pattern into packets sent by packETH or packETHcli then only packets with valid pattern will be counted. See manual for more help.  

## DONATIONS

If you would like to increase my motivation for further development, you can make a donation.
The amount is not important at all, it is just a sign for me, that time I spent for this project helps someone.

https://www.paypal.com/donate/?business=FZ8CFZHYDW2RJ&no_recurring=0&currency_code=EUR

## AUTHORS & SUPPORT  

If you get into problems, please feel free to contact me.

Miha Jemec  
<jemcek@gmail.com>  
packETH (C) 2003-2023 by Miha Jemec, <jemcek@gmail.com>  
Covered under the GPL.  
