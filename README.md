
# Egetty - Ethernet Console

Based on original code of **jelaas**

# 1. Usage

**egetty** - The server, providing shell and file operations
**econsole** - The client, connecting to remote **egetty** instances by network interface

## 1.1 Using 'egetty'

Running manually on Linux:
```
egetty <iface>
```
Ex.
```
root@home:/bin# egetty eth0
```
Adding to linux for automatic start using sysvinit style inittab:
```
tty<X>::respawn:/bin/egetty <iface>
```

Example entries for traditional sysvinit style inittab:
```
e1:2345:respawn:/sbin/egetty 0 wlan0
e2:2345:respawn:/sbin/egetty 0 eth0 console
```

egetty [0-9] <dev> [console|waitif|debug]

'**waitif**' means egetty will wait for the device to come up.
If '**waitif**' is not given egetty will try to bring up the given interface.

## 1.2 Using econsole

Ping to remote console:
```
econsole [(-i <iface> (-m <mac>))] ping
```

Getting shell:
```
econsole [(-i <iface> (-m <mac>))] shell
```

Searching for egetty consoles:
```
econsole [(-i <iface>)] devices
```

Pushing a file from local machine over the egetty connection:

```
econsole [(-i <iface> (-m <mac>))] push <file> <remote path>
```

:exclamation: :exclamation: :exclamation: :exclamation: :exclamation: :exclamation:
 ## Pushing files on an ethernet cable may result in errors! as there is no guarantee of transfer and processing order.
 One could use a data link cable that is implemented by 2-way interface which are based on the plusb driver.
 Some devices are:
 **Unitek Y-3501 based on PL-27A1**
 **Goobay Active USB 3.0**
 **NI Host-To-Host cable**
 **Belkin F5U258/F5U279**
 **PL-25A1**
:exclamation: :exclamation: :exclamation: :exclamation: :exclamation: :exclamation:

## 2. Android

Its possible to use egetty in android by compiling it into the firmware:

Adding to build system:

```
PRODUCT_PACKAGES += egetty
```

Adding as a service for a known interface:
```
service egetty /system/bin/egetty eth0
    class main
    user root
```
