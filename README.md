# Mtm - Man in the middle tool

## Presentation

This tool can be use to perform a man in the middle using ARP
poisoning on two given hosts.

Using osdep, a tunnel creation library which is part of the 
aircrack project, it can set up an interface (`mitm0`) in which
the replayed packets will be written (to sniff easily).

This tool is useful for network debugging and monitoring, and 
was NOT designed for malicious usage.

## Building & using

You'll need the lib pcap:

```
apt-get install libcap0.8-dev
```

To build it, symply run:

```
make
```

The usage is:

```
MitM v0.23 by GregWar
Usage: mitm -i interface [-t] ip1 ip2
    -i interface:       specify network interface to use
    ip1:                The IP adress of the first victim
    ip2:                The IP adress of the second victim
    -t:         Create a TAP interface containing the
            replayed packets (in order to sniff)
```

For example:

```
mitm -i wlan0 -t 192.168.1.1 192.168.1.10
```

Will ARP poison `192.168.1.1` and `192.168.1.10`. All the replayed
packets will be available in the pseudo-interface `mitm0`.

## License

This is under the MIT license
