#ifndef _MITM_H
#define _MITM_H
#include <linux/if_ether.h>

#define ARPHRD_ETHER 	1		/* Ethernet 10Mbps		*/

#define	ARPOP_REQUEST	1		/* ARP request			*/
#define	ARPOP_REPLY	2		/* ARP reply			*/
#define	ARPOP_RREQUEST	3		/* RARP request			*/
#define	ARPOP_RREPLY	4		/* RARP reply			*/
#define	ARPOP_InREQUEST	8		/* InARP request		*/
#define	ARPOP_InREPLY	9		/* InARP reply			*/
#define	ARPOP_NAK	10		/* (ATM)ARP NAK			*/

struct eth_header {
	unsigned char		target[ETH_ALEN];
	unsigned char		source[ETH_ALEN];
	unsigned short		proto;
};

struct arp_packet
{
	struct eth_header eth;	

        unsigned short          ar_hrd;         /* format of hardware address   */
        unsigned short         	ar_pro;         /* format of protocol address   */
        unsigned char   	ar_hln;         /* length of hardware address   */
        unsigned char   	ar_pln;         /* length of protocol address   */
        unsigned short          ar_op;          /* ARP opcode (command)         */

        unsigned char           ar_sha[ETH_ALEN];       /* sender hardware address      */
        unsigned char           ar_sip[4];              /* sender IP address            */
        unsigned char           ar_tha[ETH_ALEN];       /* target hardware address      */
        unsigned char           ar_tip[4];              /* target IP address            */
};

struct macip {
	unsigned char mac[6];
	unsigned char ip[4];
};

unsigned char mitm_IPbuf[0xFF];
unsigned char mitm_MACbuf[0xFF];
unsigned char*mitm_printMAC(unsigned char*);
unsigned char*mitm_printIP(unsigned char*);

void mitm_usage();
void mitm_run();
void mitm_end();
void mitm_thread_end(int s);
void *mitm_ARP_spoofer(void*);
void mitm_ARP_cleanup();
void *mitm_sniffer(void*);
void *mitm_printstats(void*);
int mitm_is_victim(unsigned char*);
int mitm_is_me(unsigned char*);

int arp_lookup(int,unsigned char*,unsigned char*,unsigned char*);

#endif /* _MITM_H */
