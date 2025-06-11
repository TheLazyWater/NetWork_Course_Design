#ifndef FORMAT_H
#define FORMAT_H

typedef unsigned char u_char;     // 1 byte
typedef unsigned short u_short;   // 2 byte
typedef unsigned int u_int;       // 4 byte
typedef unsigned long u_long;     // 4 byte

#define ARP  "ARP"                 //
#define TCP  "TCP"                 //
#define UDP  "UDP"                 //
#define ICMP "ICMP"                //
#define DNS  "DNS"                 //
#define TLS  "TLS"                 //
#define SSL  "SSL"                 //

// Ethernet protocol format
/*
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/

typedef struct ether_header{   // 14 byte
    u_char ether_des_host[6];  // destination addr [6 byte]
    u_char ether_src_host[6];  // source addr [6 byte]
    u_short ether_type;        // type [2 byte]
}ETHER_HEADER;

// Ipv4 header
/*
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           |R|D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/
typedef struct ip_header{           // 20 byte
    u_char versiosn_head_length;    // version [4 bit] and length of header [4 bit]
    u_char TOS;                     // TOS/DS_byte [1 byte]
    u_short total_length;           // ip package total length [2 byte]
    u_short identification;         // identification [2 byte]
    u_short flag_offset;            // flag [3 bit] and offset [13 bit]
    u_char ttl;                     // TTL [1 byte]
    u_char protocol;                // protocal [1 byte]
    u_short checksum;               // checksum [2 byte]
    u_int src_addr;                 // source address [4 byte]
    u_int des_addr;                 // destination address [4 byte]
}IP_HEADER;
// Tcp header

#endif // FORMAT_H
