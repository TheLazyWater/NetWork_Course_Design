#ifndef FORMAT_H
#define FORMAT_H

typedef unsigned char u_char;//1
typedef unsigned short u_short;//2
typedef unsigned int u_int;//4
typedef unsigned long u_long;//4

/*
 *
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/
typedef struct ether_header{
    u_char ethernet_des_host[6];
    u_char ethernet_src_host[6];
    u_short type;
}ETHER_HEADER;   //以太网帧


/*
 * IPV4
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           | |D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/
typedef struct ip_header{
    u_char version_length;
    u_char TOS;
    u_short total_length;
    u_short identification;
    u_short offset;
    u_char ttl;
    u_char protocol;
    u_short checksum;
    u_int src_addr;
    u_int des_addr;
}IP_HEADER;      //ip头部

#endif // FORMAT_H
