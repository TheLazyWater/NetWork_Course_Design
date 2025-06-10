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

/*
 * Tcp
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/
typedef struct tcp_heafer{
    u_short src_port;
    u_short des_port;
    u_int seqequence;
    u_int ack;
    u_char header_length;
    u_char flags;
    u_short window_size;
    u_short checksum;
    u_short urgent;
}TCP_HEADER;


/*
 * udp
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/

typedef struct udp_header{
    u_short src_port;
    u_short des_port;
    u_short data_length;
    u_short checksum;
}UDP_HEADER;


/*
 * icmp
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
typedef struct icmp_header{
    u_char type;
    u_char code;
    u_short checksum;
    u_short identification;
    u_short sequence;
}ICMP_HEADER;


/*
 * arp
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct ARP_header{
    u_short type;
    u_short protocol;
    u_char mac_length;
    u_char ip_length;
    u_short op_code;
    u_char src_eth_addr[6];
    u_char src_ip_addr[4];
    u_char des_eth_addr[6];
    u_char des_ip_addr[4];
}ARP_HEADER;


/*
 * dns
+--------------------------+---------------------------+
|           16 bit         |1b|4bit|1b|1b|1b|1b|3b|4bit|
+--------------------------+--+----+--+--+--+--+--+----+
|      identification      |QR| OP |AA|TC|RD|RA|..|Resp|
+--------------------------+--+----+--+--+--+--+--+----+
|         Question         |       Answer RRs          |
+--------------------------+---------------------------+
|     Authority RRs        |      Additional RRs       |
+--------------------------+---------------------------+
*/
typedef struct dns_HEADER {
    u_short identification;  // 标识号，用于匹配请求和响应

    // 标志位（2字节） - 实际使用时需按位解析
    u_short flags;

    // 问题数、回答资源记录数、权威资源记录数、附加资源记录数
    u_short questions;
    u_short answers;
    u_short authorities;
    u_short additionals;
} DNS_HEADER;

// 辅助结构体：分解标志位（非网络字节序部分）
typedef struct dns_FLAGS {
    unsigned char response_code : 4;  // 响应码（低4位）
    unsigned char : 3;               // 保留位
    unsigned char recursion_available : 1;  // RA 位
    unsigned char truncation : 1;           // TC 位
    unsigned char authoritative_answer : 1; // AA 位
    unsigned char opcode : 4;               // 操作码
    unsigned char query_response : 1;       // QR 位（高1位）
} DNS_FLAGS;



#endif // FORMAT_H
