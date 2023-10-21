
#ifndef PROBER_RESOURCES_H
#define PROBER_RESOURCES_H
#define RawEth  (3)
#define LOADTRACE (1)
#include <assert.h>
#include <chrono>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <infiniband/verbs.h>
#define PORT_NUM 1
/* Genral control definitions */
#define OFF	     (0)
#define ON 	     (1)
#define SUCCESS	     (0)
#define FAILURE	     (1)

#define MAC_LEN (17)
#define ETHERTYPE_LEN (6)
#define MAC_ARR_LEN (6)
#define HEX_BASE (16)


#define DEFAULT_JSON_FILE_NAME "perftest_out.json"

#define ENTRY_SIZE 512 /* The maximum size of each received packet - set to jumbo frame */
#define SQ_NUM_DESC 512
#define RQ_NUM_DESC 512 /* The maximum receive ring length without processing */
#define NOTIFY_COMP_ERROR_SEND(wc,scnt,ccnt)                     											\
	{ fprintf(stderr," Completion with error at client\n");      											\
	  fprintf(stderr," Failed status %d: wr_id %d syndrom 0x%x\n",wc.status,(int) wc.wr_id,wc.vendor_err);	\
	  fprintf(stderr, "scnt=%lu, ccnt=%lu\n",scnt, ccnt); }

#define NOTIFY_COMP_ERROR_RECV(wc,rcnt)                     											    \
	{ fprintf(stderr," Completion with error at server\n");      											\
	  fprintf(stderr," Failed status %d: wr_id %d syndrom 0x%x\n",wc.status,(int) wc.wr_id,wc.vendor_err);	\
	  fprintf(stderr," rcnt=%lu\n",rcnt); }
/* Macro for allocating. */
#define ALLOCATE(var,type,size)                                     \
{ if((var = (type*)malloc(sizeof(type)*(size))) == NULL)        \
	{ fprintf(stderr," Cannot Allocate\n"); exit(1);}}


// /* Macro for allocating in alloc_ctx function */
/*// #define ALLOC(var,type,size)									\
// { if((var = (type*)malloc(sizeof(type)*(size))) == NULL)        \
// 	{ fprintf(stderr," Cannot Allocate\n"); dealloc_ctx(ctx, user_param); return 1;}}
*/

/* Macro for allocating and jump to destroy labels in case of failures */
#define MAIN_ALLOC(var,type,size,label)									\
{ if((var = (type*)malloc(sizeof(type)*(size))) == NULL)        \
	{ fprintf(stderr," Cannot Allocate\n"); goto label;}}
#define PERF_MAC_FMT " %02X:%02X:%02X:%02X:%02X:%02X"

#define IP_ETHER_TYPE (0x800)
#define IP6_ETHER_TYPE (0x86DD)
#define PRINT_ON (1)
#define PRINT_OFF (0)
#define UDP_PROTOCOL (0x11)
#define TCP_PROTOCOL (0x06)
#define IP_HEADER_LEN (20)
#define DEFAULT_IPV6_NEXT_HDR (0x3b)



/* gen_eth_header .
 * Description :create raw Ethernet header on buffer
 *
 * Parameters :
 *	 	eth_header - Pointer to output
 *	 	src_mac - source MAC address of the packet
 *	 	dst_mac - destination MAC address of the packet
 *	 	eth_type - IP/or size of ptk
 *
 */
struct ETH_header {
	uint8_t dst_mac[6];
	uint8_t src_mac[6];
	uint16_t eth_type;
}__attribute__((packed));

struct ETH_vlan_header {
        uint8_t dst_mac[6];
        uint8_t src_mac[6];
        uint32_t vlan_header;
        uint16_t eth_type;
}__attribute__((packed));

#define VLAN_TPID (0x8100)
#define VLAN_VID (0x001)
#define VLAN_CFI (0)

#if defined(__FreeBSD__)
#if BYTE_ORDER == BIG_ENDIAN
#define __BIG_ENDIAN_BITFIELD
#define htobe32_const(x) (x)
#elif BYTE_ORDER == LITTLE_ENDIAN
#define __LITTLE_ENDIAN_BITFIELD
#define htobe32_const(x) (((x) >> 24) | (((x) >> 8) & 0xff00) | \
    ((((x) & 0xffffff) << 8) & 0xff0000) | ((((x) & 0xff) << 24) & 0xff000000))
#else
#error "Must set BYTE_ORDER"
#endif
#endif

// struct IP_V6_header {
// #if defined(__LITTLE_ENDIAN_BITFIELD)
// 	__u8			priority:4,
// 				version:4;
// #elif defined(__BIG_ENDIAN_BITFIELD)
// 	__u8			version:4,
// 				priority:4;
// #endif
// 	__u8			flow_lbl[3];

// 	__be16			payload_len;
// 	__u8			nexthdr;
// 	__u8			hop_limit;

// 	struct	in6_addr	saddr;
// 	struct	in6_addr	daddr;
// }__attribute__((packed));

struct IP_V4_header{
	// #if defined(__LITTLE_ENDIAN_BITFIELD)
	uint8_t		ihl:4;
	uint8_t		version:4;
	// #elif defined(__BIG_ENDIAN_BITFIELD)
	// uint8_t		version:4;
	// uint8_t		ihl:4;
	// #endif
	uint8_t		tos;
	uint16_t 	tot_len;
	uint16_t	id;
	uint16_t	frag_off;
	uint8_t		ttl;
	uint8_t		protocol;
	uint16_t	check;
	uint32_t	saddr;
	uint32_t	daddr;
}__attribute__((packed));

union IP_V4_header_raw {
	struct		IP_V4_header ip_header;
	uint32_t	raw[sizeof(struct IP_V4_header) / 4];
};

struct UDP_header {
	uint16_t	uh_sport;		/* source port */
	uint16_t	uh_dport;		/* destination port */
	uint16_t	uh_ulen;		/* udp length */
	uint16_t	uh_sum;			/* udp checksum */
}__attribute__((packed));

// struct TCP_header {
// 	uint16_t        th_sport;               /* source port */
// 	uint16_t        th_dport;               /* destination port */
// 	uint32_t        th_seq;
// 	uint32_t        th_ack;
// 	uint8_t         th_rsv:4;
// 	uint8_t         th_doff:4;
// 	uint8_t         th_falgs;
// 	uint16_t        th_window;
// 	uint16_t        th_check;
// 	uint16_t        th_urgptr;
// }__attribute__((packed));

struct prober_parameters
{
    /* data */
    uint64_t iters;
	std::chrono::high_resolution_clock::time_point *tposted;
	std::chrono::high_resolution_clock::time_point *rposted;
    int cpu_freq_f;
    int test_size;
    // uint8_t				server_ip6[16];
	// uint8_t				client_ip6[16];
	// uint8_t				local_ip6[16];
	// uint8_t				remote_ip6[16];
	uint8_t				src_mac[6];
	uint8_t				dst_mac[6];
	uint32_t			src_ip;
	uint32_t			dst_ip;
	int				is_server_ip;
	int				is_client_ip;
	// uint32_t			local_ip;
	// uint32_t			remote_ip;
	int				src_port;
	int				dst_port;
	int				tcp;

	// int				is_server_port;
	// int				is_client_port;
	// int				local_port;
	// int				remote_port;
	uint16_t			ethertype;
	int				is_ethertype;

    const char *ib_devname;
    char *servername;
    uint32_t ib_port;
    uint32_t gid_idx;
    uint16_t udp_sport;
};
struct raw_ethernet_info {
	uint8_t mac[6];
	uint32_t ip;
	uint8_t ip6[16];
	int port;
};


void print_ethernet_header(void* in_ethernet_header);
void print_ethernet_vlan_header(void* in_ethernet_header);
void print_ip_header(struct IP_V4_header* ip_header);
void print_packet( char* pkt );
void print_pkt(struct prober_parameters *user_param, char* pkt);
// void print_pkt(void* pkt, struct prober_parameters *user_param);
int parse_mac_from_str(char *mac, u_int8_t *addr);
int parse_ip_from_str(char *ip, u_int32_t *addr);

// void build_pkt_on_buffer(
// 			 struct prober_parameters *user_param,
// 			 uint16_t eth_type, uint16_t ip_next_protocol,
// 			 int print_flag, int pkt_size, int flows_offset);

void build_pkt(struct prober_parameters *user_param, char* packet);

#endif