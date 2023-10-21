#include "prober_resources.h"
#include <arpa/inet.h>


void print_packet( char* pkt )
{

	const size_t DST_MAC_OFFSET = 0;
	const size_t SRC_MAC_OFFSET = 6;
	const size_t SRC_IP_OFFSET = 26;
	const size_t DST_IP_OFFSET = 30;
	uint8_t				src_mac[6];
	uint8_t				dst_mac[6];

	memcpy(dst_mac, pkt + DST_MAC_OFFSET, sizeof(dst_mac));
	memcpy(src_mac, pkt + SRC_MAC_OFFSET, sizeof(src_mac));
	if(NULL == pkt) {
		printf("pkt is null:error happened can't print packet\n");
		return;
	}
	printf("**raw ethernet header****************************************\n\n");
	printf("--------------------------------------------------------------\n");
	printf("| Dest MAC         | Src MAC          | Packet Type          |\n");
	printf("|------------------------------------------------------------|\n");
	
	printf("|");
	printf(PERF_MAC_FMT,
			dst_mac[0],
			dst_mac[1],
			dst_mac[2],
			dst_mac[3],
			dst_mac[4],
			dst_mac[5]);
	printf("|");
	printf(PERF_MAC_FMT,
			src_mac[0],
			src_mac[1],
			src_mac[2],
			src_mac[3],
			src_mac[4],
			src_mac[5]);
	printf("|");
	// char* eth_type = etype_str((ntohs(user_param->ethertype)));
	// printf("%-22s|\n",eth_type);
	printf("%-22s|\n","IPv4");
	printf("|------------------------------------------------------------|\n\n");

	char str_ip_s[INET_ADDRSTRLEN];
	char str_ip_d[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, (pkt + SRC_IP_OFFSET), str_ip_s, INET_ADDRSTRLEN);
	printf("|Source IP |%-12s|\n",str_ip_s);
	inet_ntop(AF_INET, (pkt + DST_IP_OFFSET), str_ip_d, INET_ADDRSTRLEN);
	printf("|Dest IP   |%-12s|\n",str_ip_d);
	printf("|-----------------------|\n\n");
}
void print_pkt( struct prober_parameters *user_param, char* pkt )
{

	
	if(NULL == pkt) {
		printf("pkt is null:error happened can't print packet\n");
		return;
	}
	printf("**raw ethernet header****************************************\n\n");
	printf("--------------------------------------------------------------\n");
	printf("| Dest MAC         | Src MAC          | Packet Type          |\n");
	printf("|------------------------------------------------------------|\n");
	
	printf("|");
	printf(PERF_MAC_FMT,
			user_param->dst_mac[0],
			user_param->dst_mac[1],
			user_param->dst_mac[2],
			user_param->dst_mac[3],
			user_param->dst_mac[4],
			user_param->dst_mac[5]);
	printf("|");
	printf(PERF_MAC_FMT,
			user_param->src_mac[0],
			user_param->src_mac[1],
			user_param->src_mac[2],
			user_param->src_mac[3],
			user_param->src_mac[4],
			user_param->src_mac[5]);
	printf("|");
	// char* eth_type = etype_str((ntohs(user_param->ethertype)));
	// printf("%-22s|\n",eth_type);
	printf(" IPv4 |\n");
	printf("|------------------------------------------------------------|\n\n");

	char str_ip_s[INET_ADDRSTRLEN];
	char str_ip_d[INET_ADDRSTRLEN];

	inet_ntop(AF_INET, &user_param->src_ip, str_ip_s, INET_ADDRSTRLEN);
	printf("|Source IP |%-12s|\n",str_ip_s);
	inet_ntop(AF_INET, &user_param->dst_ip, str_ip_d, INET_ADDRSTRLEN);
	printf("|Dest IP   |%-12s|\n",str_ip_d);
	printf("|-----------------------|\n\n");

	
}

/******************************************************************************
 *
 ******************************************************************************/
// void print_ethernet_header(void* in_ethernet_header)
// {
// 	struct ETH_header* p_ethernet_header = in_ethernet_header;
// 	if (NULL == p_ethernet_header) {
// 		fprintf(stderr, "ETH_header pointer is Null\n");
// 		return;
// 	}

// 	printf("**raw ethernet header****************************************\n\n");
// 	printf("--------------------------------------------------------------\n");
// 	printf("| Dest MAC         | Src MAC          | Packet Type          |\n");
// 	printf("|------------------------------------------------------------|\n");
// 	printf("|");
// 	printf(PERF_MAC_FMT,
// 			p_ethernet_header->dst_mac[0],
// 			p_ethernet_header->dst_mac[1],
// 			p_ethernet_header->dst_mac[2],
// 			p_ethernet_header->dst_mac[3],
// 			p_ethernet_header->dst_mac[4],
// 			p_ethernet_header->dst_mac[5]);
// 	printf("|");
// 	printf(PERF_MAC_FMT,
// 			p_ethernet_header->src_mac[0],
// 			p_ethernet_header->src_mac[1],
// 			p_ethernet_header->src_mac[2],
// 			p_ethernet_header->src_mac[3],
// 			p_ethernet_header->src_mac[4],
// 			p_ethernet_header->src_mac[5]);
// 	printf("|");
// 	char* eth_type = etype_str((ntohs(p_ethernet_header->eth_type)));
// 	printf("%-22s|\n",eth_type);
// 	printf("|------------------------------------------------------------|\n\n");
	


// }
// /******************************************************************************
// *
// ******************************************************************************/
// void print_ethernet_vlan_header(void* in_ethernet_header)
// {
// 	struct ETH_vlan_header* p_ethernet_header = in_ethernet_header;
//         if (NULL == p_ethernet_header) {
//                 fprintf(stderr, "ETH_header pointer is Null\n");
//                 return;
//         }

//         printf("**raw ethernet header****************************************\n\n");
//         printf("----------------------------------------------------------------------------\n");
//         printf("| Dest MAC         | Src MAC          |    vlan tag    |   Packet Type     |\n");
//         printf("|--------------------------------------------------------------------------|\n");
//         printf("|");
//         printf(PERF_MAC_FMT,
//                         p_ethernet_header->dst_mac[0],
//                         p_ethernet_header->dst_mac[1],
//                         p_ethernet_header->dst_mac[2],
//                         p_ethernet_header->dst_mac[3],
//                         p_ethernet_header->dst_mac[4],
//                         p_ethernet_header->dst_mac[5]);
//         printf("|");
//         printf(PERF_MAC_FMT,
//                         p_ethernet_header->src_mac[0],
//                         p_ethernet_header->src_mac[1],
//                         p_ethernet_header->src_mac[2],
//                         p_ethernet_header->src_mac[3],
//                         p_ethernet_header->src_mac[4],
//                         p_ethernet_header->src_mac[5]);
//         printf("|");
//         printf("   0x%08x   ",ntohl(p_ethernet_header->vlan_header));

//         printf("|");
//         char* eth_type = (ntohs(p_ethernet_header->eth_type) ==  IP_ETHER_TYPE ? "IP" : "DEFAULT");
//         printf("%-19s|\n",eth_type);
//         printf("|--------------------------------------------------------------------------|\n\n");

// }
// void print_ip_header(struct IP_V4_header* ip_header)
// {
// 	char str_ip_s[INET_ADDRSTRLEN];
// 	char str_ip_d[INET_ADDRSTRLEN];

// 	if (NULL == ip_header) {
// 		fprintf(stderr, "IP_V4_header pointer is Null\n");
// 		return;
// 	}

// 	printf("**IP header**************\n");
// 	printf("|-----------------------|\n");
// 	printf("|Version   |%-12d|\n",ip_header->version);
// 	printf("|Ihl       |%-12d|\n",ip_header->ihl);
// 	printf("|TOS       |%-12d|\n",ip_header->tos);
// 	printf("|TOT LEN   |%-12d|\n",ntohs(ip_header->tot_len));
// 	printf("|ID        |%-12d|\n",ntohs(ip_header->id));
// 	printf("|Frag      |%-12d|\n",ntohs(ip_header->frag_off));
// 	printf("|TTL       |%-12d|\n",ip_header->ttl);

// 	if (ip_header->protocol)
// 		printf("|protocol  |%-12s|\n",ip_header->protocol == UDP_PROTOCOL ? "UDP" : "TCP");
// 	else
// 		printf("|protocol  |%-12s|\n","EMPTY");
// 	printf("|Check sum |%-12X|\n",ntohs(ip_header->check));
// 	inet_ntop(AF_INET, &ip_header->saddr, str_ip_s, INET_ADDRSTRLEN);
// 	printf("|Source IP |%-12s|\n",str_ip_s);
// 	inet_ntop(AF_INET, &ip_header->daddr, str_ip_d, INET_ADDRSTRLEN);
// 	printf("|Dest IP   |%-12s|\n",str_ip_d);
// 	printf("|-----------------------|\n\n");
// }



int parse_ip_from_str(char *ip, u_int32_t *addr)
{
	return inet_pton(AF_INET, ip, addr);
}

// void build_pkt_on_buffer(
// 			 struct prober_parameters *user_param,
// 			 uint16_t eth_type, uint16_t ip_next_protocol,
// 			 int print_flag, int pkt_size, int flows_offset)
// {

// }


void build_pkt(struct prober_parameters *user_param, char* packet)
{

}

int parse_mac_from_str(char *mac, u_int8_t *addr)
{
	char tmpMac[MAC_LEN+1];
	char *tmpField;
	int fieldNum = 0;

	if (strlen(mac) != MAC_LEN) {
		fprintf(stderr, "invalid MAC length\n");
		return FAILURE;
	}
	if (addr == NULL) {
		fprintf(stderr, "invalid  output addr array\n");
		return FAILURE;
	}

	strcpy(tmpMac, mac);
	tmpField = strtok(tmpMac, ":");
	while (tmpField != NULL && fieldNum < MAC_ARR_LEN) {
		char *chk;
		int tmpVal;
		tmpVal = strtoul(tmpField, &chk, HEX_BASE);
		if (tmpVal > 0xff) {
			fprintf(stderr, "field %d value %X out of range\n", fieldNum, tmpVal);
			return FAILURE;
		}
		if (*chk != 0) {
			fprintf(stderr, "Non-digit character %c (%0x) detected in field %d\n", *chk, *chk, fieldNum);
			return FAILURE;
		}
		addr[fieldNum++] = (u_int8_t) tmpVal;
		tmpField = strtok(NULL, ":");
	}
	if (tmpField != NULL || fieldNum != MAC_ARR_LEN) {
		fprintf(stderr, "MAC address longer than six fields\n");
		return FAILURE;
	}
	return SUCCESS;
}
// static int parse_ethertype_from_str(char *ether_str, uint16_t *ethertype_val)
// {
// 	if (strlen(ether_str) != ETHERTYPE_LEN) {
// 		fprintf(stderr, "invalid ethertype length\n");
// 		return FAILURE;
// 	}
// 	*ethertype_val = strtoul(ether_str, NULL, HEX_BASE);
// 	if (!*ethertype_val)
// 		return FAILURE;
// 	return SUCCESS;
// }