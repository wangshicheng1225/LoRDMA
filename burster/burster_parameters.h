
#ifndef BURSTER_PARAMETERS_H
#define BURSTER_PARAMETERS_H
#define RawEth  (3)
#define LOADTRACE (1)
#include <assert.h>
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

struct burster_parameters
{
    int port;
    char *ib_devname;
    char *servername;
    uint32_t ib_port;
    uint32_t gid_idx;
    uint16_t udp_sport;
    int mtu;
    enum ibv_mtu curr_mtu;

    int connection_type;
    int tcp;


    int interval;
    int peakrate; // Gbps
    int duration; // microsecond

    uint32_t TXsize;
    uint32_t TXnum;
	uint32_t qp_num;

    int if_load;
    const char* trace_file_name;
    // to be continued
};


struct burster_context {
        
    struct ibv_device_attr* device_attr; /* Device attributes */
    struct ibv_port_attr* port_attr;     /* IB port attributes */
    struct ibv_context *ib_ctx;         /* device handle */
    char *buf;                          /* memory buffer pointer, used for RDMA and send ops */
    
	struct rdma_event_channel		*cm_channel;
	struct rdma_cm_id			*cm_id_control;
	struct rdma_cm_id			*cm_id;
	struct ibv_comp_channel			*channel;
	struct ibv_pd				*pd;
	struct ibv_mr				*mr;
    struct ibv_cq               *cq;
	struct ibv_cq				*send_cq;
	struct ibv_cq				*recv_cq;
	// void					**buf;
	struct ibv_ah				*ah;
	struct ibv_qp				*qp;
	struct ibv_srq				*srq;
	struct ibv_sge				*sge_list;
	struct ibv_sge				*recv_sge_list;
	struct ibv_send_wr			*wr;
	struct ibv_recv_wr			*rwr;
	uint64_t				size;
	uint64_t				*my_addr;
	uint64_t				*rx_buffer_addr;
	uint64_t				*rem_addr;
	uint32_t 				*rem_qpn;
	uint64_t				buff_size;
	uint64_t				send_qp_buff_size;
	uint64_t				flow_buff_size;
	int					tx_depth;
	int					huge_shmid;
	uint64_t				*scnt;
	uint64_t				*ccnt;
	int					is_contig_supported;
	uint32_t				*r_dctn;
	uint32_t				*dci_stream_id;
	int 					dek_number;
	uint32_t                                *ctrl_buf;
	uint32_t                                *credit_buf;
	struct ibv_mr                           *credit_mr;
	struct ibv_sge                          *ctrl_sge_list;
	struct ibv_send_wr                      *ctrl_wr;
	int                                     send_rcredit;
	int                                     credit_cnt;
	int					cache_line_size;
	int					cycle_buffer;
	int					rposted;
};

 struct burster_dest {
	int 				lid;
	int 				out_reads;
	int 				qpn;
	int 				psn;
	unsigned			rkey;
	unsigned long long		vaddr;
	union ibv_gid			gid;
	unsigned			srqn;
	int				gid_index;
 };



struct packet {
    uintptr_t addr;
    int len;
};


#endif // BURSTER_PARAMETERS_H