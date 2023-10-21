#include <assert.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <malloc.h>
#include <getopt.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <inttypes.h>
#include <infiniband/verbs.h>
#include <pthread.h>
#include "burster_parameters.h"
#include "ethernet_resources.h"
#define ALIGNED __attribute__((aligned(64)))

#define TXSZ    2048
#define TXNB 16


int timer_done = 0;
double microsec_counter = 0;
void* timer_thread(void* duration_limit_ptr)
{
   
    double duration_limit = *( (double *) duration_limit_ptr);
    printf("timer thread start with duration limit: %f\n", duration_limit);
    struct timeval last0;
    gettimeofday(&last0, 0);
    struct timeval now0;    
    microsec_counter = 0;
    while(1)
    {

        gettimeofday(&now0, 0);
        timersub(&now0, &last0, &last0);
        
        double microsec = last0.tv_sec*1e6 + last0.tv_usec;
        microsec_counter += microsec;
        last0 = now0;

        if (microsec_counter > duration_limit)
        {
            break;
        }
    
    }
    timer_done = 1;
    return NULL;
}



static const char packet1[] ALIGNED = {
    /* ethernet: dst=00:0c:41:82:b2:53, src=00:d0:59:6c:40:4e, type=0x0800 (IPv4) */
    0x00, 0x0c, 0x41, 0x82, 0xb2, 0x53, 0x00, 0xd0, 0x59, 0x6c, 0x40, 0x4e, 0x08, 0x00,
    /* ipv4: src=192.168.50.50, dst=192.168.0.1, proto=17 (UDP) */
    0x45, 0x00, 0x00, 0x3d, 0x0a, 0x41, 0x00, 0x00, 0x80, 0x11, 0x7c, 0xeb, 0xc0, 0xa8, 0x32, 0x32, 0xc0, 0xa8, 0x00, 0x01,
    /* udp: sport=1026, dport=53 */
    0x04, 0x02, 0x00, 0x35, 0x00, 0x29, 0x01, 0xab,
    /* DNS Standard query 0x002b A us.pool.ntp.org */
    0x00, 0x2b, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x75, 0x73, 0x04, 0x70, 0x6f, 0x6f, 0x6c, 0x03, 0x6e, 0x74, 0x70, 0x03, 0x6f, 0x72, 0x67, 0x00, 0x00, 0x01, 0x00, 0x01
};

static struct packet packet1_ = {
    .addr = (uintptr_t)packet1,
    .len = sizeof(packet1)
};

/* default to packet1 */
static struct packet *packets = &packet1_;
static unsigned packets_nb = 1;
static const void *packets_mr_addr = packet1;
static size_t packets_mr_len = sizeof(packet1);

static void load_pcap(const char *fname)
{
    packets = 0;
    packets_nb = 0;
    packets_mr_addr = 0;
    packets_mr_len = 0;

    int fd = open(fname, O_RDONLY);
    assert(fd >= 0 && "open() failed");

    struct stat stat;
    int err = fstat(fd, &stat);
    assert(0 == err && "fstat() failed");
    assert(stat.st_size >= 24 + 16 + 64); /* we want at least 1 64B packet */

    const struct {
        uint32_t magic;
        uint32_t version;
        uint32_t tz_offset;
        uint32_t ts_acc;
        uint32_t snap_len;
        uint32_t ll_type;
    } *pcap = mmap(0, stat.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    assert(MAP_FAILED != pcap && "mmap() failed");
    assert(0xa1b2c3d4 == pcap->magic);
    assert(0x00040002 == pcap->version);
    assert(0 == pcap->tz_offset);
    assert(0 == pcap->ts_acc);
    assert(pcap->snap_len >= 64);
    assert(1 == pcap->ll_type); 

    const struct {
        uint32_t ts_sec;
        uint32_t ts_usec;
        uint32_t cap_len;
        uint32_t wire_len;
        uint8_t data[];
    } *pkt;
    for (pkt = (void *)(pcap + 1);
            (uintptr_t)pkt + sizeof(*pkt) < (uintptr_t)pcap + stat.st_size;
            pkt = (void *)(pkt->data + pkt->cap_len)) {
        assert((uintptr_t)pkt->data + pkt->cap_len <= (uintptr_t)pcap + stat.st_size);
        packets_nb++;
        if (0 == (packets_nb & (packets_nb - 1)))
            packets = realloc(packets, packets_nb * 2 * sizeof(packets[0]));
        packets[packets_nb-1].addr = (uintptr_t)pkt->data;
        packets[packets_nb-1].len = pkt->cap_len;
    }

    packets_mr_addr = pcap;
    packets_mr_len = stat.st_size;
}

void usage()
{
    printf("Usage\n");
}

int main(int argc, char **argv)
{

    // parse the parameters
    struct ibv_device *ib_dev = NULL;
    struct burster_context *ctx;
    struct burster_parameters *user_param;
    struct ibv_flow			**flow_create_result;
	struct ibv_flow_attr		**flow_rules;
	struct ibv_flow 		**flow_promisc = NULL ;
    int flow_index, qp_index;
    
    /* init default values to user's parameters */
    ctx = malloc(sizeof(struct burster_context));
    user_param = malloc(sizeof(struct burster_parameters));
    // init the default burst parameter
    user_param->duration = 1000; // 1ms
    user_param->qp_num = 1;
    user_param->TXnum = TXNB;
    user_param->TXsize = TXSZ;
    int opt;
    int c = 0;
    const char* trace_file_name;
    while(1) {
        static const struct option long_options[] = {
            {.name = "device",  .has_arg = 1, .val='d'},
            {.name = "ib-port", .has_arg = 1, .val = 'i' },
            {.name = "gid-idx", .has_arg = 1, .val = 'g' },
            {.name = "trace-file", .has_arg=1, .val = 'f'},
            {.name = "qpnum", .has_arg = 1, .val='q'},
            {.name = "txsize", .has_arg = 1, .val = 'S'},
            {.name = "txnum", .has_arg = 1, .val = 'N'},
			{.name = "help",    .has_arg = 0, .val = 'h' },
            {.name = "duration", .has_arg= 1, .val = 't'},
            {.name = "interval", .has_arg=1, .val='T'}
        };

        c = getopt_long(argc, argv, "hd:i:g:f:q:S:N:t:", long_options, NULL);
    
        if (c==-1)
            break;
        switch(c) {
            case 'd':
                // device name
                user_param->ib_devname = strdup(optarg);
                printf("device: %s\n", user_param->ib_devname);
                break;
            case 'i':
                user_param->ib_port = strtoul(optarg, NULL, 0);
                if(user_param->ib_port < 0)
                {
                    fprintf(stderr,"illegal ib_port spec\n");
                    return 1;
                }
                printf("ib-port: %u \n", user_param->ib_port);
                break;
            case 'q':
                user_param->qp_num = strtoul(optarg, NULL, 0);
                if(user_param->qp_num < 0)
                {
                    fprintf(stderr,"illegal qp_num spec\n");
                    return 1;
                }
                printf("ib-port: %u \n", user_param->qp_num);
                break;
            case 'g':
                user_param->gid_idx = strtoul(optarg, NULL, 0);
                if(user_param->gid_idx < 0)
                {
                    fprintf(stderr,"illegal gid_idx spec\n");
                    return 1;
                }
                printf("GID : %d \n", user_param->gid_idx);
                break;
            case 'S':
                user_param->TXsize = atoi(optarg);
                printf("TX size: %d \n", user_param->TXsize);
                break;
            case 'N':
                user_param->TXnum = atoi(optarg);
                printf("TX number: %d \n", user_param->TXnum);
                break;
            case 't':
                user_param->duration = atoi(optarg);
                printf("Burst duraion time: %d microsecond(s) \n", user_param->duration);
                break;
            case 'T':
                user_param->interval = atoi(optarg);
                printf("Burst interval time: %d microsecond(s) \n", user_param->duration);
                break;
            case 'f':
                user_param->trace_file_name = strdup(optarg);
                user_param->if_load = LOADTRACE;
                printf("trace file name: %s \n", user_param->trace_file_name);
                break;
            case 'h': 
                usage();
                return 1;
                break;
            default:
                fprintf(stderr," Invalid arguments.\n");
                fprintf(stderr," Please check command line and run again.\n\n");
                return 1;
        }
    }
    if(optind == argc - 1)
    {
        printf("argv[optind]: %s \n",argv[optind] );
    }
    else if (optind < argc)
    {
        return 1;
    }
    else 
    {
        printf("arguments done\n");
    }

    // craft the packet bytes (load the pcap or craft)
    if (user_param->if_load)
    {
        load_pcap(user_param->trace_file_name);
    }
    else // software craft 
    {
        __builtin_prefetch(packet1 +  0, 0, 1);
        __builtin_prefetch(packet1 + 64, 0, 1);
    }




    // Using the pipeline arch to burst !

    struct ibv_device **dev_list = NULL;
    struct ibv_qp_init_attr qp_init_attr;

    int i,j;

    int cq_size = 0;
    int num_devices;
    int rc = 0;
    dev_list = ibv_get_device_list(&num_devices);
    if (!dev_list)
    {
        fprintf(stderr, "failed to get IB devs \n");
        rc = 1;
        exit(1);
    }

    if (!num_devices)
    {
        fprintf(stderr, "found %d devs \n", num_devices);
        rc = 1;
        exit(1);
    }
    fprintf(stdout, "found %d devs \n", num_devices);
    for (i = 0; i < num_devices; i ++ )
    {
        fprintf(stdout, "find dev %s \n", strdup(ibv_get_device_name(dev_list[i])));
       
        if(!strcmp(ibv_get_device_name(dev_list[i]), user_param->ib_devname))
        {
            ib_dev = dev_list[i];
            break;
        }
    }
    assert(i != num_devices && "dev not found");
    /* if the device wasn't found in host */
    if(!ib_dev)
    {
        fprintf(stderr, "IB device %s wasn't found\n", user_param->ib_devname);
        rc = 1;
        exit(1);
    }

    /* get device handle */
    ctx->ib_ctx = ibv_open_device(ib_dev);
    
    if(!ctx->ib_ctx)
    {
        fprintf(stderr, "failed to open device %s\n", user_param->ib_devname);
        rc = 1;
        exit(1);
    }

    ibv_free_device_list(dev_list);
    dev_list = NULL;
    ib_dev = NULL;


   /* allocate Protection Domain */
    ctx->pd = ibv_alloc_pd(ctx->ib_ctx);
    if(!ctx->pd)
    {
        fprintf(stderr, "ibv_alloc_pd failed\n");
        rc = 1;
        exit(1);
    }

    cq_size = 1 * user_param->TXnum; 
    
    ctx->cq = ibv_create_cq(ctx->ib_ctx, cq_size, NULL, NULL, 0);
    if(!ctx->cq)
    {
        fprintf(stderr, "failed to create CQ with %u entries\n", cq_size);
        rc = 1;
        exit(1);
    }



    uint32_t lkey;

    struct ibv_qp_init_attr qpia = {0};
    qpia.send_cq = ctx->cq;
    qpia.recv_cq = ctx->cq;
    qpia.cap.max_send_wr =  1 * user_param->TXnum * user_param->TXsize;
    qpia.cap.max_send_sge = 1;
    qpia.cap.max_recv_wr = 0;
    qpia.cap.max_recv_sge = 1;
    qpia.qp_type = IBV_QPT_RAW_PACKET;
    ctx->qp = ibv_create_qp( ctx->pd, &qpia);
    assert(ctx->qp && "ibv_create_qp() failed");

    struct ibv_qp_attr qpa = {0};
    qpa.qp_state = IBV_QPS_INIT;
    qpa.port_num = 1;
    int err = ibv_modify_qp (ctx->qp, &qpa, IBV_QP_STATE | IBV_QP_PORT);
    assert(0 == err && "ibv_modify_qp(INIT) failed");

    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state = IBV_QPS_RTR;
    err = ibv_modify_qp (ctx->qp, &qpa, IBV_QP_STATE);
    assert(0 == err && "ibv_modify_qp(RTR) failed");

    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state = IBV_QPS_RTS;
    err = ibv_modify_qp (ctx->qp, &qpa, IBV_QP_STATE);
    assert(0 == err && "ibv_modify_qp(RTS) failed");

    struct ibv_mr *mr = ibv_reg_mr(ctx->pd, (void*)packets_mr_addr, packets_mr_len, 0);
    assert(mr && "ibv_reg_mr() failed");
    lkey = mr->lkey;
 

    static struct ibv_sge sge[TXNB][TXSZ] ALIGNED;
    static struct ibv_send_wr wr[TXNB][TXSZ] ALIGNED;


    

    for (i=0; i<user_param->TXnum; i++) {
        for (j=0; j<user_param->TXsize; j++) {
            int pktid = (i*user_param->TXsize+j) % packets_nb;
            sge[i][j].addr = packets[pktid].addr;
            sge[i][j].length = packets[pktid].len;
            sge[i][j].lkey = lkey;
            wr[i][j].wr_id = i;
            wr[i][j].next = &wr[i][j+1];
            wr[i][j].sg_list = &sge[i][j];
            wr[i][j].num_sge = 1;
            wr[i][j].opcode = IBV_WR_SEND;
        }
        wr[i][user_param->TXsize-1].next = 0;
        wr[i][user_param->TXsize-1].send_flags = IBV_SEND_SIGNALED;
    }

    /* fill the pipeline */

    pthread_t thread1, thread2; 
    double duration_limit =  user_param->duration*1.0; // microsecond
    double interval_limit = user_param->interval*1.0; // microsecond
    unsigned long tx = 0;
    unsigned long refresh = 1;
    struct timeval last;   
    struct timeval intervallast;
    struct timeval intervalnow;
    double interval_microsec=0;
    double interval_microsec_counter = 0;
    
    static struct ibv_wc wc[TXNB] ALIGNED;    
    pthread_create(&thread1, NULL, timer_thread, (void*)&duration_limit);


    for (i=0; i<user_param->TXnum; i++) {
        int err = ibv_post_send(ctx->qp, wr[i], 0);
        assert(0 == err && "ibv_post_send() failed");
    }
    int period = 0;
    gettimeofday(&last, 0);

    for (;;) {
        
        int nb = ibv_poll_cq (ctx->cq, user_param->TXnum, wc);
        assert(nb >= 0 && "ibv_poll_cq() failed");

        for (i=0; i<nb; i++) {
            int err = ibv_post_send(ctx->qp, wr[wc[i].wr_id], 0);
            assert(0 == err && "ibv_post_send() failed");
        }
        tx += nb;
        
        if (timer_done)
        {
            printf("------------BURST Timer period %d over---------------\n",period);
            period += 1;
            printf("duration spec: %f\n", duration_limit);
            printf("duration usage: %f us = %f s \n", microsec_counter, microsec_counter*1e-6);
            printf("wating for interval: %f\n", interval_limit);
            interval_microsec_counter = 0;
            gettimeofday(&intervallast, 0);
            while(1)
            {

                gettimeofday(&intervalnow, 0);
                timersub(&intervalnow, &intervallast, &intervallast);
                
                interval_microsec = intervallast.tv_sec*1e6 + intervallast.tv_usec;
                interval_microsec_counter += interval_microsec;
                intervallast = intervalnow;

                if (interval_microsec_counter > interval_limit  )
                {
                    break;
                }
            
            }
            printf("wating  %f us = %f s over, begin to burst\n", interval_microsec_counter, interval_microsec_counter*1e-6);
            timer_done = 0;
            pthread_create(&thread1, NULL, timer_thread, (void*)&duration_limit);
        }
         
    }
    
   
    return 0;

}
