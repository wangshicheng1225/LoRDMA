#include <iostream>
#include <getopt.h> 
#include <chrono>
#include <math.h>
#include "loadpcap.h"
#include "prober_resources.h"



void print_report_lat (struct prober_parameters *user_param, uint64_t test_size )
{
    printf("print_report_lat, %lu\n", test_size);

    int i;
    int rtt_factor = 2;
    double* delta = NULL;
    const char* units;

    int measure_cnt = test_size - 1;
    units = "usec";

    ALLOCATE(delta, double, measure_cnt);

    double sum = 0.0;
    double max_val = std::numeric_limits<double>::min();
    double min_val = std::numeric_limits<double>::max();

    for (i = 0; i < measure_cnt; ++i) {
        std::chrono::duration<double, std::micro> elapsed_time = user_param->rposted[i] - user_param->tposted[i];
        delta[i] = elapsed_time.count();
        double current_val = delta[i] / rtt_factor;
        sum += current_val;
        
        if (current_val > max_val) {
            max_val = current_val;
        }
        if (current_val < min_val) {
            min_val = current_val;
        }
    }

    double average = sum / measure_cnt;

    // Compute variance
    double variance = 0.0;
    for (i = 0; i < measure_cnt; ++i) {
        variance += pow((delta[i] / rtt_factor) - average, 2);
    }
    variance /= measure_cnt;

    // Compute standard deviation
    double std_dev = sqrt(variance);

    printf("#, %s\n", units);
    for (i = 0; i < measure_cnt; ++i) {
        printf("%d, %g\n", i, delta[i] / rtt_factor);
    }
    printf("Average: %g, Max: %g, Min: %g, Standard Deviation: %g\n", average, max_val, min_val, std_dev);
    

}








int main(int argc, char** argv) {

    uint64_t test_size = 1;
    struct prober_parameters user_param;
    memset(&user_param, 0 , sizeof(struct prober_parameters));
   

    const char* pcap_filename = nullptr;
    int packet_number = 1;
    // int test_size = 1;
    // Define long options
    static struct option long_options[] = {
        // {.name = "device",  .has_arg = 1, .val='d'},
        // {.name = "test-size", .has_arg = 1, .val = 'S'},
        // {.name = "trace-file", .has_arg=1, .val = 'f'},
        // {.name = "pktno", .has_arg=1, .val = 'p'},
        {"device", required_argument, nullptr, 'd'},
        {"test-size", required_argument, nullptr, 'S'},
        {"trace-file", required_argument, nullptr, 'f'},
        {"pktno", required_argument, nullptr, 'p'},
        // {"file", required_argument, nullptr, 'f'},
        // {"packet", required_argument, nullptr, 'p'},
        {nullptr, 0, nullptr, 0}
    };

    int option;
    while ((option = getopt_long(argc, argv, "f:p:S:d:", long_options, nullptr)) != -1) {
        switch (option) {
            case 'd':
                user_param.ib_devname = strdup(optarg);
                printf("device: %s\n", user_param.ib_devname);
                break;
            case 'f':
                pcap_filename = optarg;
                break;
            case 'p':
                packet_number = std::stoi(optarg);
                break;
            case 'S':
                // test_size = std::stoi(optarg);
                user_param.test_size = atoi(optarg);
                test_size = user_param.test_size;
                printf("Test size: %d \n", user_param.test_size);
                break;
            default:
                fprintf(stderr," Invalid arguments.\n");
                fprintf(stderr," Please check command line and run again.\n\n");
                return 1;
        }
    }

    if (pcap_filename == nullptr) {
        std::cerr << "You must specify a pcap file using --trace-file option." << std::endl;
        return 1;
    }

    // char* packet_data = load_pcap(pcap_filename, packet_number);

    PacketData packet = load_pcap(pcap_filename, packet_number);
    if (packet.data != nullptr) {
        std::cout << "Packet " << packet_number << " data length: " << packet.length << std::endl;
        process_packet_data(packet.data); // Print source/destination MAC and IP addresses
        // delete[] packet_data;
    }

    ALLOCATE(user_param.tposted, std::chrono::high_resolution_clock::time_point, test_size);
	memset(user_param.tposted, 0, sizeof(std::chrono::high_resolution_clock::time_point)*test_size);
    ALLOCATE(user_param.rposted, std::chrono::high_resolution_clock::time_point, test_size);
    memset(user_param.rposted, 0, sizeof(std::chrono::high_resolution_clock::time_point)*test_size);


    char send_buffer[ENTRY_SIZE*RQ_NUM_DESC]={0};
    char recv_buffer[ENTRY_SIZE*RQ_NUM_DESC]={0};
    int i;
    
   
    struct ibv_cq *send_cq;
    struct ibv_cq *recv_cq;
    struct ibv_qp *qp;
    uint32_t lkey;
    int dev_nb;
    struct ibv_device **dev = ibv_get_device_list(&dev_nb);
    assert(dev && dev_nb && "ibv_get_device_list() failed");

    
    for (i=0; i<dev_nb; i++)
        if (0 == strcmp(dev[i]->name, user_param.ib_devname))
            break;
    assert(i != dev_nb && "device not found");

    struct ibv_context *ctx = ibv_open_device(dev[i]);
    assert(ctx && "ibv_open_device() failed");

    send_cq = ibv_create_cq(ctx, SQ_NUM_DESC, 0, 0, 0);
    assert(send_cq && "ibv_create_cq() failed");

    recv_cq = ibv_create_cq(ctx, RQ_NUM_DESC, 0, 0, 0);
    assert(send_cq && "ibv_create_cq() failed");

    struct ibv_pd *pd = ibv_alloc_pd(ctx);
    assert(pd && "ibv_alloc_pd() failed");

    struct ibv_qp_init_attr qpia = {0};
    qpia.send_cq = send_cq;
    qpia.recv_cq = recv_cq;
    qpia.cap.max_send_wr = SQ_NUM_DESC;
    qpia.cap.max_send_sge = 1;
    qpia.cap.max_recv_wr = RQ_NUM_DESC;
    qpia.cap.max_recv_sge = 1;
    qpia.qp_type = IBV_QPT_RAW_PACKET;
    

    qp = ibv_create_qp(pd, &qpia);
    assert(qp  && "ibv_create_qp() failed");
    

    struct ibv_qp_attr qpa;
    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state = IBV_QPS_INIT;
    qpa.port_num = 1;

    
    int err = ibv_modify_qp (qp, &qpa, IBV_QP_STATE | IBV_QP_PORT);
    assert(0 == err && "ibv_modify_qp(INIT) failed");
    

    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state = IBV_QPS_RTR;

    err = ibv_modify_qp (qp, &qpa, IBV_QP_STATE);
    assert(0 == err && "ibv_modify_qp(RTR) failed");
    

    memset(&qpa, 0, sizeof(qpa));
    qpa.qp_state = IBV_QPS_RTS;
    
    err = ibv_modify_qp(qp, &qpa, IBV_QP_STATE);
    assert(0 == err && "ibv_modify_qp(RTS) failed");
    
    int buf_size = ENTRY_SIZE*RQ_NUM_DESC; /* maximum size of data to be accessed by hardware */
    void *buf;
    buf = malloc(buf_size);
    if (!buf) {
        fprintf(stderr, "Coudln't allocate memory\n");
        exit(1);
    }

    // printf("Register the user memory\n");
    /*  Register the user memory so it can be accessed by the HW directly */

    // struct ibv_mr *mr = ibv_reg_mr(pd, buf, buf_size, IBV_ACCESS_LOCAL_WRITE);
    // assert(mr && "ibv_reg_mr() failed");
    // lkey = mr->lkey;

    // reg send mr
    struct ibv_mr* send_mr = ibv_reg_mr(pd, send_buffer, ENTRY_SIZE*SQ_NUM_DESC, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_WRITE);
    if (!send_mr) {
        fprintf(stderr, "send_mr ibv_reg_mr() failed");
        exit(1);
    }

    // reg recv 
    struct ibv_mr* recv_mr = ibv_reg_mr(pd, recv_buffer, ENTRY_SIZE*RQ_NUM_DESC, IBV_ACCESS_LOCAL_WRITE | IBV_ACCESS_REMOTE_READ);
    if (!recv_mr) {
        fprintf(stderr, "recv_mr ibv_reg_mr() failed");
        exit(1);
    }

    size_t cr_packet_len = 0;
    cr_packet_len =  packet.length;
    // memcpy(buf, packet.data, cr_packet_len);
    memcpy(send_buffer, packet.data, cr_packet_len);
    

    static struct ibv_sge send_sge, recv_sge;
    static struct ibv_recv_wr recv_wr, *bad_recv_wr;
    static struct ibv_send_wr send_wr, *bad_send_wr;
    int n = 1;
    int send_msgs_completed, recv_msgs_complete;
    struct ibv_wc send_wc, recv_wc;
     /* Attach all buffers to the ring */

    // prepare for send
    /* scatter/gather entry describes location and size of data to send*/
    send_sge.addr = (uint64_t)send_buffer;
    send_sge.length = cr_packet_len;
    send_sge.lkey = send_mr->lkey;
    memset(&send_wr, 0, sizeof(send_wr));

    send_wr.wr_id = 1;
    send_wr.num_sge = 1;
    send_wr.sg_list = &send_sge;
    send_wr.next = NULL;
    send_wr.opcode = IBV_WR_SEND;
    send_wr.send_flags = IBV_SEND_SIGNALED;
    
    // send operation
    // send_wr.send_flags = IBV_SEND_INLINE; // uncommenting will casue dead loop in 'send_msgs_completed = ibv_poll_cq(send_cq, 1, &send_wc);'
    // send_wr.wr_id = n;
    // send_wr.send_flags |= IBV_SEND_SIGNALED;

    // prepare for recv
    /* pointer to packet buffer size and memory key of each packet buffer */
    recv_sge.addr = (uint64_t)recv_buffer;
    recv_sge.length = cr_packet_len;
    recv_sge.lkey = recv_mr->lkey;
    /*
    * descriptor for receive transaction - details:
    * - how many pointers to receive buffers to use
    * - if this is a single descriptor or a list (next == NULL single)
    */
    recv_wr.num_sge = 1;
    recv_wr.sg_list = &recv_sge;
    recv_wr.next = NULL;
    recv_wr.wr_id = 1;
    // printf("ibv_post recv\n");
    ibv_post_recv(qp, &recv_wr, &bad_recv_wr);
    // printf("after ibv_post recv\n");

    

    /* initialize sniffer rules to get copy of all traffic */
    struct ibv_flow_attr fa = {0};
    //TODO: intercept the packets by IP
    
    fa.type = IBV_FLOW_ATTR_SNIFFER;
    fa.size = sizeof(fa);
    fa.port = 1;
    struct ibv_flow *flow = ibv_create_flow(qp, &fa);
    assert(flow && "ibv_create_flow() failed");



    int recv_msgs_completed;

    // setup
    uint64_t scnt = 0;
    uint64_t rcnt = 0;
    int ne;
    err = 0;
    struct ibv_wc wc;


    /* push descriptor to hardware */
    
    scnt = 0;
    
    int ret = ibv_post_send(qp, &send_wr, &bad_send_wr);
    if (ret < 0) {
        fprintf(stderr, "failed in post send\n");
        exit(1);
    }

    n++;
    // printf("ibv_poll_cq send_cq\n");

    do
    { send_msgs_completed = ibv_poll_cq(send_cq, 1, &send_wc);}
    while(send_msgs_completed == 0);
    
    // printf("send_msgs_completed: %d\n",send_msgs_completed);
    if (send_msgs_completed < 0) {
        printf("Polling send_msgs_completed error\n");
        exit(1);
    }
    user_param.tposted[scnt] = std::chrono::high_resolution_clock::now();
    scnt ++;
    // user_param.iters ++;
    // printf("begin big while\n");
    while(user_param.iters < test_size) {
        // printf("In big while: %lu, %lu, %lu\n", user_param.iters, scnt, rcnt);
        
        if (ibv_post_recv(qp, &recv_wr, &bad_recv_wr)) {
                fprintf(stderr, "Couldn't post recv: rcnt=%lu\n", rcnt);
                return 15;
        }
        
        do
        {
            recv_msgs_completed = ibv_poll_cq(recv_cq, 1, &recv_wc);
        } while (recv_msgs_completed == 0);
        

        
        if (recv_msgs_completed < 0) {
            printf("Polling error\n");
            exit(1);
        }
        if (recv_wc.status != IBV_WC_SUCCESS) {
            NOTIFY_COMP_ERROR_RECV(recv_wc,rcnt);
            return 1;
        }
        if (recv_msgs_completed > 0) {
            // printf("recv_msgs_completed > 0, %lu\n", rcnt);
            user_param.rposted[rcnt] = std::chrono::high_resolution_clock::now();;
            rcnt++;
            user_param.iters++;
            // printf("message %ld received size %d\n", recv_wc.wr_id, recv_wc.byte_len);
            // recv_sge.addr = (uint64_t)recv_buffer;
            // recv_wr.wr_id = recv_wc.wr_id;

        } 
        
        
        // printf("In big while: %lu, %lu, %lu\n", user_param.iters, scnt, rcnt);
        if (scnt <= user_param.iters )
        {
            
            err = ibv_post_send(qp, &send_wr, &bad_send_wr);

            if (err) {
				fprintf(stderr,"Couldn't post send: scnt=%lu \n",scnt);
				return 1;
			}
            do
            { send_msgs_completed = ibv_poll_cq(send_cq, 1, &send_wc);}
            while(send_msgs_completed == 0);
            
            if (send_msgs_completed < 0) {
                fprintf(stderr, "poll on Send CQ failed %d\n", send_msgs_completed);
                exit(1);
            }
            user_param.tposted[scnt] = std::chrono::high_resolution_clock::now();
            scnt++;
        }

        

    }

    print_report_lat(&user_param, test_size);
    


    return 0;
}

