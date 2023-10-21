# LoRDMA

This repo is for our work, LoRDMA: A New Low-Rate DoS Attack in RDMA Networks.
It consists of our attack tools and ns-3 simulator.

## Burster

The burst crafter fabricates high-rate traffic using `IBV_QPT_RAW_PACKET`.

### Usage

For ease of use, first generate the trace pcap file to be replayed by burster.
You can change the packet bytes the burster sends by modifying `make_trace.py`

```bash
python make_trace.py
```

Then you can run the burster.

```bash
make all 
sudo ./burster-period.out --device <DEV_NAME> --duration <us> --txsize <TXSIZE> --txnum <TXNUM> --gid-idx <idx> -f <pcapfile> --interval <us>
```

Note that tx-size <= 2048 and tx-num <= 16 in current implementation.

An example is :

```bash
sudo ./burster-period.out --device mlx5_0 --duration 10000 --txsize 2048 --txnum 8 --gid-idx 3 -f replay.pcap --interval 100000
```
It sends a 10ms burst with an interval of 100ms.


## Prober

Craft connection request to estimate the end-to-end latency.

### Usage 


```bash
make all
sudo ./prober.out --device <DEV_NAME> --test_size <TEST_SIZE> --trace-file <pcapfile> --pktno <n>
```

An example is 

```bash
sudo ./prober --device mlx5_0 --test-size 1000 --trace-file sniff_135req136.pcap --pktno 1
```

It will replay the first packet (A `ConnectRequest`) to estimate the latency for 1000 times.

Note that the attacker should carefully set the probing packet. For a new end-to-end probing, it is better to capture a new `ConnectRequest` packet to the destination node and replay it. 
We also append a `cm-client` in `prober/cm_client/` to capture a new `ConnectRequest` packet. The usage is:

```bash
cd ./prober/cm_client/
make
./cm-client -c <SRC_IP> -s <DST_IP>
```


## NS-3 simulator for RDMA

Our simulator is based on the [RDMA simulator](https://github.com/bobzhuyb/ns3-rdma) proposed by Yibo Zhu.


### Build
Similar to Yibo Zhu's original version, our simulator also needs Visual Studio *2015* (not 2013 or 2017). 
Open windows/ns-3-dev/ns-3-dev.sln, and you can build the whole solution.

If you cannot get a Windows machine or Visual Studio, you may need to build it on Linux.
We will make a linux-based version soon.

### Run
The binary `main.exe` will be generated at `windows/ns-3-dev/x64/Release/main.exe`
Similar to Yibo Zhu's original version,  we set a sample configuration file at `windows/ns-3-dev/x64/Release/mix/config.txt`, which is the motivating experiment setup in our paper, and we set a attacker-config file 'mix/attacker.txt' which specifies the nodes that do not respond to CC signals, to simulate the line-rate burster.

To run main.exe:
```
cd windows\ns-3-dev\x64\Release\
.\main.exe mix\config.txt
```

It runs a 3:1 incast at 100Gbps for 1 millisecond. Please allow a few minutes for it to finish.
The simulation results will be generated at mix/datarate.tr, which records the rate of each node.

You can just check the code, 
project "main" -- source files -- "third.cc", and see the main logic of the simulations.


## References

The burst crafter is inspired by the following projects:

* https://github.com/zhangmenghao/RDMA-Tutorial/
* https://github.com/linux-rdma/perftest
* https://github.com/bganne/rdma-pktgen
