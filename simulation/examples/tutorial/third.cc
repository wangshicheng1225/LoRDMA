/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License version 2 as
* published by the Free Software Foundation;
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#undef PGO_TRAINING
#define PATH_TO_PGO_CONFIG "path_to_pgo_config"

#include <iostream>
#include <fstream>
#include <time.h> 
#include <vector>
#include <algorithm>
#include "ns3/core-module.h"
#include "ns3/qbb-helper.h"
#include "ns3/point-to-point-helper.h"
#include "ns3/applications-module.h"
#include "ns3/internet-module.h"
#include "ns3/global-route-manager.h"
#include "ns3/ipv4-static-routing-helper.h"
#include "ns3/broadcom-node.h"
#include "ns3/packet.h"
#include "ns3/error-model.h"
#include "ns3/flow-monitor-helper.h"
#include "ns3/flow-monitor-module.h"
//#include "ns3/qbb-net-device.h"

using namespace ns3;

NS_LOG_COMPONENT_DEFINE("GENERIC_SIMULATION");

bool enable_qcn = true, enable_cc = true, use_dynamic_pfc_threshold = true, packet_level_ecmp = false, flow_level_ecmp = false;
uint32_t packet_payload_size = 1000, l2_chunk_size = 0, l2_ack_interval = 0;
double pause_time = 5, simulator_stop_time = 3.01, app_start_time = 1.0, app_stop_time = 9.0;
std::string data_rate, link_delay, topology_file, flow_file, tcp_flow_file, trace_file, trace_output_file, attacker_file, pulse_traffic_file;
bool used_port[65536] = { 0 };
std::vector<uint32_t> attacker_id;
std::ofstream datarate_file;





double nSamplingPeriod = 0.01;   
uint32_t lastRxPacketsum = 0;
std::vector<double> monitorTimeVector;
std::vector<double> throughputVector;
Ipv4Address serverIp;   // UDP/TCP server IP
Ipv4Address clientIp;   // UDP/TCP client IP
uint32_t tmpTxPacketsum = 0;




double cnp_interval = 50, alpha_resume_interval = 55, rp_timer, dctcp_gain = 1 / 16, np_sampling_interval = 0, pmax = 1;
uint32_t byte_counter, fast_recovery_times = 5, kmax = 60, kmin = 60;
std::string rate_ai, rate_hai;

bool clamp_target_rate = false, clamp_target_rate_after_timer = false, send_in_chunks = true, l2_wait_for_ack = false, l2_back_to_zero = false, l2_test_read = false;
double error_rate_per_link = 0.0;

class MyFlow
{
public:
	uint32_t m_src;
	uint32_t m_dst;
	uint32_t m_priority;
	uint32_t m_max_packet_num;
	double m_start_time;
	double m_end_time;

	MyFlow(uint32_t src, uint32_t dst, uint32_t priority, uint32_t max_packet_num, double start_time, double end_time)
	{
		m_src = src;
		m_dst = dst;
		m_priority = priority;
		m_max_packet_num = max_packet_num;
		m_start_time = start_time;
		m_end_time = end_time;
	}

	void print()
	{
		std::cout << m_src << ", " << m_dst << ", " << m_priority << ", " << m_max_packet_num << ", " << m_start_time << ", " << m_end_time << "\n";
	}
	~MyFlow() {}
};

bool nonmem_cmp(const MyFlow &f1, const MyFlow &f2)
{
	if (f1.m_start_time < f2.m_start_time)
		return true;
	return false;
}

int main(int argc, char *argv[])
{
	clock_t begint, endt;
	begint = clock();
#ifndef PGO_TRAINING
	if (argc > 1)
#else
	if (true)
#endif
	{
		//Read the configuration file
		std::ifstream conf;
#ifndef PGO_TRAINING
		conf.open(argv[1]);
#else
		conf.open(PATH_TO_PGO_CONFIG);
#endif
		while (!conf.eof())
		{
			std::string key;
			conf >> key;

			//std::cout << conf.cur << "\n";

			if (key.compare("ENABLE_QCN") == 0)
			{
				uint32_t v;
				conf >> v;
				enable_qcn = v;
				if (enable_qcn)
					std::cout << "ENABLE_QCN\t\t\t" << "Yes" << "\n";
				else
					std::cout << "ENABLE_QCN\t\t\t" << "No" << "\n";
			}
			else if (key.compare("USE_DYNAMIC_PFC_THRESHOLD") == 0)
			{
				uint32_t v;
				conf >> v;
				use_dynamic_pfc_threshold = v;
				if (use_dynamic_pfc_threshold)
					std::cout << "USE_DYNAMIC_PFC_THRESHOLD\t" << "Yes" << "\n";
				else
					std::cout << "USE_DYNAMIC_PFC_THRESHOLD\t" << "No" << "\n";
			}
			else if (key.compare("CLAMP_TARGET_RATE") == 0)
			{
				uint32_t v;
				conf >> v;
				clamp_target_rate = v;
				if (clamp_target_rate)
					std::cout << "CLAMP_TARGET_RATE\t\t" << "Yes" << "\n";
				else
					std::cout << "CLAMP_TARGET_RATE\t\t" << "No" << "\n";
			}
			else if (key.compare("CLAMP_TARGET_RATE_AFTER_TIMER") == 0)
			{
				uint32_t v;
				conf >> v;
				clamp_target_rate_after_timer = v;
				if (clamp_target_rate_after_timer)
					std::cout << "CLAMP_TARGET_RATE_AFTER_TIMER\t" << "Yes" << "\n";
				else
					std::cout << "CLAMP_TARGET_RATE_AFTER_TIMER\t" << "No" << "\n";
			}
			else if (key.compare("PACKET_LEVEL_ECMP") == 0)
			{
				uint32_t v;
				conf >> v;
				packet_level_ecmp = v;
				if (packet_level_ecmp)
					std::cout << "PACKET_LEVEL_ECMP\t\t" << "Yes" << "\n";
				else
					std::cout << "PACKET_LEVEL_ECMP\t\t" << "No" << "\n";
			}
			else if (key.compare("FLOW_LEVEL_ECMP") == 0)
			{
				uint32_t v;
				conf >> v;
				flow_level_ecmp = v;
				if (flow_level_ecmp)
					std::cout << "FLOW_LEVEL_ECMP\t\t\t" << "Yes" << "\n";
				else
					std::cout << "FLOW_LEVEL_ECMP\t\t\t" << "No" << "\n";
			}
			else if (key.compare("PAUSE_TIME") == 0)
			{
				double v;
				conf >> v;
				pause_time = v;
				std::cout << "PAUSE_TIME\t\t\t" << pause_time << "\n";
			}
			else if (key.compare("DATA_RATE") == 0)
			{
				std::string v;
				conf >> v;
				data_rate = v;
				std::cout << "DATA_RATE\t\t\t" << data_rate << "\n";
			}
			else if (key.compare("LINK_DELAY") == 0)
			{
				std::string v;
				conf >> v;
				link_delay = v;
				std::cout << "LINK_DELAY\t\t\t" << link_delay << "\n";
			}
			else if (key.compare("PACKET_PAYLOAD_SIZE") == 0)
			{
				uint32_t v;
				conf >> v;
				packet_payload_size = v;
				std::cout << "PACKET_PAYLOAD_SIZE\t\t" << packet_payload_size << "\n";
			}
			else if (key.compare("L2_CHUNK_SIZE") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_chunk_size = v;
				std::cout << "L2_CHUNK_SIZE\t\t\t" << l2_chunk_size << "\n";
			}
			else if (key.compare("L2_ACK_INTERVAL") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_ack_interval = v;
				std::cout << "L2_ACK_INTERVAL\t\t\t" << l2_ack_interval << "\n";
			}
			else if (key.compare("L2_WAIT_FOR_ACK") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_wait_for_ack = v;
				if (l2_wait_for_ack)
					std::cout << "L2_WAIT_FOR_ACK\t\t\t" << "Yes" << "\n";
				else
					std::cout << "L2_WAIT_FOR_ACK\t\t\t" << "No" << "\n";
			}
			else if (key.compare("L2_BACK_TO_ZERO") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_back_to_zero = v;
				if (l2_back_to_zero)
					std::cout << "L2_BACK_TO_ZERO\t\t\t" << "Yes" << "\n";
				else
					std::cout << "L2_BACK_TO_ZERO\t\t\t" << "No" << "\n";
			}
			else if (key.compare("L2_TEST_READ") == 0)
			{
				uint32_t v;
				conf >> v;
				l2_test_read = v;
				if (l2_test_read)
					std::cout << "L2_TEST_READ\t\t\t" << "Yes" << "\n";
				else
					std::cout << "L2_TEST_READ\t\t\t" << "No" << "\n";
			}
			else if (key.compare("TOPOLOGY_FILE") == 0)
			{
				std::string v;
				conf >> v;
				topology_file = v;
				std::cout << "TOPOLOGY_FILE\t\t\t" << topology_file << "\n";
			}
			else if (key.compare("FLOW_FILE") == 0)
			{
				std::string v;
				conf >> v;
				flow_file = v;
				std::cout << "FLOW_FILE\t\t\t" << flow_file << "\n";
			}
			else if (key.compare("TCP_FLOW_FILE") == 0)
			{
				std::string v;
				conf >> v;
				tcp_flow_file = v;
				std::cout << "TCP_FLOW_FILE\t\t\t" << tcp_flow_file << "\n";
			}
			else if (key.compare("TRACE_FILE") == 0)
			{
				std::string v;
				conf >> v;
				trace_file = v;
				std::cout << "TRACE_FILE\t\t\t" << trace_file << "\n";
			}
			else if (key.compare("TRACE_OUTPUT_FILE") == 0)
			{
				std::string v;
				conf >> v;
				trace_output_file = v;
				if (argc > 2)
				{
					trace_output_file = trace_output_file + std::string(argv[2]);
				}
				std::cout << "TRACE_OUTPUT_FILE\t\t" << trace_output_file << "\n";
			}
			else if (key.compare("ATTACKER_FILE") == 0)
			{
				std::string v;
				conf >> v;
				attacker_file = v;
				std::cout << "ATTACKER_FILE\t\t\t" << attacker_file << "\n";
			}
			else if (key.compare("PULSE_TRAFFIC_FILE") == 0)
			{
				std::string v;
				conf >> v;
				pulse_traffic_file = v;
				std::cout << "PULSE_TRAFFIC_FILE\t\t" << pulse_traffic_file << "\n";
			}
			else if (key.compare("APP_START_TIME") == 0)
			{
				double v;
				conf >> v;
				app_start_time = v;
				std::cout << "SINK_START_TIME\t\t\t" << app_start_time << "\n";
			}
			else if (key.compare("APP_STOP_TIME") == 0)
			{
				double v;
				conf >> v;
				app_stop_time = v;
				std::cout << "SINK_STOP_TIME\t\t\t" << app_stop_time << "\n";
			}
			else if (key.compare("SIMULATOR_STOP_TIME") == 0)
			{
				double v;
				conf >> v;
				simulator_stop_time = v;
				std::cout << "SIMULATOR_STOP_TIME\t\t" << simulator_stop_time << "\n";
			}
			else if (key.compare("CNP_INTERVAL") == 0)
			{
				double v;
				conf >> v;
				cnp_interval = v;
				std::cout << "CNP_INTERVAL\t\t\t" << cnp_interval << "\n";
			}
			else if (key.compare("ALPHA_RESUME_INTERVAL") == 0)
			{
				double v;
				conf >> v;
				alpha_resume_interval = v;
				std::cout << "ALPHA_RESUME_INTERVAL\t\t" << alpha_resume_interval << "\n";
			}
			else if (key.compare("RP_TIMER") == 0)
			{
				double v;
				conf >> v;
				rp_timer = v;
				std::cout << "RP_TIMER\t\t\t" << rp_timer << "\n";
			}
			else if (key.compare("BYTE_COUNTER") == 0)
			{
				uint32_t v;
				conf >> v;
				byte_counter = v;
				std::cout << "BYTE_COUNTER\t\t\t" << byte_counter << "\n";
			}
			else if (key.compare("KMAX") == 0)
			{
				uint32_t v;
				conf >> v;
				kmax = v;
				std::cout << "KMAX\t\t\t\t" << kmax << "\n";
			}
			else if (key.compare("KMIN") == 0)
			{
				uint32_t v;
				conf >> v;
				kmin = v;
				std::cout << "KMIN\t\t\t\t" << kmin << "\n";
			}
			else if (key.compare("PMAX") == 0)
			{
				double v;
				conf >> v;
				pmax = v;
				std::cout << "PMAX\t\t\t\t" << pmax << "\n";
			}
			else if (key.compare("DCTCP_GAIN") == 0)
			{
				double v;
				conf >> v;
				dctcp_gain = v;
				std::cout << "DCTCP_GAIN\t\t\t" << dctcp_gain << "\n";
			}
			else if (key.compare("FAST_RECOVERY_TIMES") == 0)
			{
				uint32_t v;
				conf >> v;
				fast_recovery_times = v;
				std::cout << "FAST_RECOVERY_TIMES\t\t" << fast_recovery_times << "\n";
			}
			else if (key.compare("RATE_AI") == 0)
			{
				std::string v;
				conf >> v;
				rate_ai = v;
				std::cout << "RATE_AI\t\t\t\t" << rate_ai << "\n";
			}
			else if (key.compare("RATE_HAI") == 0)
			{
				std::string v;
				conf >> v;
				rate_hai = v;
				std::cout << "RATE_HAI\t\t\t" << rate_hai << "\n";
			}
			else if (key.compare("NP_SAMPLING_INTERVAL") == 0)
			{
				double v;
				conf >> v;
				np_sampling_interval = v;
				std::cout << "NP_SAMPLING_INTERVAL\t\t" << np_sampling_interval << "\n";
			}
			else if (key.compare("SEND_IN_CHUNKS") == 0)
			{
				uint32_t v;
				conf >> v;
				send_in_chunks = v;
				if (send_in_chunks)
				{
					std::cout << "SEND_IN_CHUNKS\t\t\t" << "Yes" << "\n";
					std::cout << "WARNING: deprecated and not tested. Please consider using L2_WAIT_FOR_ACK";
				}
				else
					std::cout << "SEND_IN_CHUNKS\t\t\t" << "No" << "\n";
			}
			else if (key.compare("ERROR_RATE_PER_LINK") == 0)
			{
				double v;
				conf >> v;
				error_rate_per_link = v;
				std::cout << "ERROR_RATE_PER_LINK\t\t" << error_rate_per_link << "\n";
			}
			fflush(stdout);
		}
		conf.close();
	}
	else
	{
		std::cout << "Error: require a config file\n";
		fflush(stdout);
		return 1;
	}


	bool dynamicth = use_dynamic_pfc_threshold;

	NS_ASSERT(packet_level_ecmp + flow_level_ecmp < 2); //Packet level ecmp and flow level ecmp are exclusive
	Config::SetDefault("ns3::Ipv4GlobalRouting::RandomEcmpRouting", BooleanValue(packet_level_ecmp));
	Config::SetDefault("ns3::Ipv4GlobalRouting::FlowEcmpRouting", BooleanValue(flow_level_ecmp));
	Config::SetDefault("ns3::QbbNetDevice::PauseTime", UintegerValue(pause_time));
	Config::SetDefault("ns3::QbbNetDevice::QcnEnabled", BooleanValue(enable_qcn));
	Config::SetDefault("ns3::QbbNetDevice::CCEnabled", BooleanValue(enable_cc));
	Config::SetDefault("ns3::QbbNetDevice::DynamicThreshold", BooleanValue(dynamicth));
	Config::SetDefault("ns3::QbbNetDevice::ClampTargetRate", BooleanValue(clamp_target_rate));
	Config::SetDefault("ns3::QbbNetDevice::ClampTargetRateAfterTimeInc", BooleanValue(clamp_target_rate_after_timer));
	Config::SetDefault("ns3::QbbNetDevice::CNPInterval", DoubleValue(cnp_interval));
	Config::SetDefault("ns3::QbbNetDevice::NPSamplingInterval", DoubleValue(np_sampling_interval));
	Config::SetDefault("ns3::QbbNetDevice::AlphaResumInterval", DoubleValue(alpha_resume_interval));
	Config::SetDefault("ns3::QbbNetDevice::RPTimer", DoubleValue(rp_timer));
	Config::SetDefault("ns3::QbbNetDevice::ByteCounter", UintegerValue(byte_counter));
	Config::SetDefault("ns3::QbbNetDevice::FastRecoveryTimes", UintegerValue(fast_recovery_times));
	Config::SetDefault("ns3::QbbNetDevice::DCTCPGain", DoubleValue(dctcp_gain));
	Config::SetDefault("ns3::QbbNetDevice::RateAI", DataRateValue(DataRate(rate_ai)));
	Config::SetDefault("ns3::QbbNetDevice::RateHAI", DataRateValue(DataRate(rate_hai)));
	Config::SetDefault("ns3::QbbNetDevice::L2BackToZero", BooleanValue(l2_back_to_zero));
	Config::SetDefault("ns3::QbbNetDevice::L2TestRead", BooleanValue(l2_test_read));
	Config::SetDefault("ns3::QbbNetDevice::L2ChunkSize", UintegerValue(l2_chunk_size));
	Config::SetDefault("ns3::QbbNetDevice::L2AckInterval", UintegerValue(l2_ack_interval));
	Config::SetDefault("ns3::QbbNetDevice::L2WaitForAck", BooleanValue(l2_wait_for_ack));

	SeedManager::SetSeed(time(NULL));

	std::ifstream topof, flowf, tracef, tcpflowf, attackerf, pulsef, ACKf, probe_pathf;
	topof.open(topology_file.c_str());
	flowf.open(flow_file.c_str());
	tracef.open(trace_file.c_str());
	tcpflowf.open(tcp_flow_file.c_str());
	attackerf.open(attacker_file.c_str());
	pulsef.open(pulse_traffic_file.c_str());

	uint32_t node_num, switch_num, link_num, flow_num, trace_num, tcp_flow_num, attacker_num, pulse_traffic_num;
	topof >> node_num >> switch_num >> link_num;
	flowf >> flow_num;
	tracef >> trace_num;
	tcpflowf >> tcp_flow_num;
	attackerf >> attacker_num;
	pulsef >> pulse_traffic_num;

	std::string data_rate_output_file = "mix/datarate.tr";
	std::string rtt_output_file = "mix/rtt.tr";
	std::string qlen_output_file = "mix/qlen.tr";
	std::string ack_output_file = "mix/ack.tr";
	std::string fct_output_file = "mix/fct.tr";
	std::string flow_type_file = "mix/flow_type.txt";
	std::string clos_ip_mapping_file = "mix/clos_ip_mapping.txt";
	std::string probe_path_file = "mix/probe_path.tr";
	std::string ecmp_file = "mix/ecmp.tr";
	std::string congestion_file = "mix/congestion.tr";
	std::string port_rate_file = "mix/portrate.tr";

	// Daterate
	if (remove(data_rate_output_file.c_str()) == 0)
	{
		std::cout << "Delete original datarate.tr!!\n";
	}
	else
	{
		return 0;
	}



	NodeContainer n;
	n.Create(node_num);
	for (uint32_t i = 0; i < switch_num; i++)
	{
		uint32_t sid;
		topof >> sid;
		n.Get(sid)->SetNodeType(1, dynamicth); //broadcom switch
		n.Get(sid)->m_broadcom->SetMarkingThreshold(kmin, kmax, pmax);
	}

	for (uint32_t i = 0; i < attacker_num; i++)
	{
		uint32_t aid;
		attackerf >> aid;
		attacker_id.push_back(aid);
	}

	NS_LOG_INFO("Create nodes.");

	InternetStackHelper internet;
	internet.Install(n);

	NS_LOG_INFO("Create channels.");

	//
	// Explicitly create the channels required by the topology.
	//

	Ptr<RateErrorModel> rem = CreateObject<RateErrorModel>();
	Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
	rem->SetRandomVariable(uv);
	uv->SetStream(50);
	rem->SetAttribute("ErrorRate", DoubleValue(error_rate_per_link));
	rem->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));

	QbbHelper qbb;
	Ipv4AddressHelper ipv4;
	for (uint32_t i = 0; i < link_num; i++)
	{
		uint32_t src, dst;
		std::string data_rate, link_delay;
		double error_rate;
		topof >> src >> dst >> data_rate >> link_delay >> error_rate;

		bool src_cc_enabled = enable_cc, dst_cc_enabled = enable_cc;
		//std::cout << "enable_qcn=" << enable_qcn << "\n";

		qbb.SetDeviceAttribute("DataRate", StringValue(data_rate));
		qbb.SetChannelAttribute("Delay", StringValue(link_delay));

		if (error_rate > 0)
		{
			Ptr<RateErrorModel> rem = CreateObject<RateErrorModel>();
			Ptr<UniformRandomVariable> uv = CreateObject<UniformRandomVariable>();
			rem->SetRandomVariable(uv);
			uv->SetStream(50);
			rem->SetAttribute("ErrorRate", DoubleValue(error_rate));
			rem->SetAttribute("ErrorUnit", StringValue("ERROR_UNIT_PACKET"));
			qbb.SetDeviceAttribute("ReceiveErrorModel", PointerValue(rem));
		}
		else
		{
			qbb.SetDeviceAttribute("ReceiveErrorModel", PointerValue(rem));
		}

		if (std::count(attacker_id.begin(), attacker_id.end(), dst) > 0)
		{
			dst_cc_enabled = false;
		}
		//std::for_each(attacker_id.begin(), attacker_id.end(), [](const auto &i) {std::cout << i << " "; });
		//std::cout << "\n";
		fflush(stdout);
		NetDeviceContainer d = qbb.Install(n.Get(src), n.Get(dst), dst_cc_enabled, node_num - switch_num);

		char ipstring[16];
		sprintf(ipstring, "10.%d.%d.0", i / 254 + 1, i % 254 + 1);
		ipv4.SetBase(ipstring, "255.255.255.0");
		ipv4.Assign(d);
	}

	NodeContainer trace_nodes;
	for (uint32_t i = 0; i < trace_num; i++)
	{
		uint32_t nid;
		tracef >> nid;
		trace_nodes = NodeContainer(trace_nodes, n.Get(nid));
	}
	//AsciiTraceHelper ascii;
	//qbb.EnableAscii(ascii.CreateFileStream(trace_output_file), trace_nodes);

	Ipv4GlobalRoutingHelper::PopulateRoutingTables();

	NS_LOG_INFO("Create Applications.");

	uint32_t packetSize = packet_payload_size;
	Time interPacketInterval = Seconds(0.0000005 / 2);

	std::vector<MyFlow> all_flow_list;

	for (uint32_t i = 0; i < flow_num; i++)
	{
		uint32_t src, dst, pg, maxPacketCount, port;
		double start_time, stop_time;
		flowf >> src >> dst >> pg >> maxPacketCount >> start_time >> stop_time;

		MyFlow flow(src, dst, pg, maxPacketCount, start_time, stop_time);
		all_flow_list.push_back(flow);
	}

	for (uint32_t i = 0; i < pulse_traffic_num; i++)
	{
		uint32_t src, dst, pg, maxPacketCount, port;
		double start_time, stop_time, pulse_duration, pulse_interval;
		pulsef >> src >> dst >> pg >> maxPacketCount >> start_time >> stop_time >> pulse_duration >> pulse_interval;
		uint32_t replicated_flow_cnt = 0;
		double pulse_start_time = start_time, pulse_stop_time = pulse_start_time + pulse_duration;

		while (pulse_start_time < stop_time)
		{
			MyFlow flow(src, dst, pg, maxPacketCount, pulse_start_time, pulse_stop_time);
			all_flow_list.push_back(flow);
			//pulse_start_time = pulse_stop_time + pulse_interval;  // Non-overlapping
			pulse_start_time = pulse_start_time + pulse_interval;  // Overlapping
			pulse_stop_time = pulse_start_time + pulse_duration;
		}
	}

	std::sort(all_flow_list.begin(), all_flow_list.end(), nonmem_cmp);
	for (uint32_t i = 0; i < all_flow_list.size(); i++)
	{
		all_flow_list[i].print();
	}

	for (uint32_t i = 0; i < all_flow_list.size(); i++)
	{
		uint32_t src, dst, pg, maxPacketCount, port;
		double start_time, stop_time;
		while (used_port[port = int(UniformVariable(0, 1).GetValue() * 40000)])
			continue;
		used_port[port] = true;

		MyFlow flow = all_flow_list[i];
		src = flow.m_src;
		dst = flow.m_dst;
		pg = flow.m_priority;
		maxPacketCount = flow.m_max_packet_num;
		start_time = flow.m_start_time;
		stop_time = flow.m_end_time;

		datarate_file.open(data_rate_output_file.c_str(), std::ios::app);
		datarate_file << start_time << " " << src << " " << "0bps\n";
		datarate_file << stop_time << " " << src << " " << "0bps\n";
		datarate_file.close();

		NS_ASSERT(n.Get(src)->GetNodeType() == 0 && n.Get(dst)->GetNodeType() == 0);
		Ptr<Ipv4> ipv4 = n.Get(dst)->GetObject<Ipv4>();
		Ipv4Address serverAddress = ipv4->GetAddress(1, 0).GetLocal(); //GetAddress(0,0) is the loopback 127.0.0.1

		if (send_in_chunks)
		{
			UdpEchoServerHelper server0(port, pg); //Add Priority
			ApplicationContainer apps0s = server0.Install(n.Get(dst));
			apps0s.Start(Seconds(app_start_time));
			apps0s.Stop(Seconds(app_stop_time));
			UdpEchoClientHelper client0(serverAddress, port, pg); //Add Priority
			client0.SetAttribute("MaxPackets", UintegerValue(maxPacketCount));
			client0.SetAttribute("Interval", TimeValue(interPacketInterval));
			client0.SetAttribute("PacketSize", UintegerValue(packetSize));
			ApplicationContainer apps0c = client0.Install(n.Get(src));
			apps0c.Start(Seconds(start_time));
			apps0c.Stop(Seconds(stop_time));
		}
		else
		{
			UdpServerHelper server0(port);
			ApplicationContainer apps0s = server0.Install(n.Get(dst));
			apps0s.Start(Seconds(app_start_time));
			apps0s.Stop(Seconds(app_stop_time));
			UdpClientHelper client0(serverAddress, port, pg); //Add Priority
			client0.SetAttribute("MaxPackets", UintegerValue(maxPacketCount));
			client0.SetAttribute("Interval", TimeValue(interPacketInterval));

			
			if (0)
			{
				client0.SetAttribute("PacketSize", UintegerValue(280));
			}
			else
			{
				client0.SetAttribute("PacketSize", UintegerValue(packetSize));
			}

			ApplicationContainer apps0c = client0.Install(n.Get(src));
			apps0c.Start(Seconds(start_time));
			apps0c.Stop(Seconds(stop_time));
		}

	}


	for (uint32_t i = 0; i < tcp_flow_num; i++)
	{
		uint32_t src, dst, pg, maxPacketCount, port;
		double start_time, stop_time;
		while (used_port[port = int(UniformVariable(0, 1).GetValue() * 40000)])
			continue;
		used_port[port] = true;
		tcpflowf >> src >> dst >> pg >> maxPacketCount >> start_time >> stop_time;
		NS_ASSERT(n.Get(src)->GetNodeType() == 0 && n.Get(dst)->GetNodeType() == 0);
		Ptr<Ipv4> ipv4 = n.Get(dst)->GetObject<Ipv4>();
		Ipv4Address serverAddress = ipv4->GetAddress(1, 0).GetLocal();

		Address sinkLocalAddress(InetSocketAddress(Ipv4Address::GetAny(), port));
		PacketSinkHelper sinkHelper("ns3::TcpSocketFactory", sinkLocalAddress);

		ApplicationContainer sinkApp = sinkHelper.Install(n.Get(dst));
		sinkApp.Start(Seconds(app_start_time));
		sinkApp.Stop(Seconds(app_stop_time));

		BulkSendHelper source("ns3::TcpSocketFactory", InetSocketAddress(serverAddress, port));
		// Set the amount of data to send in bytes.  Zero is unlimited.
		source.SetAttribute("MaxBytes", UintegerValue(0));
		ApplicationContainer sourceApps = source.Install(n.Get(src));
		sourceApps.Start(Seconds(start_time));
		sourceApps.Stop(Seconds(stop_time));
	}


	topof.close();
	flowf.close();
	tracef.close();
	tcpflowf.close();
	attackerf.close();
	pulsef.close();

	//
	// Now, do the actual simulation.
	//
	std::cout << "Running Simulation.\n";
	fflush(stdout);
	NS_LOG_INFO("Run Simulation.");
	Simulator::Stop(Seconds(simulator_stop_time));
	Simulator::Run();
	Simulator::Destroy();
	NS_LOG_INFO("Done.");

	endt = clock();
	std::cout << (double)(endt - begint) / CLOCKS_PER_SEC << "\n";



}
