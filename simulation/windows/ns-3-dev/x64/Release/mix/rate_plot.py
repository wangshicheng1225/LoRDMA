import pandas as pd
import math
import matplotlib
import matplotlib.pyplot as plt
import numpy as np
import re



trace_file_path = "datarate.tr"

attacker_id_list = [12,13,14]

attacker_num = len(attacker_id_list)
receiver_id_list = [10]
receiver_num = len(receiver_id_list)
# sender_id_list = [3, 4, 5, 6]
sender_id_list = [5, 6,7,8]
sender_num = len(sender_id_list)
#switch_id_list = [0, 1, 2]
switch_id_list = [0, 1, 2,3,4]
# switch_id_list = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19]
switch_num = len(switch_id_list)
base_rate_list = [50, 50, 50, 50]    # case 2

sender_index_dict = {}
for i in range(sender_num):
    sender_id = str(sender_id_list[i])
    sender_index_dict[sender_id] = i

attacker_index_dict = {}
for i in range(attacker_num):
    attacker_id = str(attacker_id_list[i])
    attacker_index_dict[attacker_id] = i

datarate_list = [[] for _ in range(sender_num)]
time_list = [[] for _ in range(sender_num)]

data = pd.read_table(trace_file_path, header=None, sep='\s+', names=['time', 'node', 'rate'], low_memory=False).dropna()

for index, row in data.iterrows():
    node = row[1]
    if node not in sender_id_list:
        continue
    else:
        current_time = row[0]
        current_rate = float(re.sub("\D", "", row[2])) / 1e+9
        node_index = sender_index_dict[str(node)]
        if current_time not in time_list[node_index]:
            datarate_list[node_index].append(current_rate)
            time_list[node_index].append(current_time)

for i in range(sender_num):
    label_str = 'Sender' + str(sender_id_list[i])
    time_list[i], datarate_list[i] = (list(t) for t in zip(*sorted(zip(time_list[i], datarate_list[i]))))
    plt.plot(time_list[i], datarate_list[i], label=label_str)
    plt.legend(loc='upper right')



plt.xlim(2.0008, 2.11)
plt.xlabel('Time (s)')
plt.ylabel('Sending Rate (Gbps)')
# plt.show()
plt.savefig("flowrate.png")



