import psutil
import floss

def get_process_utilization(process):
    try:
        # Get CPU utilization
        cpu_utilization = process.cpu_percent()

        # Get network traffic and disk I/O information
        io_counters = process.io_counters()
        sent = io_counters[0]
        recv = io_counters[1]
        read_bytes = io_counters[4]
        write_bytes = io_counters[5]

        # Get memory information
        memory_info = process.memory_info()
        memory_utilization = memory_info.rss / float(2 ** 20)

        # Print the information
        print("Process name:", process.name())
        print("CPU utilization:", cpu_utilization)
        print("Bytes sent:", sent)
        print("Bytes received:", recv)
        print("Read bytes:", read_bytes)
        print("Write bytes:", write_bytes)
        print("Memory utilization:", memory_utilization, "MB")
        print("")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass


def get_dynamic_prediction(process):
    prediction_probability = 0
    # Define the thresholds for the process metrics
    cpu_threshold = 50.0
    memory_threshold = 100.0
    net_bytes_sent_threshold = 10_000_000
    net_bytes_recv_threshold = 10_000_000
    disk_read_bytes_threshold = 100_000_000
    disk_write_bytes_threshold = 100_000_000

    thresholds = [cpu_threshold,memory_threshold,net_bytes_sent_threshold,net_bytes_recv_threshold,disk_read_bytes_threshold,disk_write_bytes_threshold]

    weights = [0.4, 0.2, 0.1,0.1,0.1,0.1] # weights representing the significance of each threshold 
    # Get the CPU utilization for the process
    cpu_percent = process.cpu_percent()

    # Get the memory utilization for the process
    memory_usage = process.memory_info().rss / float(2 ** 20)

    # Get the network I/O counters for the process
    
    net_io_counters = process.io_counters()
    # net_bytes_sent = net_io_counters.bytes_sent
    # net_bytes_recv = net_io_counters.bytes_recv
    net_bytes_sent=0
    net_bytes_recv=0
    # Get the disk I/O counters for the process
    disk_io_counters = process.io_counters()
    disk_read_bytes = disk_io_counters.read_bytes
    disk_write_bytes = disk_io_counters.write_bytes

    measurements=[cpu_percent,memory_usage,net_bytes_sent,net_bytes_recv,disk_read_bytes,disk_write_bytes]
    prediction_probability = sum([weight for i, weight in enumerate(weights) if measurements[i] > thresholds[i]])
    return prediction_probability


def get_network_connections(process):
    try:
        return [conn.raddr[0]  for conn in process.connections() if conn.raddr[0] !="::"]
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return None

import re

def find_ip_addresses_in_strings(string_list):
    pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b" # IP address pattern
    ip_list = []
    for string in string_list:
        match = re.search(pattern, string)
        if match:
            ip_list.append(match.group())
    return ip_list