import psutil

def get_process_utilization(process):
    try:
        # Get CPU utilization
        cpu_utilization = process.cpu_percent()

        # Get network traffic information
        net_io_counters = process.io_counters()
        sent = net_io_counters.bytes_sent
        recv = net_io_counters.bytes_recv

        # Get disk I/O information
        disk_io_counters = process.io_counters()
        read_count = disk_io_counters.read_count
        write_count = disk_io_counters.write_count
        read_bytes = disk_io_counters.read_bytes
        write_bytes = disk_io_counters.write_bytes

        # Get memory information
        memory_info = process.memory_info()
        memory_utilization = memory_info.rss / (1024 ** 2)

        # Print the information
        print("Process name:", process.name())
        print("CPU utilization:", cpu_utilization)
        print("Bytes sent:", sent)
        print("Bytes received:", recv)
        print("Read count:", read_count)
        print("Write count:", write_count)
        print("Read bytes:", read_bytes)
        print("Write bytes:", write_bytes)
        print("Memory utilization:", memory_utilization, "MB")
        print("")
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        pass