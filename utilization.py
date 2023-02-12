import psutil

def check_high_resource_utilization(process_name):
    for process in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_info', 'io_counters', 'connections']):
        if process.info['name'] == process_name:
            # Check CPU usage
            if process.info['cpu_percent'] > 50:
                print(f"Process {process_name} is using high CPU: {process.info['cpu_percent']}%")
            
            # Check memory usage 100 MB
            mem = process.info['memory_info']
            if mem.rss > 100 * 1024 * 1024:
                print(f"Process {process_name} is using high memory: {mem.rss / 1024 / 1024} MB")
            
            # Check disk I/O
            io = process.info['io_counters']
            if io.read_bytes + io.write_bytes > 100 * 1024 * 1024:
                print(f"Process {process_name} is performing high disk I/O: {io.read_bytes + io.write_bytes / 1024 / 1024} MB")
            
            # Check network I/O
            net = process.info['connections']
            if len(net) > 0:
                sent = sum([c.info['bytes_sent'] for c in net if c.info['type'] == psutil.SOCK_STREAM])
                recv = sum([c.info['bytes_recv'] for c in net if c.info['type'] == psutil.SOCK_STREAM])
                if sent + recv > 100 * 1024 * 1024:
                    print(f"Process {process_name} is performing high network I/O: {(sent + recv) / 1024 / 1024} MB")

# Example usage
check_high_resource_utilization("miner.exe")

