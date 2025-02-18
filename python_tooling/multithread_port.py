import argparse
import nmap
import json
import subprocess
import threading
import logging
from queue import Queue

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler()
    ]
)

def worker(queue, ip, show_process, results, thread_id):
    logging.info(f"Thread-{thread_id} started.")
    while not queue.empty():
        port = queue.get()
        logging.info(f"Thread-{thread_id} scanning port {port}.")
        scan_data = scan_port(ip, port, show_process)
        if scan_data:
            results.append(scan_data)
        queue.task_done()
    logging.info(f"Thread-{thread_id} finished.")

def scan_port(ip, port, show_process):
    nm = nmap.PortScanner()
    nm.scan(ip, str(port))

    for host in nm.all_hosts():
        for proto in nm[host].all_protocols():
            lport = nm[host][proto].keys()
            for p in lport:
                port_state = nm[host][proto][p]['state']
                if p == port:
                    port_info = {"port": port, "state": port_state}
                    if port_state == 'open' and show_process:
                        process_info = get_process_details(port)
                        port_info["process"] = process_info
                    logging.info(f"Port {port} on {ip} is {port_state}.")
                    return port_info
    return None

def get_process_details(port):
    lsof_command = f"sudo lsof -iTCP:{port} -sTCP:LISTEN"
    try:
        process = subprocess.run(lsof_command, shell=True, capture_output=True, text=True)
    except Exception as e:
        logging.error(f"Error running lsof on port {port}: {e}")
        return {}

    process_details = {}
    if process.stdout:
        lines = process.stdout.splitlines()
        logging.info(f"lsof output for port {port}:\n{process.stdout}")

        if len(lines) > 1:
            for line in lines[1:]:  # Skip the header line
                details = line.split()
                if len(details) < 2:
                    logging.warning(f"Unexpected lsof line format: {line}")
                    continue
                pid = details[1]
                process_name = details[0]
                process_info = get_process_info(pid)
                process_details = {
                    "pid": pid,
                    "name": process_name,
                    "location": process_info.get("cwd", "Unknown"),
                    "command": process_info.get("cmdline", "Unknown")
                }
                logging.info(f"Found process {process_name} with PID {pid} on port {port}.")
        else:
            logging.info(f"No processes are listening on port {port}.")
    else:
        logging.info(f"No process information found for port {port}.")
    return process_details


def get_process_info(pid):
    """Retrieve process information from /proc filesystem."""
    try:
        proc_info = {}
        with open(f"/proc/{pid}/cwd") as f:
            proc_info["cwd"] = f.read().strip()
        with open(f"/proc/{pid}/cmdline") as f:
            proc_info["cmdline"] = f.read().strip().replace('\x00', ' ')
        return proc_info
    except Exception as e:
        logging.error(f"Failed to retrieve process information for PID {pid}: {e}")
        return {"cwd": "Unknown", "cmdline": "Unknown"}

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="A simple port scanner using nmap with additional process information.")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address to scan (default: localhost).")
    parser.add_argument("-sp", "--start-port", type=int, default=1000, help="Starting port number for the scan (default: 1000).")
    parser.add_argument("-ep", "--end-port", type=int, default=8000, help="Ending port number for the scan (default: 8000).")
    parser.add_argument("-p", "--process", action="store_true", help="Show process information for open ports.")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Output JSON file for scan results (default: scan_results.json).")
    parser.add_argument("-th", "--threads", type=int, default=10, help="Number of threads to use for scanning (default: 10).")

    args = parser.parse_args()

    logging.info(f"Starting scan on {args.target} from port {args.start_port} to {args.end_port} with {args.threads} threads.")

    # Queue to hold the ports to scan
    port_queue = Queue()

    # Enqueue ports
    for port in range(args.start_port, args.end_port + 1):
        port_queue.put(port)

    # List to hold scan results
    results = []

    # Create worker threads
    threads = []
    for i in range(args.threads):
        thread = threading.Thread(target=worker, args=(port_queue, args.target, args.process, results, i+1))
        threads.append(thread)
        thread.start()

    # Wait for all threads to finish
    for thread in threads:
        thread.join()

    logging.info("All threads have finished scanning.")

    # Write the results to a JSON file
    with open(args.output, 'w') as json_file:
        json.dump({"host": args.target, "ports": results}, json_file, indent=4)
        logging.info(f"Scan results have been saved to {args.output}")

if __name__ == "__main__":
    main()