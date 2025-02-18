import argparse
import nmap
import json
import subprocess

def scan_with_nmap(ip, start_port, end_port, show_process):
    nm = nmap.PortScanner()
    print(f"Scanning {ip} from port {start_port} to {end_port} with nmap...")

    # Perform the scan
    nm.scan(ip, f'{start_port}-{end_port}')
    scan_data = {"host": ip, "ports": []}

    for host in nm.all_hosts():
        print(f"\nHost: {host} ({nm[host].hostname()})")
        print(f"State: {nm[host].state()}")
        for proto in nm[host].all_protocols():
            print(f"\nProtocol: {proto}")

            lport = nm[host][proto].keys()
            for port in lport:
                port_state = nm[host][proto][port]['state']
                print(f"Port: {port}\tState: {port_state}")
                port_info = {"port": port, "state": port_state}

                if port_state == 'open' and show_process:
                    process_info = get_process_details(port)
                    port_info["process"] = process_info

                scan_data["ports"].append(port_info)

    return scan_data

def get_process_details(port):
    # Run 'lsof' to find the process using the open port
    lsof_command = f"sudo lsof -iTCP:{port} -sTCP:LISTEN"
    process = subprocess.run(lsof_command, shell=True, capture_output=True, text=True)
    process_details = {}

    if process.stdout:
        lines = process.stdout.splitlines()
        for line in lines[1:]:  # Skip the header line
            details = line.split()
            pid = details[1]
            process_name = details[0]
            process_info = get_process_info(pid)
            process_details = {
                "pid": pid,
                "name": process_name,
                "location": process_info.get("cwd", "Unknown"),
                "command": process_info.get("cmdline", "Unknown")
            }
            print(f"  [*] PID: {pid}, Process: {process_name}")
            print(f"  [*] Location: {process_info['cwd']}")
            print(f"  [*] Command: {process_info['cmdline']}")
    else:
        print("  [-] No process information found.")

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
        return {"cwd": "Unknown", "cmdline": "Unknown"}

def main():
    # Argument parsing
    parser = argparse.ArgumentParser(description="A simple port scanner using nmap with additional process information.")
    parser.add_argument("-t", "--target", default="127.0.0.1", help="Target IP address to scan (default: localhost).")
    parser.add_argument("-sp", "--start-port", type=int, default=1000, help="Starting port number for the scan (default: 1000).")
    parser.add_argument("-ep", "--end-port", type=int, default=8000, help="Ending port number for the scan (default: 8000).")
    parser.add_argument("-p", "--process", action="store_true", help="Show process information for open ports.")
    parser.add_argument("-o", "--output", default="scan_results.json", help="Output JSON file for scan results (default: scan_results.json).")

    args = parser.parse_args()

    # Run the scan with the provided arguments
    scan_results = scan_with_nmap(args.target, args.start_port, args.end_port, args.process)

    # Write the results to a JSON file
    with open(args.output, 'w') as json_file:
        json.dump(scan_results, json_file, indent=4)
        print(f"\nScan results have been saved to {args.output}")

if __name__ == "__main__":
    main()