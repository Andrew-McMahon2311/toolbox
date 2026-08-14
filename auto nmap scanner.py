import nmap

def run_python_nmap():
    target = input("Enter target IP/Hostname: ").strip()
    if not target:
        print("[!] Please input a valid target!")
        return
    
    print("\nSelect Timing Template:")
    print("0) T0 - Paranoid")
    print("1) T1 - Sneaky")
    print("2) T2 - Polite")
    print("3) T3 - Normal")
    print("4) T4 - Aggressive")
    print("5) T5 - Insane")

    t_choice = input("\nChoice [0-5] (default: 3): ").strip() or "3"
    timing = f"-T{t_choice if t_choice in '012345' else '3'}"

    print("\nSelect Scan Type:")
    print("1) Default Scripts & Versions (-sC -sV)")
    print("2) Quick Top Ports (-F -sV)")
    print("3) All Ports (-p- -sV)")
    
    scan_choice = input("\nChoice [1-3] (default: 1): ").strip() or "1"
    
    arguments_map = {
        "1": f"{timing} -sC -sV",
        "2": f"{timing} -F -sV",
        "3": f"{timing} -p- -sV"
    }
    
    args = arguments_map.get(scan_choice, arguments_map["1"])

    nm = nmap.PortScanner()
    print(f"\n[*] Scanning {target} with args: '{args}'...\n" + "=" * 50)
    
    try:
        nm.scan(hosts=target, arguments=args)
        
        for host in nm.all_hosts():
            print(f"\nHost: {host} ({nm[host].hostname()})")
            print(f"State: {nm[host].state()}")
            
            for proto in nm[host].all_protocols():
                print(f"\nProtocol: {proto.upper()}")
                ports = nm[host][proto].keys()
                
                for port in sorted(ports):
                    state = nm[host][proto][port]['state']
                    service = nm[host][proto][port]['name']
                    product = nm[host][proto][port].get('product', '')
                    version = nm[host][proto][port].get('version', '')
                    
                    print(f"  Port {port}/{proto}\tState: {state}\tService: {service} {product} {version}".strip())
                    
    except KeyboardInterrupt:
        print("\n[!] Scan cancelled.")
    except Exception as e:
        print(f"\n[!] Error: {e}")

if __name__ == "__main__":
    run_python_nmap()