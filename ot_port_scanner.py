#!/usr/bin/env python3

import socket
import time
import argparse
from typing import List, Dict, Optional
import sys
from concurrent.futures import ThreadPoolExecutor
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)

# Common OT/ICS protocol ports and their descriptions
OT_PORTS = {
    20000: "DNP3",
    502: "Modbus TCP",
    44818: "EtherNet/IP",
    102: "S7COMM (Siemens S7)",
    2222: "EtherCAT",
    9600: "PROFINET",
    1962: "PCWorx",
    789: "Red Lion Crimson",
    1911: "Fox",
    4000: "OMRON FINS",
    11001: "SRTP (GE-SRTP)"
}

class OTPortScanner:
    def __init__(
        self,
        target: str,
        timeout: float = 2.0,
        delay: float = 0.1,
        max_threads: int = 2
    ):
        """
        Initialize the OT Port Scanner with safety parameters.
        
        Args:
            target: Target IP address
            timeout: Socket timeout in seconds
            delay: Delay between scans in seconds
            max_threads: Maximum number of concurrent scans
        """
        self.target = target
        self.timeout = timeout
        self.delay = delay
        self.max_threads = max_threads
        self.results: Dict[int, str] = {}
        
    def check_port(self, port: int) -> Optional[str]:
        """
        Gently check if a port is open using a TCP SYN scan.
        
        Args:
            port: Port number to scan
            
        Returns:
            Optional[str]: Protocol name if port is open, None otherwise
        """
        try:
            # Create TCP socket with generous timeout
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            
            # Attempt connection
            result = sock.connect_ex((self.target, port))
            
            if result == 0:
                protocol = OT_PORTS.get(port, "Unknown OT Protocol")
                logging.info(f"Port {port} is open - Likely {protocol}")
                return protocol
                
        except socket.gaierror:
            logging.error(f"Hostname could not be resolved: {self.target}")
            return None
        except socket.error:
            logging.error(f"Could not connect to {self.target}:{port}")
            return None
        finally:
            sock.close()
            # Implement delay between scans for gentleness
            time.sleep(self.delay)
        
        return None

    def scan(self) -> Dict[int, str]:
        """
        Perform the port scan with built-in safety measures.
        
        Returns:
            Dict[int, str]: Dictionary of open ports and their protocols
        """
        logging.info(f"Starting gentle OT port scan of {self.target}")
        logging.info("This scanner is designed to be non-intrusive for OT systems")
        
        try:
            # Verify target is reachable before scanning
            socket.gethostbyname(self.target)
            
            with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                # Only scan known OT ports
                futures = {
                    executor.submit(self.check_port, port): port 
                    for port in OT_PORTS.keys()
                }
                
                for future in futures:
                    port = futures[future]
                    protocol = future.result()
                    if protocol:
                        self.results[port] = protocol
                        
        except socket.gaierror:
            logging.error(f"Target {self.target} is not reachable")
            sys.exit(1)
            
        return self.results

def main():
    parser = argparse.ArgumentParser(
        description="Gentle OT/ICS Port Scanner - Safe for industrial systems"
    )
    parser.add_argument("target", help="Target IP address or hostname")
    parser.add_argument(
        "--timeout",
        type=float,
        default=2.0,
        help="Timeout for each port scan in seconds (default: 2.0)"
    )
    parser.add_argument(
        "--delay",
        type=float,
        default=0.1,
        help="Delay between scans in seconds (default: 0.1)"
    )
    parser.add_argument(
        "--max-threads",
        type=int,
        default=2,
        help="Maximum number of concurrent scans (default: 2)"
    )
    
    args = parser.parse_args()
    
    scanner = OTPortScanner(
        target=args.target,
        timeout=args.timeout,
        delay=args.delay,
        max_threads=args.max_threads
    )
    
    results = scanner.scan()
    
    if results:
        print("\nOpen ports and protocols:")
        for port, protocol in results.items():
            print(f"Port {port}: {protocol}")
    else:
        print("\nNo open OT ports found")

if __name__ == "__main__":
    main() 