#!/usr/bin/env python3

import tkinter as tk
from tkinter import ttk, scrolledtext, filedialog, messagebox
import threading
import json
import csv
from datetime import datetime
import ipaddress
from typing import List, Optional, Union
import queue
import os

# Import our original scanner
from ot_port_scanner import OTPortScanner, OT_PORTS

class OTScannerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("OT Port Scanner")
        self.root.geometry("900x700")
        
        # Variables
        self.target_var = tk.StringVar()
        self.subnet_var = tk.StringVar()
        self.timeout_var = tk.StringVar(value="2.0")
        self.delay_var = tk.StringVar(value="0.1")
        self.max_threads_var = tk.StringVar(value="2")
        self.scan_queue = queue.Queue()
        self.is_scanning = False
        self.total_hosts = 0
        self.scanned_hosts = 0
        
        # Create GUI elements
        self.create_input_frame()
        self.create_config_frame()
        self.create_results_frame()
        self.create_status_bar()
        self.create_progress_bar()
        
        # Configure grid weights
        self.root.grid_rowconfigure(3, weight=1)
        self.root.grid_columnconfigure(0, weight=1)
        
    def create_input_frame(self):
        """Create the input section for IP addresses and subnet"""
        input_frame = ttk.LabelFrame(self.root, text="Target Input", padding="5")
        input_frame.grid(row=0, column=0, padx=5, pady=5, sticky="ew")
        
        # Direct IP input
        ttk.Label(input_frame, text="IP Address:").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(input_frame, textvariable=self.target_var).grid(row=0, column=1, padx=5, pady=5, sticky="ew")
        
        # Subnet input
        ttk.Label(input_frame, text="Subnet:").grid(row=1, column=0, padx=5, pady=5)
        subnet_entry = ttk.Entry(input_frame, textvariable=self.subnet_var)
        subnet_entry.grid(row=1, column=1, padx=5, pady=5, sticky="ew")
        ttk.Label(input_frame, text="(e.g., 192.168.1.0/24)").grid(row=1, column=2, padx=5, pady=5)
        
        # Button frame
        button_frame = ttk.Frame(input_frame)
        button_frame.grid(row=2, column=0, columnspan=3, pady=5)
        
        # File input
        ttk.Button(button_frame, text="Load IP List", command=self.load_ip_file).pack(side=tk.LEFT, padx=5)
        
        # Scan control buttons
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Stop Scan", command=self.stop_scan).pack(side=tk.LEFT, padx=5)
        ttk.Button(button_frame, text="Clear Results", command=self.clear_results).pack(side=tk.LEFT, padx=5)
        
        input_frame.grid_columnconfigure(1, weight=1)
        
    def create_config_frame(self):
        """Create the configuration section"""
        config_frame = ttk.LabelFrame(self.root, text="Scan Configuration", padding="5")
        config_frame.grid(row=1, column=0, padx=5, pady=5, sticky="ew")
        
        # Timeout configuration
        ttk.Label(config_frame, text="Timeout (s):").grid(row=0, column=0, padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.timeout_var, width=10).grid(row=0, column=1, padx=5, pady=5)
        
        # Delay configuration
        ttk.Label(config_frame, text="Delay (s):").grid(row=0, column=2, padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.delay_var, width=10).grid(row=0, column=3, padx=5, pady=5)
        
        # Thread configuration
        ttk.Label(config_frame, text="Max Threads:").grid(row=0, column=4, padx=5, pady=5)
        ttk.Entry(config_frame, textvariable=self.max_threads_var, width=10).grid(row=0, column=5, padx=5, pady=5)
        
    def create_progress_bar(self):
        """Create progress bar"""
        progress_frame = ttk.Frame(self.root)
        progress_frame.grid(row=2, column=0, padx=5, pady=5, sticky="ew")
        
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(
            progress_frame,
            variable=self.progress_var,
            maximum=100
        )
        self.progress_bar.grid(row=0, column=0, sticky="ew")
        progress_frame.grid_columnconfigure(0, weight=1)
        
    def create_results_frame(self):
        """Create the results display section"""
        results_frame = ttk.LabelFrame(self.root, text="Scan Results", padding="5")
        results_frame.grid(row=3, column=0, padx=5, pady=5, sticky="nsew")
        
        # Create Treeview for results
        columns = ("IP Address", "Port", "Protocol", "Status", "Timestamp")
        self.results_tree = ttk.Treeview(results_frame, columns=columns, show="headings")
        
        # Set column headings
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=100)
        
        # Add scrollbars
        y_scrollbar = ttk.Scrollbar(results_frame, orient="vertical", command=self.results_tree.yview)
        x_scrollbar = ttk.Scrollbar(results_frame, orient="horizontal", command=self.results_tree.xview)
        self.results_tree.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        # Grid layout
        self.results_tree.grid(row=0, column=0, sticky="nsew")
        y_scrollbar.grid(row=0, column=1, sticky="ns")
        x_scrollbar.grid(row=1, column=0, sticky="ew")
        
        # Export button
        export_frame = ttk.Frame(results_frame)
        export_frame.grid(row=2, column=0, columnspan=2, pady=5)
        
        ttk.Button(export_frame, text="Export Results (CSV)", command=lambda: self.export_results("csv")).pack(side=tk.LEFT, padx=5)
        ttk.Button(export_frame, text="Export Results (JSON)", command=lambda: self.export_results("json")).pack(side=tk.LEFT, padx=5)
        
        results_frame.grid_rowconfigure(0, weight=1)
        results_frame.grid_columnconfigure(0, weight=1)
        
    def create_status_bar(self):
        """Create the status bar"""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief="sunken")
        status_bar.grid(row=4, column=0, sticky="ew", padx=5, pady=5)
        
    def validate_ip(self, ip_str: str) -> bool:
        """Validate IP address"""
        try:
            ipaddress.ip_address(ip_str)
            return True
        except ValueError:
            return False
            
    def validate_subnet(self, subnet_str: str) -> bool:
        """Validate subnet"""
        try:
            ipaddress.ip_network(subnet_str, strict=False)
            return True
        except ValueError:
            return False
            
    def get_ip_range(self, subnet_str: str) -> List[str]:
        """Get list of IP addresses from subnet"""
        try:
            network = ipaddress.ip_network(subnet_str, strict=False)
            return [str(ip) for ip in network.hosts()]
        except ValueError:
            return []
            
    def clear_results(self):
        """Clear all results from the treeview"""
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        self.status_var.set("Results cleared")
            
    def load_ip_file(self):
        """Load IP addresses from a file"""
        file_path = filedialog.askopenfilename(
            filetypes=[("Text files", "*.txt"), ("CSV files", "*.csv"), ("All files", "*.*")]
        )
        if not file_path:
            return
            
        try:
            with open(file_path, 'r') as f:
                ips = [line.strip() for line in f if line.strip()]
            
            # Validate IPs
            valid_ips = [ip for ip in ips if self.validate_ip(ip)]
            
            if valid_ips:
                self.target_var.set(valid_ips[0])  # Set first IP in entry
                # Add all IPs to queue
                for ip in valid_ips:
                    self.scan_queue.put(ip)
                    
                messagebox.showinfo("Success", f"Loaded {len(valid_ips)} valid IP addresses")
            else:
                messagebox.showerror("Error", "No valid IP addresses found in file")
                
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load IP file: {str(e)}")
            
    def start_scan(self):
        """Start the scanning process"""
        if self.is_scanning:
            messagebox.showwarning("Warning", "Scan already in progress")
            return
            
        # Clear previous results
        self.clear_results()
            
        # Validate inputs
        try:
            timeout = float(self.timeout_var.get())
            delay = float(self.delay_var.get())
            max_threads = int(self.max_threads_var.get())
            
            if timeout <= 0 or delay <= 0 or max_threads <= 0:
                raise ValueError("Values must be positive")
                
        except ValueError as e:
            messagebox.showerror("Error", "Invalid configuration values")
            return
            
        # Process subnet if provided
        subnet = self.subnet_var.get().strip()
        if subnet:
            if self.validate_subnet(subnet):
                ip_list = self.get_ip_range(subnet)
                for ip in ip_list:
                    self.scan_queue.put(ip)
            else:
                messagebox.showerror("Error", "Invalid subnet format")
                return
                
        # Process single IP if provided
        current_target = self.target_var.get().strip()
        if current_target and self.validate_ip(current_target):
            self.scan_queue.put(current_target)
            
        if self.scan_queue.empty():
            messagebox.showerror("Error", "No valid IP addresses to scan")
            return
            
        self.total_hosts = self.scan_queue.qsize()
        self.scanned_hosts = 0
        self.is_scanning = True
        self.status_var.set("Scanning...")
        self.progress_var.set(0)
        
        # Start scan thread
        scan_thread = threading.Thread(target=self.scan_worker)
        scan_thread.daemon = True
        scan_thread.start()
        
    def stop_scan(self):
        """Stop the scanning process"""
        self.is_scanning = False
        self.status_var.set("Scan stopped by user")
        
    def update_progress(self):
        """Update progress bar"""
        if self.total_hosts > 0:
            progress = (self.scanned_hosts / self.total_hosts) * 100
            self.progress_var.set(progress)
        
    def scan_worker(self):
        """Worker thread for scanning"""
        while self.is_scanning and not self.scan_queue.empty():
            target = self.scan_queue.get()
            
            try:
                scanner = OTPortScanner(
                    target=target,
                    timeout=float(self.timeout_var.get()),
                    delay=float(self.delay_var.get()),
                    max_threads=int(self.max_threads_var.get())
                )
                
                self.status_var.set(f"Scanning {target}...")
                results = scanner.scan()
                
                # Update results in GUI thread
                timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                if results:
                    for port, protocol in results.items():
                        self.root.after(0, self.add_result, target, port, protocol, "Open", timestamp)
                else:
                    self.root.after(0, self.add_result, target, "-", "-", "No open ports", timestamp)
                    
            except Exception as e:
                self.root.after(0, self.add_result, target, "-", "-", f"Error: {str(e)}", timestamp)
            
            self.scanned_hosts += 1
            self.root.after(0, self.update_progress)
                
        self.is_scanning = False
        self.root.after(0, self.status_var.set, "Scan completed")
        
    def add_result(self, ip, port, protocol, status, timestamp):
        """Add a result to the treeview"""
        self.results_tree.insert("", "end", values=(ip, port, protocol, status, timestamp))
        
    def export_results(self, format_type="csv"):
        """Export results to a file"""
        if not self.results_tree.get_children():
            messagebox.showwarning("Warning", "No results to export")
            return
            
        if format_type == "csv":
            file_types = [("CSV files", "*.csv")]
            default_ext = ".csv"
        else:
            file_types = [("JSON files", "*.json")]
            default_ext = ".json"
            
        file_path = filedialog.asksaveasfilename(
            defaultextension=default_ext,
            filetypes=file_types,
            initialfile=f"ot_scan_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}{default_ext}"
        )
        
        if not file_path:
            return
            
        try:
            results = []
            for item in self.results_tree.get_children():
                values = self.results_tree.item(item)["values"]
                results.append({
                    "IP Address": values[0],
                    "Port": values[1],
                    "Protocol": values[2],
                    "Status": values[3],
                    "Timestamp": values[4]
                })
                
            if format_type == "csv":
                with open(file_path, 'w', newline='') as f:
                    writer = csv.DictWriter(f, fieldnames=["IP Address", "Port", "Protocol", "Status", "Timestamp"])
                    writer.writeheader()
                    writer.writerows(results)
            else:
                with open(file_path, 'w') as f:
                    json.dump(results, f, indent=2)
                    
            messagebox.showinfo("Success", f"Results exported successfully to {format_type.upper()}")
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export results: {str(e)}")

def main():
    root = tk.Tk()
    app = OTScannerGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main() 