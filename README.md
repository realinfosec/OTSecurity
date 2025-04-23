# OT Port Scanner GUI

A graphical user interface application for scanning operational technology (OT) networks and identifying open ports. This tool is designed to help network administrators and security professionals assess the security of industrial control systems and OT networks.

## Features

- **Multiple Scanning Methods**:
  - Single IP address scanning
  - Subnet scanning (CIDR notation)
  - Bulk IP scanning from file
  
- **Configurable Scan Parameters**:
  - Adjustable timeout settings
  - Customizable scan delay
  - Configurable thread count for parallel scanning
  
- **User-Friendly Interface**:
  - Real-time scan progress monitoring
  - Clear results display in a sortable table
  - Status updates and progress bar
  
- **Export Capabilities**:
  - Export results to CSV format
  - Export results to JSON format
  
## Requirements

- Python 3.x
- tkinter (usually comes with Python)
- Required Python packages:
  ```
  ipaddress
  threading
  queue
  ```

## Installation

1. Clone or download this repository to your local machine
2. Ensure Python 3.x is installed on your system
3. Install required dependencies (if not already installed):
   ```bash
   pip install ipaddress
   ```

## Usage

1. Run the application:
   ```bash
   python ot_port_scanner_gui.py
   ```

2. Using the GUI:
   - Enter a single IP address or subnet in CIDR notation
   - Or load multiple IP addresses from a file
   - Configure scan parameters (timeout, delay, threads)
   - Click "Start Scan" to begin scanning
   - Monitor progress in real-time
   - Export results as needed

## Scan Configuration Options

- **Timeout**: Time to wait for each port response (in seconds)
- **Delay**: Time between port scans (in seconds)
- **Max Threads**: Maximum number of concurrent scanning threads

## Export Options

Results can be exported in two formats:
- CSV (Comma Separated Values)
- JSON (JavaScript Object Notation)

Both formats include:
- IP Address
- Port Number
- Protocol
- Status
- Timestamp

## Security Considerations

- Always ensure you have permission to scan the target network
- Use appropriate delays to avoid network disruption
- Consider the impact on operational technology systems
- Follow your organization's security policies

## License

This project is open source and available under the MIT License.

## Contributing

Contributions are welcome! Please feel free to submit pull requests or create issues for bugs and feature requests. 