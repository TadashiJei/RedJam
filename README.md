# Wireless Network Testing Tool ( RED JAM ) - Python version
- ESP32 & 8266 will be released soon in different branch so stay tuned

## ⚠️ Important Notice
This tool is designed **strictly for educational and authorized testing purposes**. Users must:
- Have explicit permission to test any networks
- Understand and comply with all applicable laws and regulations
- Use this tool responsibly and ethically
- Have proper authorization before deployment

## Overview
This Python-based tool provides network administrators and security professionals with capabilities to analyze wireless networks for security assessment purposes. It utilizes the Scapy library for packet manipulation and network interface control.

## Features
- Monitor Mode Management
  - Automatic interface configuration
  - Channel hopping across wireless frequencies
  - Support for both North American (11) and World (13) channel ranges

- Network Discovery
  - Access Point (AP) detection and logging
  - Client device identification
  - Real-time SSID scanning
  - Channel tracking

- Advanced Capabilities
  - Targeted or broadcast packet transmission
  - Configurable packet timing intervals
  - Customizable packet burst counts
  - Channel-specific monitoring
  - MAC address tracking

## Prerequisites
- Python 3.x
- Root/Administrator privileges
- Scapy library
- Compatible wireless network interface with monitor mode support

## Installation
```bash
# Install required Python package
pip install scapy
```

## Usage
```bash
sudo python3 wireless_tool.py [-h] [-i INTERFACE] [-c CHANNEL] [-m MAXIMUM] 
                             [-t TIMEINTERVAL] [-p PACKETS] [-d] [-a ACCESSPOINT] 
                             [--world]
```

### Command Line Arguments
- `-i, --interface`: Specify the monitor mode interface
- `-c, --channel`: Listen on a specific channel only
- `-m, --maximum`: Maximum number of clients to process
- `-t, --timeinterval`: Time interval between packets (default: 0)
- `-p, --packets`: Number of packets per burst (default: 1)
- `-d, --directedonly`: Enable directed packet mode only
- `-a, --accesspoint`: Target specific access point MAC address
- `--world`: Enable 13-channel scanning (non-North American)

## Core Functions

### Monitor Mode Management
```python
start_monitor_mode(interface: str) -> str
```
Configures the specified network interface for monitor mode operation.

### Channel Management
```python
channel_hop(mon_iface: str, args: argparse.Namespace, stop_event: Event) -> None
```
Handles channel switching for comprehensive network scanning.

### Network Discovery
```python
packet_handler(pkt, clients_aps: List[Tuple[str, str, str, str]], 
              aps: List[Tuple[str, str, str]], args: argparse.Namespace) -> None
```
Processes captured packets to identify network devices and relationships.

### Interface Management
```python
get_interface_mac(iface: str) -> str
```
Retrieves the MAC address of the specified network interface.

## Technical Details

### Packet Processing
The tool utilizes Scapy's packet manipulation capabilities to:
- Decode beacon frames for AP discovery
- Process data frames for client detection
- Handle management frames for network mapping

### Logging and Output
- Colored console output for better visibility
- Structured logging with timestamps
- Error handling and status reporting

### Threading
- Implements concurrent operations for channel hopping
- Event-based thread control for clean shutdown
- Thread-safe data structures for device tracking

## Error Handling
- Root privilege verification
- Interface compatibility checking
- Graceful shutdown on interruption
- Exception management for packet processing

## Recovery
The tool automatically restores network interfaces to their original state upon:
- Normal program termination
- Keyboard interruption (Ctrl+C)
- Error conditions

## Security Considerations
- Implements safe defaults for packet operations
- Includes verification steps for interface modes
- Maintains logs for accountability
- Requires explicit configuration for advanced features

## Developer Notes
- Built with type hints for better code maintainability
- Modular design for easy feature extension
- Comprehensive command-line argument parsing
- Clear separation of concerns in functionality

## License
This tool should only be used in accordance with applicable laws and regulations, with proper authorization and permissions.
