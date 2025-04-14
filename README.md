# PowerInterface - RSPS Network Analysis Tool

A GUI application for monitoring, capturing, and manipulating network packets for RuneScape Private Servers.

## Features

- Real-time packet capture for RSPS clients
- Packet inspection and analysis
- Packet modification and replay
- Support for both Windows and WSL environments
- Filter packets using BPF-style expressions
- Save captures to PCAP format

## Prerequisites

- Python 3.6 or higher
- For WSL users:
  - An X server (e.g., VcXsrv, Xming)
  - WSL2 recommended

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/PowerInterface.git
   cd PowerInterface
   ```

2. Make the setup script executable:
   ```bash
   chmod +x setup.sh
   ```

3. Run the setup script:
   ```bash
   ./setup.sh
   ```

4. Run PowerInterface:
   ```bash
   source venv/bin/activate
   python power_interface.py
   ```

## WSL Setup Notes

If running in WSL, ensure you have:
1. An X server installed and running on Windows
2. The DISPLAY environment variable set correctly
3. Proper permissions for packet capture (run with sudo)

Example WSL run command:
```bash
sudo python power_interface.py
```

## Manual Setup

If you prefer to set up manually:

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

## Usage

1. Launch PowerInterface
2. Select your RSPS client process from the dropdown
3. Click "Start Capture" to begin capturing packets
4. Use the filter box to filter packets (e.g., "tcp.port == 43594")
5. Click on packets to view details and hex dump
6. Use the Packet Editor tab to modify and resend packets

## Troubleshooting

1. **No GUI in WSL**: Ensure X server is running and DISPLAY is set
2. **Permission Denied**: Run with sudo for packet capture
3. **Process Not Found**: Ensure the RSPS client is running
4. **WSL Network Issues**: Check WSL network configuration

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.