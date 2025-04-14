# PowerInterface - RSPS Network Analysis Tool

PowerInterface is a GUI-based application for monitoring, capturing, editing, and resending network packets associated with RuneScape Private Servers (RSPS). This tool is designed to help security engineers identify potential vulnerabilities and ensure the integrity of server-client communications.

## Features

- **Process Selection**: Scan and select running RSPS processes
- **Packet Capture**: Monitor and display network traffic in real-time
- **Packet Analysis**: Inspect packet details and structure
- **Packet Editing**: Modify packet data and resend to the server
- **Filtering**: Filter packets based on various criteria
- **Export**: Save captured packets to PCAP files

## Requirements

- Python 3.x
- Administrator/root privileges (required for packet capture)
- Operating systems: Windows, macOS, Linux

## Installation

1. Clone this repository or download the source code:
   ```bash
   git clone https://github.com/yourusername/PowerInterface.git
   cd PowerInterface
   ```

2. Set up a Python virtual environment:

   **Windows:**
   ```bash
   python -m venv venv
   venv\Scripts\activate
   ```

   **Linux/macOS:**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```

4. Install system dependencies (Linux/Ubuntu only):
   ```bash
   sudo apt-get install -y python3-pyqt5 python3-pyqt5.qtwebengine python3-pyqt5.qtwebchannel
   sudo apt-get install -y libxcb-xinerama0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-render-util0
   ```

## Usage

1. Activate the virtual environment (if not already activated):

   **Windows:**
   ```bash
   venv\Scripts\activate
   ```

   **Linux/macOS:**
   ```bash
   source venv/bin/activate
   ```

2. Run the application with administrator/root privileges:

   **Windows:**
   Right-click on command prompt or PowerShell and select "Run as administrator", then:
   ```bash
   python power_interface.py
   ```

   **Linux/macOS:**
   ```bash
   sudo venv/bin/python power_interface.py
   ```

   **WSL Users:**
   If using Windows Subsystem for Linux, make sure you have an X server (like VcXsrv) running and set:
   ```bash
   export DISPLAY=:0
   sudo venv/bin/python power_interface.py
   ```

3. Select a running RSPS process from the dropdown menu.

4. Click "Start Capture" to begin monitoring network packets.

5. Use the packet table to view captured packets and their details.

6. Select a packet to view its details or edit its content.

7. Modify packet data in the "Packet Editor" tab and click "Apply Changes" to update.

8. Use the "Resend Packet" button to send modified packets back to the server.

## Troubleshooting

- If you get an "externally-managed-environment" error, make sure you're using a virtual environment as described in the installation steps.
- If you encounter Qt/GUI issues on Linux:
  - Ensure all required Qt dependencies are installed
  - Check that you have proper X server configuration if using WSL
  - Try running `sudo apt-get install -y qtbase5-dev qt5-qmake python3-pyqt5 libqt5gui5`

## Security Considerations

- This tool should only be used for legitimate security research and testing.
- Always ensure you have permission to monitor and modify network traffic for the target application.
- Be cautious when modifying and resending packets, as this may cause unexpected behavior in the target application.

## License

[Insert your chosen license here]

## Disclaimer

This tool is provided for educational and research purposes only. The authors are not responsible for any misuse or damage caused by this software.