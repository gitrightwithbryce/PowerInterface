#!/bin/bash

# Exit on error
set -e

echo "Setting up PowerInterface development environment..."

# Check if Python 3 is installed
if ! command -v python3 &> /dev/null; then
    echo "Python 3 is required but not installed. Please install Python 3 first."
    exit 1
fi

# Create virtual environment if it doesn't exist
if [ ! -d "venv" ]; then
    echo "Creating virtual environment..."
    python3 -m venv venv
fi

# Activate virtual environment
echo "Activating virtual environment..."
source venv/bin/activate

# Upgrade pip
echo "Upgrading pip..."
python -m pip install --upgrade pip

# Install requirements
echo "Installing dependencies..."
pip install scapy
pip install PyQt5
pip install psutil
pip install pandas
pip install numpy
pip install hexdump

# Create requirements.txt for future reference
echo "Generating requirements.txt..."
pip freeze > requirements.txt

# Check if running on WSL
if grep -qi microsoft /proc/version; then
    echo "WSL detected - Installing additional dependencies..."
    # Check if X server is installed
    if ! command -v xauth &> /dev/null; then
        echo "Please ensure you have an X server installed for the GUI to work in WSL."
        echo "You can install one with: sudo apt-get install x11-apps"
    fi
fi

echo "Setup complete! You can now run PowerInterface with:"
echo "source venv/bin/activate && python power_interface.py"

# Keep the terminal open if running in Windows
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    read -p "Press Enter to exit..."
fi 