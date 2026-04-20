#!/bin/bash
# CTF Helper Installation Script
# This script installs the CTF Navigator and all helper scripts

set -e  # Exit on any error

echo "=== CTF Helper Installation ==="
echo "This script will:"
echo "1. Install Python3 and pip if needed"
echo "2. Install PyInstaller"
echo "3. Download CTF Helper scripts from GitHub"
echo "4. Build the CTF Navigator executable"
echo "5. Install everything to ~/Downloads"
echo ""

# Check if we're running as root (not recommended, but check)
if [ "$EUID" -eq 0 ]; then
    echo "Warning: Running as root is not recommended for this script."
    read -p "Continue anyway? (y/N) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Update package list and install dependencies
echo "Updating package list..."
if command -v apt-get >/dev/null 2>&1; then
    sudo apt-get update
    sudo apt-get install -y python3 python3-pip python3-tk git
elif command -v yum >/dev/null 2>&1; then
    sudo yum update -y
    sudo yum install -y python3 python3-pip tkinter git
elif command -v dnf >/dev/null 2>&1; then
    sudo dnf update -y
    sudo dnf install -y python3 python3-pip tkinter git
elif command -v pacman >/dev/null 2>&1; then
    sudo pacman -Syu --noconfirm
    sudo pacman -S --noconfirm python3 python-pip tk git
else
    echo "Unknown package manager. Please install Python3, pip, and git manually."
    exit 1
fi

# Install PyInstaller
echo "Installing PyInstaller..."
pip3 install --user pyinstaller
# Add user's bin to PATH if needed
export PATH="$HOME/.local/bin:$PATH"

# Create directories
echo "Creating directories..."
mkdir -p "$HOME/Documents"
mkdir -p "$HOME/Downloads/ctf_helper_build"

# Navigate to build directory
cd "$HOME/Downloads/ctf_helper_build"

# Download the repository
echo "Downloading CTF Helper repository..."
if [ -d ".git" ]; then
    git pull origin main
else
    git clone https://github.com/david-constantinescu/ctf-helper.git .
fi

# Check if we have the scripts folder
if [ ! -d "scripts" ]; then
    echo "Error: 'scripts' folder not found in repository."
    echo "Repository contents:"
    ls -la
    exit 1
fi

# Copy scripts to Documents folder
echo "Copying scripts to Documents folder..."
cp -r scripts/* "$HOME/Documents/useful python scripts/" 2>/dev/null || mkdir -p "$HOME/Documents/useful python scripts" && cp -r scripts/* "$HOME/Documents/useful python scripts/"

# Copy the main Python file
echo "Copying CTF Navigator..."
cp ctf_navigator.py "$HOME/Downloads/"

# Make the Python file executable
chmod +x "$HOME/Downloads/ctf_navigator.py"

# Install any Python dependencies from requirements.txt if it exists
if [ -f "requirements.txt" ]; then
    echo "Installing Python dependencies..."
    pip3 install --user -r requirements.txt
fi

# Build executable with PyInstaller
echo "Building executable with PyInstaller..."
pyinstaller --onefile --windowed --name="CTF Navigator" "$HOME/Downloads/ctf_navigator.py"

# Check if build succeeded
if [ ! -f "dist/CTF Navigator" ]; then
    echo "Error: PyInstaller failed to create executable."
    ls -la dist/
    exit 1
fi

# Move executable to Downloads and clean up
echo "Installing executable..."
mv "dist/CTF Navigator" "$HOME/Downloads/CTF Navigator"
chmod +x "$HOME/Downloads/CTF Navigator"

# Clean up build files
echo "Cleaning up..."
cd "$HOME"
rm -rf "$HOME/Downloads/ctf_helper_build"

# Create README in Downloads
echo "Creating README..."
cat > "$HOME/Downloads/README.md" << 'EOF'
# CTF Helper Suite

This package contains:
1. CTF Navigator - A rule-based expert system for CTF competitions
2. Collection of useful Python scripts for various CTF challenges

## Files in ~/Downloads/
- `CTF Navigator` - Executable file (double-click to run)
- `ctf_navigator.py` - Source Python file
- `README.md` - This file

## Files in ~/Documents/useful python scripts/
- Various Python scripts for CTF challenges (decoding, forensics, etc.)

## Usage
1. Double-click the "CTF Navigator" executable to run the GUI application
2. Or run `python3 ctf_navigator.py` from the terminal
3. Use the "+ Add Artifact" button to load files for analysis
4. Double-click artifacts to edit hints and details
5. Click "Run" on suggestions to execute commands and capture output
6. Mark output as interesting/not interesting to track your investigation

## Supported Challenge Types
- Network (PCAP analysis)
- Image Steganography
- Audio Steganography
- Archives (ZIP, etc.)
- Executables (ELF, PE)
- PDFs
- Text/encoded strings
- Web applications
- And more!

## Notes
- The application is rule-based and competition-legal (no AI/ML)
- All tools execute in the background with output capture
- Your investigation path and notes are preserved
- For best results, keep your wordlists and common tools updated

## Troubleshooting
If you encounter issues:
1. Make sure Python3 is installed: `python3 --version`
2. Try running the Python script directly: `python3 ctf_navigator.py`
3. Check that scripts are in ~/Documents/useful python scripts/
4. Ensure you have execute permissions: `chmod +x ~/Downloads/CTF\ Navigator`

Happy hacking!
EOF

echo ""
echo "=== Installation Complete! ==="
echo "Executable installed to: $HOME/Downloads/CTF Navigator"
echo "Source code available at: $HOME/Downloads/ctf_navigator.py"
echo "Scripts installed to: $HOME/Documents/useful python scripts/"
echo "README available at: $HOME/Downloads/README.md"
echo ""
echo "To run the application:"
echo "  Double-click 'CTF Navigator' in your Downloads folder"
echo "  OR run: $HOME/Downloads/CTF Navigator"
echo "  OR run: python3 $HOME/Downloads/ctf_navigator.py"
echo ""