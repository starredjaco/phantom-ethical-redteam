#!/bin/bash
echo "🚀 Installing Phantom + external tools..."

sudo apt update && sudo apt install -y golang-go ruby python3-pip curl git nmap

# Bettercap (official)
sudo apt install -y bettercap

# Zphisher (templates educational phishing)
git clone https://github.com/htr-tech/zphisher.git tools/zphisher_repo || true
chmod +x tools/zphisher_repo/zphisher.sh

# CyberStrikeAI (orchestrateur AI-native)
git clone https://github.com/Ed1s0nZ/CyberStrikeAI.git tools/cyberstrike_repo || true
cd tools/cyberstrike_repo && go build -o ../../bin/cyberstrike ./cmd/cyberstrike && cd ../..

echo "✅ Install complete !"
echo "Add to your PATH : export PATH=\$PATH:\$(pwd)/bin"
