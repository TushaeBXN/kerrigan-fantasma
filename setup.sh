#!/usr/bin/env bash
set -e

echo "======================================================"
echo "  KERRIGAN-FANTASMA Setup"
echo "======================================================"

# Check Ollama
if ! command -v ollama &> /dev/null; then
    echo "[ERROR] Ollama not found. Install from https://ollama.com"
    exit 1
fi
echo "[OK] Ollama found: $(ollama --version)"

# Pull required models
echo ""
echo "[1/3] Pulling base models..."
ollama pull deepseek-coder:6.7b
ollama pull llama3.2:3b

# Create kerrigan-fantasma model
echo ""
echo "[2/3] Creating kerrigan-fantasma model..."
ollama create kerrigan-fantasma -f config/Modelfile
echo "[OK] kerrigan-fantasma model ready"

# Install Python deps
echo ""
echo "[3/3] Installing Python dependencies..."
pip3 install --quiet ollama chromadb

echo ""
echo "======================================================"
echo "  Setup complete."
echo "  Run with: python3 kerrigan.py"
echo "======================================================"
