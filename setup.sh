#!/bin/bash
# Run from WSL Ubuntu terminal
set -e

echo "[setup] Installing Python dependencies (no liboqs)..."
pip install -r requirements.txt

echo "[setup] Creating data directories..."
mkdir -p data
for i in 1 2 3 4 5; do mkdir -p data/node_$i; done

echo "[setup] Running crypto tests (no Docker needed)..."
pytest tests/test_sss.py tests/test_lagrange.py tests/test_hkdf.py \
       tests/test_keyfile.py tests/test_share_store.py tests/test_ledger.py \
       -v --tb=short

echo ""
echo "✅ Setup complete. Run 'make demo' to see the full demonstration."
echo "   For post-quantum mode: install Docker Desktop, then 'make docker-demo'"
