#!/usr/bin/env bash
set -euo pipefail

cd /app/app
mkdir -p /app/app/inst_folder
mkdir -p /circuits

mpirun --allow-run-as-root -np 1 \
    /app/app/rss_snark setup \
    --log-instance-size 13 \
    --log-num-workers-per-party 1 \
    --log-num-public-workers 0 \
    --key-out /app/app/inst_folder

# Export the input layout alongside the generated circuit.
cd /app/app/files
rg '^(input|nizkinput|output)\b' JRPC_complete_dynamic_optimized.arith > input_layout_complete.txt
cp JRPC_complete_dynamic_optimized.arith input_layout_complete.txt /circuits/
