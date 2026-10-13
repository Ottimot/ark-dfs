#!/usr/bin/env bash
set -euo pipefail

export MPI_HOME="$HOME/opt/openmpi-4.1.2"
export PATH="$MPI_HOME/bin:$PATH"
export LD_LIBRARY_PATH="$MPI_HOME/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"

mpirun -np 1 ../../target/release/examples/rss_snark setup  --log-instance-size 13 --log-num-workers-per-party 1 --log-num-public-workers 0 --key-out inst_folder
