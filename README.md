# DFS container simulation

This research project extends the artifact for **DFS: Delegation-friendly
zkSNARK and Private Delegation of Provers**, by Yuncong Hu, Pratyush Mishra,
Xiao Wang, Jie Xie, Kang Yang, Yu Yu and Yuwen Zhang (USENIX Security 2025).
The original implementation provides the DFS proof system and delegation
protocols; this checkout adds TLS instrumentation, circuit parsing, Merkle-tree
proof support and a simulated container network.

- [Original paper](https://www.usenix.org/conference/usenixsecurity25/presentation/hu-yuncong)
- [Original artifact, version cited by the artifact appendix](https://doi.org/10.5281/zenodo.14677896)
- [Artifact appendix](https://secartifacts.github.io/usenixsec2025/appendix-files/sec25cycle1ae-final77.pdf)

**For research simulations using containers and a simulated Docker network only.
Not for production or real traffic.** The original code is an academic prototype;
this extension has not been established as production software. The customized
TLS implementation deliberately exposes handshake material for the experiment.

## Host requirements

Use an **amd64 Linux machine**, with Ubuntu 24.04 as the target environment.
You need Bash, Docker Engine, the Docker Compose plugin and Docker Buildx.
Git is needed only if you obtain this checkout by cloning it; an unpacked
source archive works too.

The client and worker Dockerfiles compile Rust inside Ubuntu 24.04 builder
containers using `rust-toolchain.toml` (`nightly-2025-10-20`). They install the
native compiler, MPI and other build dependencies there. Java, Python and their
runtime dependencies are also installed inside the images. **You do not need
Rust, Cargo, MPI, Java or Python installed on the host for the default run.**
Internet access is needed for package/image downloads and Cargo Git dependencies.

Allow substantial RAM and disk space for the generated setup data, circuit,
Docker images and build cache. Setup and simultaneous loading by three workers
can be memory intensive. Ensure Docker has access to sufficient host resources.
The simulation uses `172.20.0.0/16`; it must not conflict with another Docker
network or host route. This configuration uses a local, rootful Docker daemon.

## Install and set up

Install Docker Engine, the Compose plugin and Buildx following the
[official Docker Ubuntu installation instructions](https://docs.docker.com/engine/install/ubuntu/).
Skip this if Docker is already installed. Rust, MPI, Java and ripgrep are
installed inside the images.

From the repository root, build the images and run setup explicitly:

```sh
sudo docker compose build server client coordinator
mkdir -p artifacts/circuits examples/rss_snark/inst_folder
sudo docker compose --profile tools run --rm --no-deps setup
```

Omit `sudo` if your user already has Docker access. The coordinator and all
workers share the `dfs-mpc:local` image built by the coordinator service.

Setup runs `docker/setup.sh` inside that image. It generates the circuit and
`input_layout_complete.txt` under `artifacts/circuits/`, and the proof setup data
under `examples/rss_snark/inst_folder/inst_13_0_1/`. All required simulation
configuration is handled automatically inside the containers.

Run setup once, and repeat it when the circuit or proof format changes. Stop any
running simulation before regenerating setup data. The launcher never builds
images or runs setup.

## Launch and debug

```sh
sudo bash docker_compose_launcher.sh run
```

Running the script without arguments also launches the simulation. Use `check`
to verify Docker access and Compose configuration, `logs` to inspect service
logs, and `down` to stop and remove the containers.

### What launch does

The launcher starts the TLS server, three workers and coordinator. The
coordinator and workers use the **same** `dfs-mpc:local` image. Client/server
traffic passes through the coordinator.

The launcher waits for the server, coordinator and worker listeners and the packet
capture file before starting the client; it does not open probe connections to
the single-use proof listeners. The client performs the TLS request, generates
session inputs using `JRPCInputGenerator`, and sends shares to the workers.
Setup circuit/layout mounts are read-only; session inputs are written separately
inside the client container under `/app/client-runtime/files/`.

The Nginx server acknowledges `POST /mcp` with a simulation JSON response; it
does not execute the requested command. Successful completion requires both the
client and coordinator to exit with status zero. The launcher saves service
logs and removes the simulation containers after a successful run. On failure
or interruption it leaves containers available for inspection:

```sh
sudo bash docker_compose_launcher.sh logs
sudo bash docker_compose_launcher.sh down
```

`down` preserves setup files, measurements and named Docker volumes.
Runtime transcripts, session inputs and captures inside containers are removed
with those containers. Save anything needed for debugging before `down`.

## Results and optional measurements

Each run writes client measurements under `measurments_client/`:

- `output_client1.json`: client output and timing.
- `memory_client1.json`: memory/CPU samples.
- `cputime_client1.txt`: sampled client CPU time.

Combined service logs are saved as `measurments/run_1.log`. The existing
`measurments` spelling is intentional. Run IDs start at 1 on each invocation;
copy results elsewhere before another invocation if you want to retain them.

For additional worker/coordinator CSV metrics, install the optional host Python
prerequisites and enable measurement:

```sh
sudo apt-get install -y python3 python3-venv
python3 -m venv .venv
.venv/bin/python -m pip install docker
sudo bash docker_compose_launcher.sh run --measure
```

`--measure` uses this prepared `.venv/` to run `measurment_docker_streaming.py`, producing
`metrics_<container>_<run>.csv`, and stops that helper after the run. The client
measurements above are collected even without this option.

To repeat runs or change time limits:

```sh
sudo env REPS=3 STARTUP_TIMEOUT=1800 RUN_TIMEOUT=7200 bash docker_compose_launcher.sh run
```

Startup timeout defaults to 30 minutes per readiness check; execution timeout
defaults to two hours per run. Setup/build duration is not limited by these
values. Increase the timeouts for slower machines when necessary.
Use `bash docker_compose_launcher.sh --help` for the command reference.

## Implementation notes

The setup and work phases have been tested successfully in the author's
container environment.

Keep the bundled `xjsnark_decompiled/` and `input_generator/` Java classes.
They run directly with the Java runtime installed in the images; rebuilding
them from Java source is not required. Cargo uses the Git parser
dependency from `Ottimot/XJSNARK_to_ARK` and the vendored `rustls-0.23.35/` and
`tokio-rustls/` source trees. Keep those directories and `Cargo.lock`.


## Attribution and license

Retain `LICENSE-MIT` and `LICENSE-APACHE` from the DFS artifact and the license
files in the vendored TLS libraries. Cite the original DFS paper and artifact
when using the underlying work. The laboratory's extensions and simulation
results must be described separately from the original paper's claims.
