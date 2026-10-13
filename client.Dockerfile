# syntax=docker/dockerfile:1

# Build from the repository root, not from the docker/ directory.
FROM ubuntu:24.04 AS client-builder

ARG DEBIAN_FRONTEND=noninteractive

# MPI currently uses Ubuntu's packages. This is NOT an exact reproduction
# of the host's custom OpenMPI 4.1.2 installation.
# cmake/libtool are included to support native-dependency build paths;
# this is a practical starting environment, not a proven minimal package list.
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    clang-14 \
    libclang-14-dev \
    pkg-config \
    libopenmpi-dev \
    openmpi-bin \
    autoconf \
    automake \
    libtool \
    cmake \
    git \
    curl \
    ca-certificates \
 && rm -rf /var/lib/apt/lists/*

ENV PATH="/root/.cargo/bin:${PATH}" \
    CC=clang-14 \
    CXX=clang++-14 \
    LIBCLANG_PATH=/usr/lib/llvm-14/lib \
    MPICC=/usr/bin/mpicc \
    MPICXX=/usr/bin/mpicxx \
    CARGO_NET_GIT_FETCH_WITH_CLI=true

RUN curl --proto '=https' --tlsv1.2 -fsS \
      https://sh.rustup.rs -o /tmp/rustup-init.sh \
 && sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain none \
 && rm /tmp/rustup-init.sh

WORKDIR /build

# Generated once by docker/pin-rust-toolchain.sh and then committed to Git.
COPY rust-toolchain.toml ./
RUN channel="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml)" \
 && test -n "$channel" \
 && rustup toolchain install "$channel" --profile minimal \
 && rustc --version --verbose

# Preserves local path dependencies, including tokio-rustls and rustls-0.23.35.
# .dockerignore excludes binaries and virtualenvs from the host.
COPY . .
RUN RUSTFLAGS="-Awarnings" cargo build --locked --release --bin client


FROM ubuntu:24.04 AS client-runtime

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome \
    PYTHONUNBUFFERED=1

# Keep native runtime libraries initially; refine after checking the actual binary.
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-venv \
    python3-pip \
    openjdk-17-jre-headless \
    ca-certificates \
    iproute2 \
    tzdata \
    bash \
    libopenmpi3t64 \
    libstdc++6 \
    libgomp1 \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN python3 -m venv /app/.venv \
 && /app/.venv/bin/python -m pip install --no-cache-dir psutil

# Preserve the account present in the original client image.
# The entrypoint still runs as root to configure its network route.
RUN useradd -m -s /bin/bash mpi \
 && mkdir -p /home/mpi/.ssh /app/files /app/measurments \
 && chown -R mpi:mpi /home/mpi/.ssh

COPY --from=client-builder /build/target/release/client /app/client
COPY xjsnark_decompiled/ /app/xjsnark_decompiled/
COPY input_generator/ /app/input_generator/
COPY merkle_tree/ /app/merkle_tree/
COPY trackers.py /app/trackers.py
COPY docker/client-entrypoint.sh /usr/local/bin/client-entrypoint.sh

RUN chmod +x /app/client /app/trackers.py /usr/local/bin/client-entrypoint.sh

# Check linked shared libraries without starting the client or contacting servers.
# dlopen libraries and external commands still require a real runtime test.
RUN ldd /app/client > /tmp/client-libraries.txt \
 && cat /tmp/client-libraries.txt \
 && ! grep -q 'not found' /tmp/client-libraries.txt \
 && rm /tmp/client-libraries.txt

ENTRYPOINT ["/usr/local/bin/client-entrypoint.sh"]