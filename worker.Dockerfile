# syntax=docker/dockerfile:1
# Place at docker/Dockerfile.mpc and build with the repository root as context.
# Reuse the rust-toolchain.toml and .dockerignore already used for the client.

FROM ubuntu:24.04 AS mpc-builder

ARG DEBIAN_FRONTEND=noninteractive

# Same native build environment as the client.
# MPI comes from Ubuntu packages, not the old custom OpenMPI 4.1.2 installation.
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

COPY rust-toolchain.toml ./
RUN channel="$(sed -nE 's/^[[:space:]]*channel[[:space:]]*=[[:space:]]*"([^"]+)".*/\1/p' rust-toolchain.toml)" \
 && test -n "$channel" \
 && rustup toolchain install "$channel" --profile minimal \
 && rustc --version --verbose

# Includes the local tokio-rustls and rustls-0.23.35 source directories.
# Host target/ directories are excluded by .dockerignore.
COPY . .
RUN RUSTFLAGS="-Awarnings" cargo build --locked --release --example rss_snark


FROM ubuntu:24.04 AS mpc-runtime

ARG DEBIAN_FRONTEND=noninteractive
ENV TZ=Europe/Rome \
    PYTHONUNBUFFERED=1

# Retain the tools used by the existing worker/coordinator runtime.
# Compiler headers (libopenmpi-dev) are only needed in the builder.
RUN apt-get update && apt-get install -y --no-install-recommends \
    netcat-openbsd \
    ripgrep \
    ca-certificates \
    tzdata \
    bash \
    openssh-server \
    openssh-client \
    iproute2 \
    python3 \
    python-is-python3 \
    python3-pip \
    python3-venv \
    tshark \
    git \
    openjdk-17-jre-headless \
    openmpi-bin \
    libopenmpi3t64 \
    libstdc++6 \
    libgomp1 \
 && rm -rf /var/lib/apt/lists/*

# Matches the original amd64 environment.
ENV JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64
ENV PATH="/opt/venv/bin:${JAVA_HOME}/bin:${PATH}"

RUN python3 -m venv /opt/venv \
 && /opt/venv/bin/python -m pip install --no-cache-dir pyshark flask

RUN mkdir -p /var/run/sshd /root/.ssh \
 && chmod 700 /root/.ssh

# Preserve the existing development SSH scheme.
# Build ONE image and use the same image for the coordinator and all workers,
# so they share the same development key pair. It is embedded in that image.
RUN ssh-keygen -t rsa -b 4096 -N "" -f /opt/dev_ssh_id_rsa \
 && cp /opt/dev_ssh_id_rsa.pub /opt/dev_authorized_keys

WORKDIR /app

COPY docker/worker-entrypoint.sh /usr/local/bin/worker-entrypoint.sh
COPY docker/coordinator-entrypoint.sh /usr/local/bin/coordinator-entrypoint.sh

# Original WORKDIR /app + destination app/... resolves to /app/app/....
# Keep those paths so existing entrypoints and MPI commands continue to match.
COPY xjsnark_decompiled/ /app/app/xjsnark_decompiled/
COPY input_generator/ /app/app/input_generator/
COPY --from=mpc-builder /build/target/release/examples/rss_snark /app/app/rss_snark
COPY merkle_tree/ /app/app/merkle_tree/
COPY docker/hostfile /app/app/hostfile
COPY capture.py /app/app/capture.py
COPY runprocess.py /app/app/runprocess.py

RUN chmod +x /usr/local/bin/worker-entrypoint.sh \
    /usr/local/bin/coordinator-entrypoint.sh \
    /app/app/rss_snark \
    /app/app/capture.py

# Check linked libraries without running the MPC protocol or contacting workers.
RUN ldd /app/app/rss_snark > /tmp/rss-snark-libraries.txt \
 && cat /tmp/rss-snark-libraries.txt \
 && ! grep -q 'not found' /tmp/rss-snark-libraries.txt \
 && rm /tmp/rss-snark-libraries.txt

# Compose overrides this for the coordinator.
# The original worker-ssh-entrypoint.sh was not one of the files being copied.
ENTRYPOINT ["/usr/local/bin/worker-entrypoint.sh"]