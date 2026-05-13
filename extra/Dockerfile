# This Dockerfile creates an image suitable to run LibAFL Fuzzer for
# Xen CI tests. It pulls Ubuntu plus all the required packages.

FROM ubuntu AS fuzzer-builder
LABEL "maintainer"="Volodymyr Babchuk <volodymyr_babchuk@epam.com>"


ENV DEBIAN_FRONTEND=noninteractive
RUN apt update \
 && apt upgrade -y \
 && apt install -y \
  gcc-aarch64-linux-gnu \
  binutils \
  bison \
  build-essential \
  clang \
  flex \
  gawk \
  gcc \
  git \
  help2man \
  libglib2.0-dev \
  libncurses5-dev \
  libtool \
  libtool-bin \
  llvm \
  meson \
  ninja-build \
  python3-dev \
  python3-setuptools \
  python3-venv \
  texinfo \
  unzip \
  wget


RUN useradd -ms /bin/bash nonroot
USER nonroot
WORKDIR /home/nonroot

ENV PATH=$PATH:/home/nonroot/.cargo/bin:/home/nonroot/.local/bin
RUN wget -qO- https://sh.rustup.rs | sh -s -- -y -q --no-modify-path && rustup default stable

RUN git clone --depth=1 https://github.com/xen-troops/xen-fuzzer-rs.git && \
	cd xen-fuzzer-rs && cargo build --release && cargo install cargo-make && cargo make build_xtf


FROM ubuntu
LABEL "maintainer"="Volodymyr Babchuk <volodymyr_babchuk@epam.com>"

WORKDIR /root

ENV DEBIAN_FRONTEND=noninteractive
RUN apt update \
 && apt upgrade -y \
 && apt install -y \
  libglib2.0-0

COPY --from=fuzzer-builder /home/nonroot/xen-fuzzer-rs/target/xtf/tests/arm-hypercall-fuzzer/test-mmu64le-arm-hypercall-fuzzer /root

COPY --from=fuzzer-builder /home/nonroot/xen-fuzzer-rs/target/xtf/tests/arm-vgic-fuzzer/test-mmu64le-arm-vgic-fuzzer /root

COPY --from=fuzzer-builder /home/nonroot/xen-fuzzer-rs/target/release/xen_fuzzer /root

COPY --from=fuzzer-builder /home/nonroot/xen-fuzzer-rs/corpus /root/corpus

COPY --from=fuzzer-builder /home/nonroot/xen-fuzzer-rs/target/release/qemu-libafl-bridge/pc-bios/efi-virtio.rom /root
