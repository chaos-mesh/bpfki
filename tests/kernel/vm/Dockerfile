# syntax=docker/dockerfile:1
FROM ubuntu:24.04
RUN --mount=type=cache,id=chaos-mesh-ubuntu24.04-apt-amd64,target=/var/cache/apt,sharing=locked \
    rm -f /etc/apt/apt.conf.d/docker-clean && apt-get update && \
    apt-get install --no-install-recommends -y \
      build-essential cmake pkg-config python3 libbpfcc-dev llvm-dev \
      libgrpc++-dev protobuf-compiler-grpc libprotobuf-dev protobuf-compiler \
      libabsl-dev libspdlog-dev libgflags-dev sudo iproute2 kmod util-linux busybox-static && \
    rm -rf /var/lib/apt/lists/*
RUN useradd --uid 1001 --create-home runner && \
    printf 'runner ALL=(ALL) NOPASSWD: ALL\n' > /etc/sudoers.d/runner && \
    chmod 440 /etc/sudoers.d/runner && \
    mkdir -p /home/runner/work/_temp /kernel-headers /boot && \
    chown -R runner:runner /home/runner/work
COPY candidate /opt/bpfki
COPY source-control /opt/source-control
COPY provenance.json /home/runner/work/_temp/bpfki-source-control.json
RUN cmake -S /opt/source-control -B /tmp/control-build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build /tmp/control-build --parallel 2 && \
    cmake --install /tmp/control-build --prefix /opt/control && \
    cmake -S /opt/bpfki -B /tmp/candidate-build -DCMAKE_BUILD_TYPE=Release -DBPFKI_BUILD_KERNEL_TESTS=ON && \
    cmake --build /tmp/candidate-build --parallel 2 && \
    cmake --install /tmp/candidate-build --prefix /opt/candidate && \
    cp /tmp/candidate-build/kernel-tests /opt/kernel-tests && \
    rm -rf /tmp/control-build /tmp/candidate-build /opt/source-control
RUN chmod 755 /opt/bpfki/tests/kernel/vm/init.sh
ENTRYPOINT ["/opt/bpfki/tests/kernel/vm/init.sh"]
