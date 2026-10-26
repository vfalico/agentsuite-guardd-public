ARG BASE_IMAGE=debian:bookworm-slim
FROM ${BASE_IMAGE} AS build
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ARG TARGETARCH
ARG CRICTL_SHA256
ARG SOURCE_DATE_EPOCH=0
ENV SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH} PYTHONDONTWRITEBYTECODE=1

RUN test "$TARGETARCH" = amd64 && \
    apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates clang libbpf-dev python3-venv && \
    rm -rf /var/lib/apt/lists/*

COPY --from=guardd_inputs /vmlinux.h /inputs/vmlinux.h
COPY --from=guardd_inputs /crictl /inputs/crictl
COPY LICENSE NOTICE THIRD_PARTY_NOTICES.md README.md MANIFEST.in pyproject.toml /source/
COPY _backend /source/_backend
COPY src /source/src
COPY gadget /source/gadget
COPY packaging/kubernetes /source/packaging/kubernetes
WORKDIR /build

RUN test "${#CRICTL_SHA256}" -eq 64 && \
    [[ "$CRICTL_SHA256" != *[!a-f0-9]* ]] && \
    printf '%s  /inputs/crictl\n' "$CRICTL_SHA256" | sha256sum --check --strict - && \
    mkdir records wheels && \
    find /source -type f -print0 | LC_ALL=C sort -z | \
      xargs -0 sha256sum > records/source-files.sha256 && \
    sha256sum records/source-files.sha256 /inputs/vmlinux.h /inputs/crictl \
      > records/inputs.sha256 && \
    printf '%s\n' "$SOURCE_DATE_EPOCH" > records/source-date-epoch && \
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
      -ffile-prefix-map=/source=. -ffile-prefix-map=/inputs=. \
      -I/inputs -c /source/gadget/program.bpf.c -o filesystem.bpf.o && \
    clang -g -O2 -target bpf -D__TARGET_ARCH_x86 \
      -ffile-prefix-map=/source=. -ffile-prefix-map=/inputs=. \
      -I/inputs -c /source/gadget/container.bpf.c -o container.bpf.o && \
    sha256sum filesystem.bpf.o container.bpf.o > records/filesystem-object.sha256 && \
    dpkg-query -W > records/debian-build-packages.txt && \
    python3 -m venv /build/venv && \
    /build/venv/bin/pip install --no-cache-dir 'setuptools>=77' wheel && \
    /build/venv/bin/pip wheel --no-cache-dir --no-build-isolation \
      --wheel-dir /build/wheels /source && \
    /build/venv/bin/pip freeze --all > records/python-build-packages.txt

FROM ${BASE_IMAGE}
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
ARG BASE_IMAGE
ARG SOURCE_DATE_EPOCH=0
LABEL org.opencontainers.image.title="Guardd Kubernetes enforcement provider" \
      org.opencontainers.image.base.name="${BASE_IMAGE}"
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

RUN apt-get update && apt-get install -y --no-install-recommends \
      bpftool ca-certificates libbpf1 python3-venv util-linux && \
    rm -rf /var/lib/apt/lists/* && \
    python3 -m venv /opt/guardd/venv
COPY --from=build /build/wheels /tmp/guardd-wheels
RUN /opt/guardd/venv/bin/pip install --no-cache-dir --no-index \
      --find-links /tmp/guardd-wheels agentsuite-guardd && \
    rm -rf /tmp/guardd-wheels
COPY --from=build /build/filesystem.bpf.o /opt/guardd/filesystem.bpf.o
COPY --from=build /build/container.bpf.o /opt/guardd/container.bpf.o
COPY --from=build --chmod=0755 /inputs/crictl /usr/local/bin/crictl
COPY --from=build /build/records /usr/local/share/guardd/build
RUN /usr/local/bin/crictl --version > /usr/local/share/guardd/build/crictl-version.txt && \
    dpkg-query -W > /usr/local/share/guardd/build/debian-runtime-packages.txt && \
    /opt/guardd/venv/bin/pip freeze --all > /usr/local/share/guardd/build/python-runtime-packages.txt
ENTRYPOINT ["/opt/guardd/venv/bin/agentsuite-guardd"]
CMD ["--config", "/etc/guardd/provider.json", "serve-kubernetes-enforcement"]
