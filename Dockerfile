# NightOwl official image — batteries included.
# Ships the CLI plus jadx/apktool (Java parsers) so `full`, `decompile`,
# static-audit and semgrep work out of the box. Dynamic analysis (adb/frida)
# expects a device attached at runtime: run with --privileged or pass through
# /dev/bus/usb, or point NIGHTOWL_ADB_HOST at an adb TCP endpoint.

FROM python:3.12-slim AS base

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_NO_CACHE_DIR=1 \
    NIGHTOWL_HOME=/data \
    PATH="/opt/tools/jadx/bin:/opt/tools:${PATH}"

RUN apt-get update && apt-get install -y --no-install-recommends \
        default-jre-headless ca-certificates wget unzip \
    && rm -rf /var/lib/apt/lists/*

# jadx 1.5.1 (>= pinned minimum 1.4.0)
RUN wget -q https://github.com/skylot/jadx/releases/download/v1.5.1/jadx-1.5.1.zip \
      -O /tmp/jadx.zip \
 && unzip -q /tmp/jadx.zip -d /opt/tools/jadx \
 && rm /tmp/jadx.zip

# apktool 2.9.3 wrapper + jar (>= pinned minimum 2.7.0)
RUN wget -q https://bitbucket.org/iBotPeaches/apktool/downloads/apktool_2.9.3.jar \
      -O /opt/tools/apktool.jar \
 && printf '#!/bin/sh\nexec java -jar /opt/tools/apktool.jar "$@"\n' \
      > /opt/tools/apktool && chmod +x /opt/tools/apktool

WORKDIR /app
COPY . .
RUN pip install ".[full]" && pip install pytest

# Runtime artifacts go to the mounted volume, never into the image layer.
VOLUME ["/data"]
ENTRYPOINT ["nightowl"]
CMD ["--help"]
