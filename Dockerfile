# =============================================================================
# FlowGuard — optimized multi-stage Dockerfile
#
# builder: builds PcapPlusPlus and the C++ parser
# runtime: contains only runtime packages, Python deps, code and parser binary
# =============================================================================

FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libpcap-dev \
        pkg-config \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /tmp

RUN git clone --depth 1 https://github.com/seladb/PcapPlusPlus.git \
    && cmake -S PcapPlusPlus -B PcapPlusPlus/build \
        -DCMAKE_BUILD_TYPE=Release \
        -DPCAPPP_BUILD_TESTS=OFF \
        -DPCAPPP_BUILD_EXAMPLES=OFF \
        -DPCAPPP_BUILD_TUTORIALS=OFF \
    && cmake --build PcapPlusPlus/build -j"$(nproc)" \
    && cmake --install PcapPlusPlus/build \
    && ldconfig

WORKDIR /build

COPY cpp ./cpp

RUN cmake -S cpp/FlowParser -B cpp/FlowParser/build -DCMAKE_BUILD_TYPE=Release \
    && cmake --build cpp/FlowParser/build -j"$(nproc)"


FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH=/opt/venv/bin:$PATH \
    FLOWGUARD_CONFIG=/opt/flowguard/flowguard.yaml \
    STREAMLIT_SERVER_HEADLESS=true \
    STREAMLIT_BROWSER_GATHER_USAGE_STATS=false

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        python3-venv \
        libpcap0.8 \
        bash \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib /usr/local/lib
RUN ldconfig

RUN groupadd --system flowguard \
    && useradd --system --create-home --gid flowguard --shell /bin/bash flowguard

WORKDIR /opt/flowguard

COPY requirements.txt ./

RUN python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install --no-cache-dir -r requirements.txt \
    && /opt/venv/bin/pip check

COPY python ./python
COPY scripts ./scripts
COPY docs ./docs
COPY flowguard.yaml README.md ./

RUN mkdir -p cpp/FlowParser/build \
    && mkdir -p data/raw data/parsed data/interim data/retrain \
              models/active reports/latest reports/archive logs

COPY --from=builder /build/cpp/FlowParser/build/pcap_flow_parser \
    ./cpp/FlowParser/build/pcap_flow_parser

RUN chmod +x scripts/*.sh cpp/FlowParser/build/pcap_flow_parser \
    && chown -R flowguard:flowguard /opt/flowguard

USER flowguard

EXPOSE 8501

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8501/_stcore/health', timeout=3)" || exit 1

CMD ["streamlit", "run", "python/flowguard/ui/flowguard_ui.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true", \
     "--server.fileWatcherType=none"]
