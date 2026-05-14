# =============================================================================
# FlowGuard — Dockerfile (multi-stage build)
#
# Этап 1: builder — собирает PcapPlusPlus и C++ парсер
# Этап 2: runtime — финальный лёгкий образ
# =============================================================================

# -----------------------------------------------------------------------------
# Этап 1: сборка
# -----------------------------------------------------------------------------
FROM ubuntu:24.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        cmake \
        git \
        libpcap-dev \
        pkg-config \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# --- PcapPlusPlus ---
WORKDIR /tmp
RUN git clone --depth 1 https://github.com/seladb/PcapPlusPlus.git && \
    cd PcapPlusPlus && \
    cmake -S . -B build -DCMAKE_BUILD_TYPE=Release && \
    cmake --build build -j"$(nproc)" && \
    cmake --install build && \
    ldconfig

# --- сборка парсера FlowGuard ---
WORKDIR /build
COPY cpp ./cpp
RUN cd cpp/FlowParser && \
    mkdir -p build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release .. && \
    make -j"$(nproc)"

# -----------------------------------------------------------------------------
# Этап 2: рантайм
# -----------------------------------------------------------------------------
FROM ubuntu:24.04 AS runtime

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_BREAK_SYSTEM_PACKAGES=1

# --- рантайм-зависимости (минимум) ---
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        libpcap0.8 \
        curl \
        bash \
        ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# --- копируем PcapPlusPlus из builder ---
COPY --from=builder /usr/local/lib /usr/local/lib
COPY --from=builder /usr/local/include /usr/local/include
RUN ldconfig

WORKDIR /opt/flowguard

# --- сначала зависимости (для слоя кеша) ---
COPY requirements.txt ./
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# --- копируем код ---
COPY python ./python
COPY scripts ./scripts
COPY flowguard.yaml ./
COPY README.md ./

# --- копируем собранный бинарь парсера ---
COPY --from=builder /build/cpp ./cpp

# --- права на исполнение ---
RUN chmod +x scripts/*.sh && \
    mkdir -p data/raw data/parsed data/interim data/retrain \
             models/active reports/latest reports/archive logs

# --- проверка работоспособности ---
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health 2>/dev/null || exit 1

EXPOSE 8501

# --- по умолчанию запускается веб-интерфейс ---
CMD ["streamlit", "run", "python/flowguard/ui/flowguard_ui.py", \
     "--server.address=0.0.0.0", \
     "--server.port=8501", \
     "--server.headless=true"]
