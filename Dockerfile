FROM python:3.12-slim AS liboqs-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    git cmake build-essential libssl-dev ninja-build \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 https://github.com/open-quantum-safe/liboqs.git /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build \
        -DBUILD_SHARED_LIBS=ON \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX=/usr/local \
    && cmake --build /tmp/liboqs/build -j$(nproc) \
    && cmake --install /tmp/liboqs/build \
    && rm -rf /tmp/liboqs

FROM python:3.12-slim

COPY --from=liboqs-builder /usr/local/lib/liboqs.so* /usr/local/lib/
COPY --from=liboqs-builder /usr/local/include/oqs /usr/local/include/oqs
RUN ldconfig

WORKDIR /app

COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

COPY . .
RUN mkdir -p data

ENV NODE_TRANSPORT=http
ENV NODE_ID=1
ENV NODE_PORT=8000

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${NODE_PORT}"]
