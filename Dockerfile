FROM openquantumsafe/liboqs-python:latest

WORKDIR /app

# Install Python dependencies
COPY requirements-docker.txt .
RUN pip install --no-cache-dir -r requirements-docker.txt

# Copy source
COPY . .

# Create data directory
RUN mkdir -p data

# Default: run the API on port 8000
# Override CMD for node-specific startup
ENV NODE_TRANSPORT=http
ENV NODE_ID=1
ENV NODE_PORT=8000

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${NODE_PORT}"]
