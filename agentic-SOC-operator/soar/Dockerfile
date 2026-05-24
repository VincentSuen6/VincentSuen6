FROM python:3.11-slim

WORKDIR /app

# iptables is needed for the active containment node.
# iproute2 provides `ip` for network diagnostics.
RUN apt-get update && apt-get install -y --no-install-recommends \
        iptables \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Install Python deps before copying source so Docker layer cache is reused
# on code-only changes (no dep changes = no pip re-install).
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000
