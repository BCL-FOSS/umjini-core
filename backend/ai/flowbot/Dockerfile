FROM python:3.12-slim

# Install system dependencies and network tools
RUN apt-get update -y && \
    apt-get upgrade -y && \
    apt-get install -y \
    curl \
    nmap \
    tcpdump \
    traceroute \
    iperf3 \
    tshark \
    dnsutils \
    iputils-ping \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN adduser quart --disabled-password

WORKDIR /home/quart

# Copy requirements and install Python dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY *.py ./
COPY boot.sh ./
COPY utils/ ./utils/

# Create ChromaDB data directory
RUN mkdir -p chromadb_data && chown -R quart:quart chromadb_data

# Make boot script executable
RUN chmod +x boot.sh

# Switch to non-root user
USER quart

EXPOSE 8000

ENTRYPOINT ["sh", "./boot.sh"]