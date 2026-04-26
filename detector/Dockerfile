FROM python:3.11-slim

# Install system dependencies for iptables and psutil
RUN apt-get update && apt-get install -y \
    iptables \
    procps \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the code
COPY . .

# Expose the Dashboard port
EXPOSE 5000

# Run main.py
CMD ["python", "-u", "main.py"]
