FROM python:3.11-slim
# Install system dependencies for psutil and iptables
RUN apt-get update && apt-get install -y iptables gcc python3-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy EVERYTHING else (config.yaml, templates/, etc.)
COPY . . 
CMD ["python", "main.py"]
