FROM python:3.12

# Install system dependencies
RUN apt update && \
    apt install -y \
    redis-server \
    supervisor \
    wget 

# Install Chrome
RUN apt-get install -y wget gnupg \ 
    && wget -q -O - https://dl-ssl.google.com/linux/linux_signing_key.pub | apt-key add - \
    && sh -c 'echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" >> /etc/apt/sources.list.d/google.list' \
    && apt-get update \
    && apt-get install -y google-chrome-stable

# Install Go 
RUN wget https://go.dev/dl/go1.23.0.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.23.0.linux-amd64.tar.gz && \
    rm go1.23.0.linux-amd64.tar.gz && \
    ln -s /usr/local/go/bin/go /usr/bin/go && \
    ln -s /usr/local/go/bin/gofmt /usr/bin/gofmt

# Create directory structure
RUN mkdir -p /app /cdn-service /var/lib/redis /var/log/supervisor 

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Copy Python web app
COPY web-app/ /app/
# Install Python dependencies
RUN pip install --no-cache-dir -r /app/requirements.txt 

# Install Go dependencies and build CDN service
COPY cdn-service/main.go cdn-service/go.mod /cdn-service/
RUN cd /cdn-service && \
    go mod tidy && \
    go build -o cdn-service main.go

# Copy Redis configuration and init script
COPY redis/redis.conf redis/redis_init.sh /etc/redis/
RUN chmod +x /etc/redis/redis_init.sh

# Copy Supervisor configuration
COPY supervisord.conf /etc/supervisor/supervisord.conf

# Expose ports
EXPOSE 1337

# Set admin password
RUN export ADMIN_PASS=$(python3 -c "import secrets; print(secrets.token_hex(16))") && \
    sed -i "s/PLACEHOLDER/$ADMIN_PASS/" /app/config.py

# Copy flag
COPY flag.txt /flag.txt

# Start services
CMD ["/usr/bin/supervisord", "-c", "/etc/supervisor/supervisord.conf"]