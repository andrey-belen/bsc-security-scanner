FROM node:20-slim

# Install Python and curl (for healthcheck)
RUN apt-get update && apt-get install -y python3 python3-pip python3-venv curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy package files
COPY package*.json ./
COPY frontend/package*.json ./frontend/

# Install Node dependencies
RUN npm ci

# Install frontend dependencies and build
COPY frontend ./frontend
RUN cd frontend && npm ci && npm run build && \
    mkdir -p ../public && cp -r dist/* ../public/

# Install Python dependencies
COPY requirements.txt ./
RUN pip3 install --break-system-packages -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 3001

# Set environment
ENV NODE_ENV=production
ENV PORT=3001

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:3001/health || exit 1

CMD ["npm", "start"]
