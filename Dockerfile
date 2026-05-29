FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System deps
RUN apt-get update && apt-get install -y \
    python3 python3-pip \
    clang \
    curl git \
    && rm -rf /var/lib/apt/lists/*

# Install Ollama
RUN curl -fsSL https://ollama.com/install.sh | sh

WORKDIR /kerrigan

# Python deps
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Pull base model and create kerrigan-fantasma
RUN ollama serve & sleep 5 && \
    ollama pull deepseek-coder:6.7b && \
    ollama create kerrigan-fantasma -f config/Modelfile

EXPOSE 11434

CMD ["python3", "kerrigan.py"]
