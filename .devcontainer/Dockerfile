# Development container for PQC Migration Audit
FROM python:3.11-bullseye

# Install system dependencies
RUN apt-get update && apt-get install -y \
    # Development tools
    git \
    curl \
    wget \
    vim \
    nano \
    jq \
    tree \
    htop \
    # Build tools
    build-essential \
    gcc \
    g++ \
    make \
    # Security tools
    gnupg \
    ca-certificates \
    # Shell and terminal
    zsh \
    tmux \
    # Database clients
    postgresql-client \
    sqlite3 \
    # Network tools
    netcat \
    telnet \
    # Clean up
    && rm -rf /var/lib/apt/lists/*

# Install development Python packages globally
RUN pip install --no-cache-dir \
    # Development tools
    ipython \
    jupyter \
    # Debugging
    pdb++ \
    ipdb \
    # Performance analysis
    line-profiler \
    memory-profiler \
    # Security tools
    bandit \
    safety \
    # Container tools
    docker-compose

# Create development user
RUN groupadd -g 1000 pqcdev \
    && useradd -u 1000 -g pqcdev -s /bin/zsh -m pqcdev \
    && usermod -aG sudo pqcdev \
    && echo "pqcdev ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Install Oh My Zsh for better developer experience
USER pqcdev
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" "" --unattended \
    && git clone https://github.com/zsh-users/zsh-autosuggestions ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-autosuggestions \
    && git clone https://github.com/zsh-users/zsh-syntax-highlighting.git ${ZSH_CUSTOM:-~/.oh-my-zsh/custom}/plugins/zsh-syntax-highlighting

# Configure zsh
RUN echo 'plugins=(git python docker zsh-autosuggestions zsh-syntax-highlighting)' >> ~/.zshrc \
    && echo 'export PYTHONPATH="/workspace/src:$PYTHONPATH"' >> ~/.zshrc \
    && echo 'alias ll="ls -la"' >> ~/.zshrc \
    && echo 'alias pqc-audit="python -m pqc_migration_audit.cli"' >> ~/.zshrc

# Switch back to root for final setup
USER root

# Set up workspace
WORKDIR /workspace

# Install pre-commit hooks system
RUN pip install pre-commit

# Create directories for development
RUN mkdir -p /workspace/.vscode \
    && mkdir -p /workspace/reports \
    && mkdir -p /workspace/logs \
    && chown -R pqcdev:pqcdev /workspace

# Switch to development user
USER pqcdev

# Set default shell
SHELL ["/bin/zsh", "-c"]

# Default command
CMD ["/bin/zsh"]