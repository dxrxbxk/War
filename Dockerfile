FROM debian:latest

# Install necessary packages
RUN apt-get update && apt-get install -y \
    git \
    vim \
    gcc \
    make \
    gdb \
    strace \
    curl \
    zsh \
    tmux \
    nasm \
    wget \
	procps \
    && apt-get clean

# Create working directory
RUN mkdir /root/famine
WORKDIR /root/famine

# Install Oh My Zsh
RUN sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" && \
    chsh -s $(which zsh) root

COPY . .

# Set Zsh as default shell
CMD ["zsh"]
