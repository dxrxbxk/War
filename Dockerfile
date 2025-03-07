FROM debian:latest

# Install the necessary packages

RUN apt-get update && apt-get install -y \
	build-essential \
	git \
	vim \
	gcc \
	clang \
	make \
	gdb \
	strace \
	curl \
	zsh \
	tmux \
	&& apt-get clean 

RUN	mkdir /root/famine

#RUN (curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)
#
#RUN chsh -s $(which zsh)

WORKDIR /root/famine

# Copy the source code to the container

COPY . .

ENTRYPOINT ["/bin/bash"]
