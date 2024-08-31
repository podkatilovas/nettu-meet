FROM node:19.0.0-buster

# Update repository information and upgrade to a newer Debian release
#RUN sed -i 's/stretch/buster/g' /etc/apt/sources.list && \
#    apt-get update && \
#    apt-get upgrade -y

# Install DEB dependencies and others.
#RUN apt-get install -y net-tools build-essential valgrind

# Install DEB dependencies and others.
RUN \
    set -x \
    && apt-get update \
    && apt-get install -y net-tools build-essential valgrind python3-pip

WORKDIR /app

COPY package.json .
COPY tsconfig.json .
COPY src src
RUN npm install
