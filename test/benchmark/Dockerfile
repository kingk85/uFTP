# Image of one of the servers uFTP is compared with (they conflict with each other, one image each).
# The versions are the ones of Ubuntu 24.04:   docker build --build-arg PKG="vsftpd" -t uftp-bench-vsftpd .
FROM ubuntu:24.04
ARG PKG
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends $PKG openssl libssl3t64 libpam-modules ca-certificates \
    && rm -rf /var/lib/apt/lists/*
