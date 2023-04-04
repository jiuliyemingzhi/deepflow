FROM ghcr.io/deepflowio/rust-build:1.18 as builder

COPY ./agent/docker/rust-proxy-config  /usr/local/cargo/config


RUN source /opt/rh/devtoolset-8/enable \
&& yum -y install wget \
&& yum -y remove git* \
&& yum -y install epel-release \
&& yum -y install git \
&& yum -y install vim \
&& wget https://github.com/rust-lang/rust-analyzer/archive/refs/tags/2023-03-27.tar.gz \
&& tar -zvxf 2023-03-27.tar.gz \
&& cd rust-analyzer-* \
&& cargo xtask install --server 


WORKDIR /deepflow/agent