#!/bin/bash

export DEBIAN_FRONTEND=noninteractive

apt-get update && \
    apt-get install -y git make autoconf automake libtool bison re2c pkg-config \
        libicu-dev
