#!/usr/bin/env bash

sudo -E valgrind \
    --tool=memcheck \
    --leak-check=full \
    --show-leak-kinds=all \
    ./bin/app -e eth3 -w ./output/catch.pcap

