#!/usr/bin/env bash
set -e

cmake -S . -B build -DCMAKE_C_COMPILER=gcc
cmake --build build --parallel 8
#sudo chown root:root ./bin/app
#sudo chmod u+s ./bin/app

echo "build success"
