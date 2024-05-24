#!/bin/bash

echo "Creating keys and server config"

docker build -t kvnnap/wg-create-py .devcontainer/
docker run --rm -it -v $PWD:/home/debian/wg-create-py -w /home/debian/wg-create-py kvnnap/wg-create-py:latest python3 ./gen.py

echo "Ready to deploy wireguard container inside wgsrv"

