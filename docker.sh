#!/bin/bash

IMAGE_NAME="debian_test"
CONTAINER_NAME="famine"

docker build -t "$IMAGE_NAME" .
docker run --rm -it --name "$CONTAINER_NAME" "$IMAGE_NAME"

