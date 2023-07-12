#!/bin/sh
docker build -t x .
docker run -it --rm x sh
