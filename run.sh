#!/bin/sh
docker build -t x .
docker run -it --rm -p 8080:8080 x sh
