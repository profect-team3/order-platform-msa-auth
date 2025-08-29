#!/bin/bash

set -e

docker build -t order-platform-msa-auth .

docker stop auth > /dev/null 2>&1 || true
docker rm auth > /dev/null 2>&1 || true

docker run --name auth \
    --network entity-repository_order-network \
    -p 8081:8081 \
    -e DB_URL=jdbc:postgresql://postgres:5432/order_platform \
    -e DB_USERNAME=bonun \
    -e DB_PASSWORD=password \
    -e OAUTH_JWKS_URI=http://host.docker.internal:8083/oauth/jwks \
    -e AUTH_INTERNAL_AUDIENCE=internal-services \
    -d order-platform-msa-auth


# Check container status
docker ps -f "name=auth"