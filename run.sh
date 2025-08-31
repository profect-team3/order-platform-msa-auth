#!/bin/bash

set -e

docker build -t order-platform-msa-auth .

docker stop auth > /dev/null 2>&1 || true
docker rm auth > /dev/null 2>&1 || true

docker run --name auth \
    --network entity-repository_order-network \
    -p 8083:8083 \
    -e DB_URL=jdbc:postgresql://postgres:5432/order_platform \
    -e DB_USERNAME=bonun \
    -e DB_PASSWORD=password \
    -e OAUTH_JWKS_URI=http://host.docker.internal:8083/oauth/jwks \
    -e AUTH_INTERNAL_AUDIENCE=internal-services \
    -e AWS_REGION=ap-northeast-2 \
    -e KMS_JWT_KEY_ID=arn:aws:kms:ap-northeast-2:252098843029:key/c45bc708-8728-4926-b41f-79eedc115405 \
    -e JWT_ISSUER=https://auth.internal.example.com \
    -e REDIS_HOST=localhost \
    -e REDIS_PORT=6379 \
    -e REDIS_PASSWORD=password \
    -d order-platform-msa-auth


# Check container status
docker ps -f "name=auth"