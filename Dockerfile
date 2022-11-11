# 64bit
FROM alpine

# 32bit
# FROM i386/alpine

# https://github.com/gliderlabs/docker-alpine/issues/24
RUN apk update && apk add alpine-sdk zsh && mkdir -p /mframbouandoronda

WORKDIR /mframbouandoronda
CMD ["zsh"]