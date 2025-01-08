FROM alpine:latest AS build

# Install build dependencies
RUN echo "@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
    && apk update && apk add --no-cache \
    g++ make libgcrypt-dev libb64-dev@testing

WORKDIR /usr/src/custom-cryptd

COPY . .

# Build the application
RUN make

FROM alpine:latest

# Install runtime dependencies
RUN echo "@testing https://dl-cdn.alpinelinux.org/alpine/edge/testing" >> /etc/apk/repositories \
    && apk update && apk add --no-cache \
    libgcrypt libb64@testing libstdc++ libgcc

COPY --from=build /usr/src/custom-cryptd/custom-cryptd /usr/local/bin/custom-cryptd
COPY entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/entrypoint.sh

# Expose the default server port
EXPOSE 10000

# Command to run the server
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]