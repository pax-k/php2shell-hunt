# Parameterized ASAN build — var_destroy re-entry UAF patch-gap verification.
# Builds a given PHP version with ASAN+UBSan (native arch, no emulation) to
# check whether the var_destroy __destruct reentry UAF survives the patch.
#
#   docker build --build-arg PHP_VERSION=8.5.12 -t php-asan-8512:local .
#   docker run --rm -v "$PWD/../poc:/work/poc" php-asan-8512:local \
#       php /work/poc/verify_uaf_asan.php
ARG PHP_VERSION=8.5.12

FROM debian:bookworm-slim AS build
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /usr/src/php
ARG PHP_VERSION
RUN curl -fsSLo php.tar.gz https://www.php.net/distributions/php-${PHP_VERSION}.tar.gz \
    && tar -xzf php.tar.gz --strip-components=1
RUN ./configure \
        --disable-all \
        --enable-session \
        --enable-filter \
        --enable-debug \
        --disable-phpdbg \
        CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=address,undefined" \
    && make -j"$(nproc)" \
    && make install

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libasan8 libubsan1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local /usr/local
ENV USE_ZEND_ALLOC=0 \
    ASAN_OPTIONS="detect_leaks=0,detect_stack_use_after_return=1"
WORKDIR /work
CMD ["php", "-v"]