# PHP 8.2.34 built from official source tarball with ASAN, for running
# poc/verify_uaf_asan.php (var_destroy reentry UAF crash reproduction).
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config \
        ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/php
RUN curl -fsSLo php.tar.gz https://www.php.net/distributions/php-8.2.34.tar.gz \
    && tar -xzf php.tar.gz --strip-components=1

# ASAN build: debug + UBSan, allocator disabled at runtime via USE_ZEND_ALLOC=0
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

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates libasan8 libubsan1 \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local /usr/local
ENV USE_ZEND_ALLOC=0 \
    ASAN_OPTIONS="detect_leaks=0,detect_stack_use_after_return=1"
WORKDIR /work
CMD ["php", "-v"]