# WordPress lab on the rung-5b instrumented PHP build (CVE-2026-109618 /
# CVE-2026-109619). Same source-built PHP 8.2.34 + [UAFDBG] instrumentation
# as lab-zendmm-fpm, with the extensions WordPress needs added so a REAL
# WordPress install runs as the webroot app alongside the chain endpoints.
#
# Lab-bound escalation research only (see docs/ANALYSIS.md §0.6).
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config bison re2c \
        ca-certificates curl python3 \
        libxml2-dev libssl-dev zlib1g-dev libcurl4-openssl-dev \
        libonig-dev libzip-dev \
        libpng-dev libjpeg-dev libfreetype6-dev \
    && rm -rf /var/lib/apt/lists/*

ARG PHP_VERSION=8.2.34
WORKDIR /usr/src/php
RUN curl -fsSLo php.tar.gz \
        "https://www.php.net/distributions/php-${PHP_VERSION}.tar.gz" \
    && tar -xzf php.tar.gz --strip-components=1

COPY instrument.py .
RUN python3 instrument.py /usr/src/php

RUN ./configure \
        --disable-all \
        --enable-session \
        --enable-filter \
        --enable-fpm \
        --without-pear \
        --disable-cgi \
        --with-zlib \
        --with-openssl \
        --with-mysqli=mysqlnd \
        --enable-pdo \
        --with-pdo-mysql=mysqlnd \
        --enable-mbstring \
        --with-libxml --enable-dom --enable-xml --enable-simplexml \
        --enable-xmlwriter --enable-xmlreader \
        --with-curl \
        --enable-gd --with-jpeg --with-freetype \
        --with-zip \
        CFLAGS="-g -O2" \
    && make -j"$(nproc)" \
    && make install

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        libxml2 libssl3 zlib1g libcurl4 libpng16-16 libjpeg62-turbo \
        libfreetype6 libzip4 libonig5 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /usr/local /usr/local
RUN mkdir -p /tmp/sessions /usr/local/etc/php-fpm.d /var/www/html \
    && chmod 1777 /tmp/sessions \
    && cp /usr/local/etc/php-fpm.conf.default /usr/local/etc/php-fpm.conf \
    && sed -i -e 's|^;daemonize = yes|daemonize = no|' \
              -e 's|^include=.*|include=/usr/local/etc/php-fpm.d/*.conf|' \
              /usr/local/etc/php-fpm.conf \
    && printf '[global]\nerror_log = /proc/self/fd/2\n\n[www]\nuser = www-data\ngroup = www-data\nlisten = 9000\nclear_env = no\npm = static\npm.max_children = 1\ncatch_workers_output = yes\ndecorate_workers_output = yes\nphp_admin_value[session.save_handler] = files\nphp_admin_value[session.save_path] = /tmp/sessions\nphp_admin_value[session.use_strict_mode] = 0\nphp_admin_value[session.use_cookies] = 1\nphp_admin_value[session.use_only_cookies] = 0\nphp_admin_value[session.upload_progress.enabled] = On\nphp_admin_value[session.upload_progress.cleanup] = Off\nphp_admin_value[session.upload_progress.prefix] = upload_progress_\nphp_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS\nphp_admin_value[session.upload_progress.freq] = 1%%\nphp_admin_value[session.upload_progress.min_freq] = 0\nphp_admin_value[display_errors] = stderr\nphp_admin_value[error_reporting] = E_ALL\nphp_admin_value[memory_limit] = 128M\nphp_admin_value[max_execution_time] = 30\nphp_admin_value[max_input_time] = 30\nphp_admin_value[post_max_size] = 8M\nphp_admin_value[upload_max_filesize] = 8M\n' > /usr/local/etc/php-fpm.d/zz-lab.conf

WORKDIR /var/www/html
EXPOSE 9000
CMD ["php-fpm"]
