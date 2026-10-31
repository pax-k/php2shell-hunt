# PHP 8.2.35 (patched) built from official source tarball.
# Minimal build: FPM + session, enough to retest the research chains.
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config \
        ca-certificates curl libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/php
RUN curl -fsSLo php.tar.gz https://www.php.net/distributions/php-8.2.35.tar.gz \
    && tar -xzf php.tar.gz --strip-components=1

RUN ./configure \
        --disable-all \
        --enable-session \
        --enable-filter \
        --enable-fpm \
        --with-openssl \
        --without-pear \
        --enable-hash --enable-json \
    && make -j"$(nproc)" \
    && make install

# ---- runtime ----
FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*
# debian:bookworm-slim already ships www-data (uid 33)
COPY --from=build /usr/local /usr/local
RUN mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions \
    && mkdir -p /var/www/html \
    && mkdir -p /usr/local/etc/php-fpm.d \
    && cp /usr/local/etc/php-fpm.conf.default /usr/local/etc/php-fpm.conf \
    && sed -i -e 's|^;daemonize = yes|daemonize = no|' -e 's|^include=.*|include=/usr/local/etc/php-fpm.d/*.conf|' /usr/local/etc/php-fpm.conf \
    && printf '[global]\nerror_log = /proc/self/fd/2\n\n[www]\nuser = www-data\ngroup = www-data\nlisten = 9000\nclear_env = no\npm = dynamic\npm.max_children = 5\npm.start_servers = 2\npm.min_spare_servers = 1\npm.max_spare_servers = 3\nphp_admin_value[session.save_path] = /tmp/sessions\nphp_admin_value[session.upload_progress.enabled] = On\nphp_admin_value[session.upload_progress.cleanup] = Off\nphp_admin_value[session.use_strict_mode] = 0\nphp_admin_value[session.use_cookies] = 1\nphp_admin_value[session.use_only_cookies] = 0\nphp_admin_value[display_errors] = On\nphp_admin_value[error_reporting] = E_ALL\n' > /usr/local/etc/php-fpm.d/zz-lab.conf
WORKDIR /var/www/html
EXPOSE 9000
CMD ["php-fpm"]