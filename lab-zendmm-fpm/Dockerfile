# Rung-1 weaponization-research lab: PHP 8.2.34 FPM built from the official
# source with the PRODUCTION allocator shape (plain ZendMM — no ASAN, no
# --enable-debug) plus the [UAFDBG] instrumentation patch (instrument.py).
#
# Parameterized (PHP_VERSION build arg) for the rung-5b FIXED-VERSION
# NEGATIVE CONTROL: the same lab built from patched sources (8.2.35)
# demonstrates the official patch blocks the weaponization chain —
# see lab-zendmm-fpm-8235/ and ANALYSIS §0.9.2.
#
# Purpose: after the CVE-2026-109619 producer request frees the decoder
# bookkeeping (an 8216-byte "large" ZendMM allocation), freed pages return
# to the chunk free-map and ARE reusable by later requests — unlike the
# ASAN quarantine in lab-asan-fpm. This lab lets us observe:
#   - the exact address of the dangling php_unserialize_data (INIT print),
#   - which consumer-request allocation reclaims it (SESS print vs WRAP print),
#   - what the stale bookkeeping resolves to after the reclaim (WRAP/RREF).
#
# Single static FPM child => the producer and consumer requests are
# deterministic (same worker, same chunk reuse pattern).
#
# Lab-bound escalation research only (see docs/ANALYSIS.md §0.6).
FROM debian:bookworm-slim AS build

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config bison re2c \
        ca-certificates curl python3 \
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
        --enable-hash --enable-json \
        CFLAGS="-g -O2" \
    && make -j"$(nproc)" \
    && make install

# ---- runtime ----
FROM debian:bookworm-slim
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
