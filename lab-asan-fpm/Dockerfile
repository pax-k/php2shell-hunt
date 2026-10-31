# CVE-2026-109619 reproduction lab: PHP-FPM 8.2.34 built from official source
# with ASAN/UBSan.
#
# Purpose: capture hard evidence (ASAN reports) of the FPM stale-global-state
# chain described by GHSA-6wmf-4rv5-p3rp:
#
#   Request A (application, post-startup):
#     session_start() decodes attacker-built session data;
#     a fatal mid-decode (advisory-listed producer, here max_execution_time
#     via __wakeup busy-loop) skips PHP_VAR_UNSERIALIZE_DESTROY();
#     BG(unserialize).data keeps pointing into the request heap; level != 0.
#     Normal request shutdown frees the heap; the FPM worker SURVIVES.
#
#   Request B (multipart, same worker):
#     PHPSESSID + PHP_SESSION_UPLOAD_PROGRESS + a file part -> FILE_START
#     -> php_session_initialize() decodes the attacker session BEFORE
#     Basic's RINIT resets BG(unserialize) -> php_var_unserialize_init()
#     reuses the dangling decoder state -> heap-use-after-free.
#
# ASAN visibility requires the tracked system allocator:
#   USE_ZEND_ALLOC=0  (every emalloc is a real malloc)
#   USE_TRACKED_ALLOC=1 (request shutdown tracked_free_all() frees leftovers)
# Note: with USE_ZEND_ALLOC=0 memory_limit is NOT enforced (custom heap sets
# limit to SIZE_MAX/2), so the OOM producer is unavailable here — the
# advisory lists "Maximum execution time exceeded" among the valid fatal
# producers, which is what this lab uses.
#
# Escalation to weaponized RCE (heap groom, negative used_slots) is out of
# scope; this lab captures the stale-state consumption evidence only.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config bison re2c \
        ca-certificates curl libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/php
RUN curl -fsSLo php.tar.gz https://www.php.net/distributions/php-8.2.34.tar.gz \
    && tar -xzf php.tar.gz --strip-components=1

# Research instrumentation: enable the upstream debug prints of the
# serialize_lock / BG(unserialize).level state in php_var_unserialize_
# init()/destroy() (var_unserializer.c) so the stale-state chain is
# observable per request in the FPM worker stderr (docker logs).
RUN sed -i \
    -e 's|/\* fprintf(stderr, "UNSERIALIZE_INIT    == lock: %u, level: %u\\n", BG(serialize_lock), BG(unserialize).level); \*/|fprintf(stderr, "[UAFDBG] INIT    lock=%u level=%u\\n", BG(serialize_lock), BG(unserialize).level);|' \
    -e 's|/\* fprintf(stderr, "UNSERIALIZE_DESTROY == lock: %u, level: %u\\n", BG(serialize_lock), BG(unserialize).level); \*/|fprintf(stderr, "[UAFDBG] DESTROY lock=%u level=%u\\n", BG(serialize_lock), BG(unserialize).level);|' \
    /usr/src/php/ext/standard/var_unserializer.c \
    && grep -c "UAFDBG" /usr/src/php/ext/standard/var_unserializer.c

RUN ./configure \
        --disable-all \
        --enable-session \
        --enable-filter \
        --enable-fpm \
        --enable-debug \
        --with-openssl \
        --without-pear \
        --disable-cgi \
        --enable-hash --enable-json \
        CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=address,undefined" \
    && make -j"$(nproc)" \
    && make install

# FPM pool: one static child so the producer and consumer requests are
# guaranteed to land on the same worker (the cross-request requirement).
RUN mkdir -p /tmp/sessions /usr/local/etc/php-fpm.d /var/www/html \
    && chmod 1777 /tmp/sessions \
    && cp /usr/local/etc/php-fpm.conf.default /usr/local/etc/php-fpm.conf \
    && sed -i -e 's|^;daemonize = yes|daemonize = no|' \
              -e 's|^include=.*|include=/usr/local/etc/php-fpm.d/*.conf|' \
              /usr/local/etc/php-fpm.conf \
    && printf '[global]\nerror_log = /proc/self/fd/2\n\n[www]\nuser = www-data\ngroup = www-data\nlisten = 9000\nclear_env = no\npm = static\npm.max_children = 1\ncatch_workers_output = yes\ndecorate_workers_output = yes\n; ASAN visibility: system allocator + tracked auto-free at request shutdown\nenv[USE_ZEND_ALLOC] = 0\nenv[USE_TRACKED_ALLOC] = 1\nphp_admin_value[session.save_handler] = files\nphp_admin_value[session.save_path] = /tmp/sessions\nphp_admin_value[session.use_strict_mode] = 0\nphp_admin_value[session.use_cookies] = 1\nphp_admin_value[session.use_only_cookies] = 0\nphp_admin_value[session.upload_progress.enabled] = On\nphp_admin_value[session.upload_progress.cleanup] = Off\nphp_admin_value[session.upload_progress.prefix] = upload_progress_\nphp_admin_value[session.upload_progress.name] = PHP_SESSION_UPLOAD_PROGRESS\nphp_admin_value[session.upload_progress.freq] = 1%%\nphp_admin_value[session.upload_progress.min_freq] = 0\n; NOTE: session.serialize_handler is deliberately NOT pinned here so the\n; per-dir .user.ini mismatch (webroot/app = php_serialize, webroot/api = php)\n; stays available for the producer decode path (PHP Bug #71101 lineage).\nphp_admin_value[display_errors] = stderr\nphp_admin_value[error_reporting] = E_ALL\nphp_admin_value[memory_limit] = 128M\nphp_admin_value[max_execution_time] = 3\nphp_admin_value[max_input_time] = 30\nphp_admin_value[post_max_size] = 8M\nphp_admin_value[upload_max_filesize] = 8M\n' > /usr/local/etc/php-fpm.d/zz-lab.conf

WORKDIR /var/www/html
ENV ASAN_OPTIONS="detect_leaks=0:halt_on_error=0"
EXPOSE 9000
CMD ["php-fpm"]
