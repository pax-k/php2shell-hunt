# CVE-2026-109618/109619 reproduction lab: Apache prefork + mod_php,
# PHP 8.2.34 built from official source with ASAN/UBSan.
#
# Reproduces the ADVISORY-CONFIRMED CONDITIONS of the two CVEs (OOM-during-
# startup shutdown processing; stale global state consumed by a later
# request on the same worker) and captures ASAN evidence.
# Corruption-to-RCE escalation is out of scope.
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential autoconf pkg-config bison re2c \
        ca-certificates curl apache2 apache2-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /usr/src/php
RUN curl -fsSLo php.tar.gz https://www.php.net/distributions/php-8.2.34.tar.gz \
    && tar -xzf php.tar.gz --strip-components=1

# mod_php via apxs (prefork). Sanitizers on.
RUN ./configure \
        --disable-all \
        --enable-session \
        --enable-filter \
        --enable-debug \
        --with-apxs2=/usr/bin/apxs \
        --with-openssl \
        --without-pear \
        --disable-cgi \
        CFLAGS="-g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer" \
        LDFLAGS="-fsanitize=address,undefined" \
    && make -j"$(nproc)" \
    && make install

RUN a2enmod mpm_prefork \
    ; a2dismod mpm_event \
    ; a2dismod mpm_worker 2>/dev/null \
    ; echo "LoadModule php_module /usr/lib/apache2/modules/libphp.so" > /etc/apache2/mods-available/php.load \
    ; ln -sf ../mods-available/php.load /etc/apache2/mods-enabled/php.load \
    ; printf '<FilesMatch \\.php$>\nSetHandler application/x-httpd-php\n</FilesMatch>\n' > /etc/apache2/conf-available/php.conf \
    ; a2enconf php \
    ; echo "ServerName localhost" > /etc/apache2/conf-available/servername.conf \
    ; a2enconf servername \
    ; mkdir -p /tmp/sessions && chmod 1777 /tmp/sessions \
    && mkdir -p /var/www/html

# lab php.ini: advisory-relevant settings
RUN printf '[Session]\nsession.save_handler = files\nsession.save_path = /tmp/sessions\nsession.use_strict_mode = 0\nsession.use_cookies = 1\nsession.use_only_cookies = 0\nsession.upload_progress.enabled = On\nsession.upload_progress.cleanup = Off\nsession.upload_progress.prefix = upload_progress_\nsession.upload_progress.name = PHP_SESSION_UPLOAD_PROGRESS\nsession.upload_progress.freq = 1%%\nsession.upload_progress.min_freq = 0\n\n[PHP]\ndisplay_errors = On\nerror_reporting = E_ALL\nfile_uploads = On\npost_max_size = 128M\nupload_max_filesize = 128M\nmemory_limit = 128M\nmax_execution_time = 5\nmax_input_time = 10\n' > /usr/local/etc/php/php.ini \
    ; true

WORKDIR /var/www/html
ENV ASAN_OPTIONS="detect_leaks=0"

EXPOSE 80
CMD ["apachectl", "-D", "FOREGROUND"]