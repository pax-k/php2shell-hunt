# LAB-ONLY: php:8.4.27-apache + phpredis.
#
# The Redis *session* save handler is implemented by the phpredis extension, so
# the official image (which ships without it) cannot exercise
# session.save_handler=redis. Pinned to redis 6.3.0 for a reproducible build.
FROM php:8.4.27-apache

RUN pecl install redis-6.3.0 \
    && docker-php-ext-enable redis
