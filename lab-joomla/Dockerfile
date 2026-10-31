# Joomla lab PHP: official php:8.2-fpm (vulnerable 8.2.34) + the MySQL
# drivers Joomla needs. The base image ships mysqlnd/PDO but not mysqli/
# pdo_mysql, so compile them from the bundled source.
FROM php:8.2-fpm
RUN docker-php-ext-install -j"$(nproc)" mysqli pdo_mysql