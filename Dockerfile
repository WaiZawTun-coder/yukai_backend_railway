FROM php:8.2-apache

RUN a2enmod rewrite
RUN a2dismod mpm_event mpm_worker || true
RUN a2enmod mpm_prefork

RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
 && docker-php-ext-install curl pdo_mysql mysqli \
 && rm -rf /var/lib/apt/lists/*

COPY --chown=www-data:www-data . /var/www/html/

EXPOSE 8080

CMD sed -i "s/80/${PORT}/g" /etc/apache2/ports.conf \
 && sed -i "s/:80/:${PORT}/g" /etc/apache2/sites-enabled/000-default.conf \
 && apache2-foreground
