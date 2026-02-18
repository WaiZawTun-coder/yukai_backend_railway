FROM php:8.2-apache

# Enable rewrite
RUN a2enmod rewrite

# Fix MPM conflict
RUN a2dismod mpm_event mpm_worker || true
RUN a2enmod mpm_prefork

# Install PHP extensions
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
 && docker-php-ext-install curl pdo_mysql mysqli

# Copy project
COPY . /var/www/html/

RUN chown -R www-data:www-data /var/www/html

# Railway port handling
CMD sed -i "s/80/${PORT}/g" /etc/apache2/ports.conf \
 && sed -i "s/:80/:${PORT}/g" /etc/apache2/sites-enabled/000-default.conf \
 && apache2-foreground
