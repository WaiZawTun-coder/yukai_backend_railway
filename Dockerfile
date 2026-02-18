FROM php:8.2-apache

# Enable Apache rewrite
RUN a2enmod rewrite

# Install required extensions
RUN apt-get update && apt-get install -y \
    libcurl4-openssl-dev \
 && docker-php-ext-install curl pdo_mysql mysqli

# Copy project
COPY . /var/www/html/

# Set permissions
RUN chown -R www-data:www-data /var/www/html

# Railway uses dynamic PORT
ENV PORT=8080
EXPOSE 8080

# Change Apache to listen on Railway PORT
CMD sed -i "s/80/${PORT}/g" /etc/apache2/ports.conf \
 && sed -i "s/:80/:${PORT}/g" /etc/apache2/sites-enabled/000-default.conf \
 && apache2-foreground
