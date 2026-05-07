FROM php:8.2-apache

# Enable mod_rewrite
RUN a2enmod rewrite

# Copy project files into Apache web root
COPY . /var/www/html/

# Set correct permissions
RUN chown -R www-data:www-data /var/www/html \
    && chmod -R 755 /var/www/html

EXPOSE 80