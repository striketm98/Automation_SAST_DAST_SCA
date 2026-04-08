FROM php:8.3-apache

RUN docker-php-ext-install pdo pdo_mysql mysqli
RUN a2enmod rewrite

RUN printf '%s\n' '<Directory /var/www/html/public>' '    DirectoryIndex login.php index.php' '</Directory>' >> /etc/apache2/sites-available/000-default.conf
RUN sed -i 's#/var/www/html#/var/www/html/public#g' /etc/apache2/sites-available/000-default.conf

COPY . /var/www/html

RUN mkdir -p /var/www/html/public/uploads/client-logos /var/www/html/storage/source-uploads
RUN chown -R www-data:www-data /var/www/html

EXPOSE 80
