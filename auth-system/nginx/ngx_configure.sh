#!/bin/bash

work_dir=`pwd`
ngx_dir="$(git rev-parse --show-toplevel)"/auth-system/nginx

set -e

# Create SSL cert required by Authelia
printf "\n%s" "Generating SSL certificates"

[ -d "$ngx_dir"/ssl ] && rm -rf "$ngx_dir"/ssl
mkdir -p "$ngx_dir"/conf/ssl

openssl req \
  -x509 \
  -nodes \
  -days 365 \
  -newkey rsa:2048 \
  -keyout "$ngx_dir"/conf/ssl/localhost.key \
  -out "$ngx_dir"/conf/ssl/localhost.crt \
  -subj '/C=NO/ST=Oslo/L=Oslo/O=Hello Inc./CN=localhost' \
  --config "$ngx_dir"/openssl.conf

# Create symlinks to /etc/nginx/
printf "\n%s\n" "Creating symlinks"
for i in $ngx_dir/conf/*; do
  dest=/etc/nginx/`basename $i`
  if [ -d $i ]; then
    [ -d $dest ] && rm -rf $dest
    mkdir $dest
    ln -s $i/* $dest
  else
    [ -e $dest ] && rm $dest
    ln -s "$i" $dest
  fi
done

printf "\n%s" "Enabling configured sites"
[ -d /etc/nginx/sites-enabled ] && rm -rf /etc/nginx/sites-enabled
mkdir /etc/nginx/sites-enabled

for i in /etc/nginx/sites-available/*; do
  ln -s $i /etc/nginx/sites-enabled/`basename $i`
done

# Configure local DNS
printf "\n%s\n" "Updating /etc/hosts"
printf "\n%s\t%s\n%s\t%s" "127.0.0.1" "hello.com" "127.0.0.1" "auth.hello.com" \
  | tee -a /etc/hosts
