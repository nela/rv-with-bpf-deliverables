#!/bin/bash

work_dir=`pwd`
ngx_dir="$(git rev-parse --show-toplevel)"/auth-system/nginx
[ -d "$ngx_dir/nginx-1.18.0" ] && rm -rf "$ngx_dir/nginx-1.18.0"

ngx_url="https://nginx.org/download/nginx-1.18.0.tar.gz"

set -e

wget -q -O- $ngx_url | tar -xz -C $ngx_dir

patch -d $ngx_dir/nginx-1.18.0 -p1 < $ngx_dir/nginx_usdt.patch

# chown -R $USER:$USER $ngx_dir/nginx-1.18.0
# chmod -R 0666 $ngx_dir/nginx-1.18.0
# chmod 0777 $ngx_dir/nginx-1.18.0/configure

cd $ngx_dir/nginx-1.18.0

set +e

source configure \
  --with-cc-opt="-g -O2 -ffile-prefix-map=/build/nginx-QeqwpL/nginx-1.18.0=. -fstack-protector-strong -Wformat -Werror=format-security -fPIC -Wdate-time -D_FORTIFY_SOURCE=2" \
  --with-ld-opt='-Wl,-z,relro -Wl,-z,now -fPIC' \
  --prefix=/usr/share/nginx \
  --sbin-path=/usr/sbin \
  --conf-path=/etc/nginx/nginx.conf \
  --http-log-path=/var/log/nginx/access.log \
  --error-log-path=/var/log/nginx/error.log \
  --lock-path=/var/lock/nginx.lock \
  --pid-path=/run/nginx.pid \
  --modules-path=/usr/lib/nginx/modules \
  --http-client-body-temp-path=/var/lib/nginx/body \
  --http-fastcgi-temp-path=/var/lib/nginx/fastcgi \
  --http-proxy-temp-path=/var/lib/nginx/proxy \
  --http-scgi-temp-path=/var/lib/nginx/scgi \
  --http-uwsgi-temp-path=/var/lib/nginx/uwsgi \
  --with-compat \
  --with-pcre-jit \
  --with-http_ssl_module \
  --with-http_stub_status_module \
  --with-http_realip_module \
  --with-http_auth_request_module \
  --with-http_v2_module \
  --with-http_dav_module \
  --with-http_slice_module \
  --with-threads \
  --with-http_addition_module \
  --with-http_gunzip_module \
  --with-http_gzip_static_module \
  --with-http_sub_module

set -e

printf "\n%s" "Configuration successful. Now go to nginx-1.18.0 directory and run make and make install."

[ -d /var/lib/nginx/body ] || mkdir -p /var/lib/nginx/body
