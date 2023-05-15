#!/bin/bash

work_dir=`pwd`
authelia_dir="$(git rev-parse --show-toplevel)"/auth-system/authelia

set -e

printf "\n%s" "Installing go..."
[ -d "/usr/local/go1.19.9" ] && rm -rf "/usr/local/go1.19.9"
mkdir "/usr/local/go1.19.9"

go_url="https://go.dev/dl/go1.19.9.linux-amd64.tar.gz"
wget -q -O- $go_url | tar -xz -C /usr/local/go1.19.9
[ -e /usr/local/bin/go ] && rm /usr/local/bin/go
ln -s /usr/local/go1.19.9/go/bin/go /usr/local/bin/go

chmod 0775 /usr/local/go1.19.9/
chmod 0775 /usr/local/go1.19.9/go/bin/go
chown -R $USER:$USER /usr/local/go1.19.0
chmod 0775 /usr/local/bin/go
chown $USER:$USER /usr/local/bin/go

[ ! -d $authelia_dir/authelia-src ] && \
  git clone https://github.com/authelia/authelia.git $authelia_dir/authelia-src

cd $authelia_dir/authelia-src

git checkout tags/v4.37.5

/usr/local/go/bin/go mod download

cd $authelia_dir/authelia-src/web

pnpm install
pnpm build

cd $authelia_dir/authelia-src

CGO_ENABLED=1 \
  CGO_CPPFLAGS="-D_FORTIFY_SOURCE=2 -fstack-protector-strong" \
  CGO_LDFLAGS="-Wl,-z,relro,-z,now" \
  /usr/local/go/bin/go build -ldflags "-linkmode=external" -trimpath -buildmode=pie \
  -o authelia ./cmd/authelia


chown -R $USER:$USER $authelia_dir/authelia-src
chmod 775 $authelia_dir/authelia-src

cd $work_dir
