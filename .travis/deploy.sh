#!/bin/sh

set -e

gox -os="darwin" -arch="amd64"

chmod u+x ./tlself_darwin_amd64

mkdir build/ && cd build/
cp ../tlself_darwin_amd64 . && mv tlself_darwin_amd64 tlself && zip tlself_macos.zip tlself

cd ..

mv build/*.zip .
