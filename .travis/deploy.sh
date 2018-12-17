#!/bin/sh

set -e

gox -os="linux darwin windows" -arch="amd64"

chmod u+x ./tlself_darwin_amd64 ./tlself_linux_amd64

mkdir build/ && cd build/
cp ../tlself_darwin_amd64 . && mv tlself_darwin_amd64 tlself && zip tlself_macos.zip tlself
cp ../tlself_linux_amd64 . && mv tlself_linux_amd64 tlself && zip tlself_linux.zip tlself
cp ../tlself_windows_amd64.exe . && mv tlself_windows_amd64.exe tlself.exe && zip tlself_windows.zip tlself.exe

cd ..

mv build/*.zip .
