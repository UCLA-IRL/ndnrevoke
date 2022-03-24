#!/usr/bin/env bash
set -ex

pushd "$CACHE_DIR" >/dev/null

INSTALLED_VERSION=$(git -C cert-ledger rev-parse HEAD 2>/dev/null || echo NONE)

sudo rm -rf cert-ledger-latest
git clone --depth 1 https://github.com/UCLA-IRL/cert-ledger.git cert-ledger-latest
LATEST_VERSION=$(git -C cert-ledger-latest rev-parse HEAD 2>/dev/null || echo UNKNOWN)

if [[ $INSTALLED_VERSION != $LATEST_VERSION ]]; then
    sudo rm -rf cert-ledger
    mv cert-ledger-latest cert-ledger
else
    sudo rm -rf cert-ledger-latest
fi

sudo rm -fr /usr/local/include/cert-ledger
sudo rm -f /usr/local/lib{,64}/libcert-ledger*
sudo rm -f /usr/local/lib{,64}/pkgconfig/libcert-ledger.pc

pushd cert-ledger >/dev/null
mkdir build
pushd build >/dev/null

cmake -DCMAKE_BUILD_TYPE=Release ..
make
sudo_preserve_env PATH -- make install

popd >/dev/null
popd >/dev/null
popd >/dev/null

if has Linux $NODE_LABELS; then
    sudo ldconfig
fi