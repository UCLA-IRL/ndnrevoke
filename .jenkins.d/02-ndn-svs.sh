#!/usr/bin/env bash
set -ex

pushd "$CACHE_DIR" >/dev/null

INSTALLED_VERSION=$(git -C ndn-svs rev-parse HEAD 2>/dev/null || echo NONE)

sudo rm -rf ndn-svs-latest
git clone --depth 1 https://github.com/named-data/ndn-svs.git ndn-svs-latest
LATEST_VERSION=$(git -C ndn-svs-latest rev-parse HEAD 2>/dev/null || echo UNKNOWN)

if [[ $INSTALLED_VERSION != $LATEST_VERSION ]]; then
    sudo rm -rf ndn-svs
    mv ndn-svs-latest ndn-svs
else
    sudo rm -rf ndn-svs-latest
fi

sudo rm -fr /usr/local/include/ndn-svs
sudo rm -f /usr/local/lib{,64}/libndn-svs*
sudo rm -f /usr/local/lib{,64}/pkgconfig/libndn-svs.pc

pushd ndn-svs >/dev/null

if has CentOS-8 $NODE_LABELS; then
    # https://bugzilla.redhat.com/show_bug.cgi?id=1721553
    PCH="--without-pch"
fi

./waf --color=yes configure --disable-static --enable-shared $PCH
./waf --color=yes build -j$WAF_JOBS
sudo_preserve_env PATH -- ./waf --color=yes install

popd >/dev/null
popd >/dev/null

if has Linux $NODE_LABELS; then
    sudo ldconfig
fi