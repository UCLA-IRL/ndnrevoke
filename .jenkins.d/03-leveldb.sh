#!/usr/bin/env bash
set -ex

pushd "$CACHE_DIR" >/dev/null

INSTALLED_VERSION=$(git -C leveldb rev-parse HEAD 2>/dev/null || echo NONE)

sudo rm -rf leveldb-latest
git clone --recurse-submodules --depth 1 -b 1.23 https://github.com/google/leveldb.git leveldb-latest
LATEST_VERSION=$(git -C leveldb-latest rev-parse HEAD 2>/dev/null || echo UNKNOWN)

if [[ $INSTALLED_VERSION != $LATEST_VERSION ]]; then
    sudo rm -rf leveldb
    mv leveldb-latest leveldb
else
    sudo rm -rf leveldb-latest
fi

sudo rm -fr /usr/local/include/leveldb
sudo rm -f /usr/local/lib{,64}/libleveldb*

pushd leveldb >/dev/null
mkdir build
pushd build >/dev/null

cmake -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=True -DLEVELDB_BUILD_TESTS=OFF -DLEVELDB_BUILD_BENCHMARKS=OFF ..
cmake --build .
sudo_preserve_env PATH -- make install

popd >/dev/null
popd >/dev/null
popd >/dev/null

if has Linux $NODE_LABELS; then
    sudo ldconfig
fi