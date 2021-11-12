#!/bin/bash

set -ex

VERSION="$(git describe --tags 2>/dev/null || echo 'v0.0.1')"
PACKAGE=$(basename ${PWD})

build() {
    export GOOS=linux GOARCH=amd64
    go build -a -trimpath -o ${PACKAGE}_${VERSION} cmd/*.go
}

convert() {
    export GOOS=linux GOARCH=amd64
    go build -a -trimpath -o ${PACKAGE}_${VERSION} cmd/*.go
    upx -9 -o ${PACKAGE}_${VERSION}_${GOOS}_${GOARCH} ${PACKAGE}_${VERSION}
    rm -f ${PACKAGE}_${VERSION}
}

$1
