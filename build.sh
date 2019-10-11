#!/bin/bash

SCRIPT_LOCATION=$(cd $(dirname $0); echo $PWD)

OUTPUT_PATH="dist"
OUTPUT_FILE_NAME="gopenpgp"
ANDROID_OUT=${OUTPUT_PATH}/"Android"
IOS_OUT=${OUTPUT_PATH}/"iOS"
WASM_OUT=${OUTPUT_PATH}/"Wasm"
mkdir -p $ANDROID_OUT
mkdir -p $IOS_OUT
mkdir -p $WASM_OUT

printf "\e[0;32mStart Building iOS framework .. Location: ${IOS_OUT} \033[0m\n\n"
PACKAGE_PATH=github.com/DimensionDev/gopenpgp
GO_CRYPTO_OPENPGP=golang.org/x/crypto/openpgp

# gomobile bind -ldflags=-w -target ios -o ${IOS_OUT}/DMSGoPGP.framework $PACKAGE_PATH/DMSGoPGP \
# $PACKAGE_PATH/crypto $PACKAGE_PATH/helper $PACKAGE_PATH/armor $PACKAGE_PATH/constants

# printf "\e[0;32mStart Building Android lib .. Location: ${ANDROID_OUT} \033[0m\n\n"

# gomobile bind -target android -javapkg com.dimension.DMSGoPGP -o ${ANDROID_OUT}/DMSGoPGP.aar $PACKAGE_PATH/DMSGoPGP \
# $PACKAGE_PATH/crypto $PACKAGE_PATH/helper $PACKAGE_PATH/armor $PACKAGE_PATH/constants

# printf "\e[0;32mInstalling frameworks. \033[0m\n\n"

printf "\e[0;32mStart Building WASM lib .. Location: ${WASM_OUT} \033[0m\n\n"

GOOS=js GOARCH=wasm go build  -o ${WASM_OUT}/DMSGoPGP.wasm $PACKAGE_PATH/wasm

printf "\e[0;32mAll Done. \033[0m\n\n"


