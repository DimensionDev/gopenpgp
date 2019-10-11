package main

import (
	"syscall/js"

	"github.com/DimensionDev/gopenpgp/crypto"
	"github.com/aaronpowell/webpack-golang-wasm-async-loader/gobridge"
)

var c chan struct{}

func generateKeyRing(this js.Value, args []js.Value) (interface{}, error) {
	rsaKey, err := crypto.GetGopenPGP().GenerateKey("test", "test@gmail.com", "test", "x25519", 256)
	if err != nil {
		return nil, err
	}
	return js.ValueOf(rsaKey), nil
}

func main() {
	c := make(chan struct{}, 0)
	println("Go Wasm loaded successfully!")
	gobridge.RegisterCallback("generateKeyRing", generateKeyRing)
	<-c
}
