module github.com/DimensionDev/gopenpgp

go 1.13

require (
	github.com/ProtonMail/go-mime v0.0.0-20190521135552-09454e3dbe72
	github.com/aaronpowell/webpack-golang-wasm-async-loader v0.1.0
	github.com/stretchr/testify v1.2.2
	golang.org/x/crypto v0.0.0-20190923035154-9ee001bba392
)

replace golang.org/x/crypto => github.com/DimensionDev/crypto v0.0.0-20190814153124-b5b07a6add54
