module github.com/DimensionDev/gopenpgp

go 1.12

require (
	github.com/ProtonMail/go-mime v0.0.0-20190521135552-09454e3dbe72
	github.com/stretchr/testify v1.2.2
	golang.org/x/crypto v0.0.0-20190513172903-22d7a77e9e5f
)

replace golang.org/x/crypto => github.com/ProtonMail/crypto v0.0.0-20190604143603-d3d8a14a4d4f
