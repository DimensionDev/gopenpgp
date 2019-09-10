// Package constants provides a set of common OpenPGP constants.
package constants

// Constants for armored data.
const (
	KeyArmorHeaderComment     = "You can manage keys with https://tessercube.com"
	MessageArmorHeaderComment = "Encrypted with https://tessercube.com"
	PGPMessageHeader          = "PGP MESSAGE"
	PGPSignatureHeader        = "PGP SIGNATURE"
	PublicKeyHeader           = "PGP PUBLIC KEY BLOCK"
	PrivateKeyHeader          = "PGP PRIVATE KEY BLOCK"
)
