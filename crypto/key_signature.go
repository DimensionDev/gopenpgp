package crypto

import "golang.org/x/crypto/openpgp/packet"

type Signature struct {
	packet.Signature
}
