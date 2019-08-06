package crypto

import (
	"bytes"
	"crypto"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/DimensionDev/gopenpgp/armor"
	"github.com/DimensionDev/gopenpgp/constants"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/packet"
)

// IsKeyExpired checks whether the given (unarmored, binary) key is expired.
func (pgp *GopenPGP) IsKeyExpired(publicKey []byte) (bool, error) {
	now := pgp.getNow()
	pubKeyReader := bytes.NewReader(publicKey)
	pubKeyEntries, err := openpgp.ReadKeyRing(pubKeyReader)
	if err != nil {
		return true, err
	}
	for _, e := range pubKeyEntries {
		if _, ok := e.EncryptionKey(now); ok {
			return false, nil
		}
	}
	return true, errors.New("keys expired")
}

// IsArmoredKeyExpired checks whether the given armored key is expired.
func (pgp *GopenPGP) IsArmoredKeyExpired(publicKey string) (bool, error) {
	rawPubKey, err := armor.Unarmor(publicKey)
	if err != nil {
		return false, err
	}
	return pgp.IsKeyExpired(rawPubKey)
}

func (pgp *GopenPGP) generateKey(
	name, email, passphrase, keyType string,
	bits int,
	prime1, prime2, prime3, prime4 []byte,
) (string, error) {
	if len(email) <= 0 {
		return "", errors.New("invalid email format")
	}

	if len(name) <= 0 {
		return "", errors.New("invalid name format")
	}

	comments := ""

	cfg := &packet.Config{
		Algorithm:     packet.PubKeyAlgoRSA,
		RSABits:       bits,
		Time:          pgp.getTimeGenerator(),
		DefaultHash:   crypto.SHA256,
		DefaultCipher: packet.CipherAES256,
	}

	if keyType == "x25519" {
		cfg.Algorithm = packet.PubKeyAlgoEdDSA
	}

	if prime1 != nil && prime2 != nil && prime3 != nil && prime4 != nil {
		var bigPrimes [4]*big.Int
		bigPrimes[0] = new(big.Int)
		bigPrimes[0].SetBytes(prime1)
		bigPrimes[1] = new(big.Int)
		bigPrimes[1].SetBytes(prime2)
		bigPrimes[2] = new(big.Int)
		bigPrimes[2].SetBytes(prime3)
		bigPrimes[3] = new(big.Int)
		bigPrimes[3].SetBytes(prime4)

		cfg.RSAPrimes = bigPrimes[:]
	}

	newEntity, err := openpgp.NewEntity(name, comments, email, cfg)
	if err != nil {
		return "", err
	}

	if err := newEntity.SelfSign(nil); err != nil {
		return "", err
	}

	rawPwd := []byte(passphrase)
	if newEntity.PrivateKey != nil && !newEntity.PrivateKey.Encrypted {
		if err := newEntity.PrivateKey.Encrypt(rawPwd); err != nil {
			return "", err
		}
	}

	for _, sub := range newEntity.Subkeys {
		if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
			if err := sub.PrivateKey.Encrypt(rawPwd); err != nil {
				return "", err
			}
		}
	}

	w := bytes.NewBuffer(nil)
	if err := newEntity.SerializePrivateNoSign(w, nil); err != nil {
		return "", err
	}
	serialized := w.Bytes()
	return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
}

// GenerateRSAKeyWithPrimes generates a RSA key using the given primes.
func (pgp *GopenPGP) GenerateRSAKeyWithPrimes(
	name, email, passphrase string,
	bits int,
	primeone, primetwo, primethree, primefour []byte,
) (string, error) {
	return pgp.generateKey(name, email, passphrase, "rsa", bits, primeone, primetwo, primethree, primefour)
}

// GenerateKey generates a key of the given keyType ("rsa" or "x25519").
// If keyType is "rsa", bits is the RSA bitsize of the key.
// If keyType is "x25519" bits is unused.
func (pgp *GopenPGP) GenerateKey(name, email, passphrase, keyType string, bits int) (string, error) {
	return pgp.generateKey(name, email, passphrase, keyType, bits, nil, nil, nil, nil)
}

// UpdatePrivateKeyPassphrase decrypts the given armored privateKey with oldPassphrase,
// re-encrypts it with newPassphrase, and returns the new armored key.
func (pgp *GopenPGP) UpdatePrivateKeyPassphrase(
	privateKey string, oldPassphrase string, newPassphrase string,
) (string, error) {
	privKey := strings.NewReader(privateKey)
	privKeyEntries, err := openpgp.ReadArmoredKeyRing(privKey)
	if err != nil {
		return "", err
	}

	oldrawPwd := []byte(oldPassphrase)
	newRawPwd := []byte(newPassphrase)
	w := bytes.NewBuffer(nil)
	for _, e := range privKeyEntries {
		if e.PrivateKey != nil && e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Decrypt(oldrawPwd); err != nil {
				return "", err
			}
		}
		if e.PrivateKey != nil && !e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Encrypt(newRawPwd); err != nil {
				return "", err
			}
		}

		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Decrypt(oldrawPwd); err != nil {
					return "", err
				}
			}
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Encrypt(newRawPwd); err != nil {
					return "", err
				}
			}
		}
		if err := e.SerializePrivateNoSign(w, nil); err != nil {
			return "", err
		}
	}

	serialized := w.Bytes()
	return armor.ArmorWithType(serialized, constants.PrivateKeyHeader)
}

// PrintFingerprints is a debug helper function that prints the key and subkey fingerprints.
func (pgp *GopenPGP) PrintFingerprints(pubKey string) (string, error) {
	pubKeyReader := strings.NewReader(pubKey)
	entries, err := openpgp.ReadArmoredKeyRing(pubKeyReader)
	if err != nil {
		return "", err
	}

	for _, e := range entries {
		for _, subKey := range e.Subkeys {
			if !subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications {
				fmt.Println("SubKey:" + hex.EncodeToString(subKey.PublicKey.Fingerprint[:]))
			}
		}
		fmt.Println("PrimaryKey:" + hex.EncodeToString(e.PrimaryKey.Fingerprint[:]))
	}
	return "", nil
}

/* DMS customized KeyEntity and Key structs */
const (
	PubKeyAlgoRSA     int = 1
	PubKeyAlgoElGamal int = 16
	PubKeyAlgoDSA     int = 17
	// RFC 6637, Section 5.
	PubKeyAlgoECDH  int = 18
	PubKeyAlgoECDSA int = 19
	// https://www.ietf.org/archive/id/draft-koch-eddsa-for-openpgp-04.txt
	PubKeyAlgoEdDSA int = 22

	// Deprecated in RFC 4880, Section 13.5. Use key flags instead.
	PubKeyAlgoRSAEncryptOnly int = 2
	PubKeyAlgoRSASignOnly    int = 3
)

type PublicKey struct {
	packet.PublicKey
}

func (p *PublicKey) GetCreationTimestamp() int {
	return int(p.CreationTime.Unix())
}

func (p *PublicKey) GetAlgorithm() int {
	return int(p.PubKeyAlgo)
}

func (p *PublicKey) GetFingerprint() string {
	return hex.EncodeToString(p.Fingerprint[:])
}

func (p *PublicKey) GetKeyId() int {
	return int(p.KeyId)
}

// KeyIdString returns the public key's fingerprint in capital hex
// (e.g. "6C7EE1B8621CC013").
func (p *PublicKey) KeyIdString() string {
	return p.KeyIdString()
}

// KeyIdShortString returns the short form of public key's fingerprint
// in capital hex, as shown by gpg --list-keys (e.g. "621CC013").
func (p *PublicKey) KeyIdShortString() string {
	return p.KeyIdShortString()
}

func (p *PublicKey) BitLength() (bitLength int, err error) {
	rawBitLength, err := p.BitLength()
	return int(rawBitLength), err
}

type PrivateKey struct {
	PublicKey
	packet.PrivateKey
}

func (privKey *PrivateKey) GetEncrypted() bool {
	return privKey.Encrypted
}

type UserId struct {
	packet.UserId
}

func (u *UserId) GetName() string {
	return u.Name
}

func (u *UserId) GetId() string {
	return u.Id
}

func (u *UserId) GetComment() string {
	return u.Comment
}

func (u *UserId) GetEmail() string {
	return u.Email
}

type Identity struct {
	Name          string // by convention, has the form "Full Name (comment) <email@example.com>"
	UserId        *UserId
	SelfSignature *Signature
	Signatures    []*Signature
}

func genIdentity(rawIdentity *openpgp.Identity) *Identity {
	id := new(Identity)
	id.Name = rawIdentity.Name
	id.UserId = &UserId{*rawIdentity.UserId}
	id.SelfSignature = &Signature{*rawIdentity.SelfSignature}
	var sigs []*Signature
	for _, s := range rawIdentity.Signatures {
		sigs = append(sigs, &Signature{*s})
	}
	id.Signatures = sigs
	return id
}

func genIdentityMap(rawIdentityMap map[string]*openpgp.Identity) map[string]*Identity {
	newMap := make(map[string]*Identity)
	for key, value := range rawIdentityMap {
		newMap[key] = genIdentity(value)
	}
	return newMap
}

func getRawIdentity(identity *Identity) *openpgp.Identity {
	rawId := new(openpgp.Identity)
	rawId.Name = identity.Name
	rawId.UserId = &identity.UserId.UserId
	rawId.SelfSignature = &identity.SelfSignature.Signature
	var sigs []*packet.Signature
	for _, s := range identity.Signatures {
		sigs = append(sigs, &s.Signature)
	}
	rawId.Signatures = sigs
	return rawId
}

func genRawIdentityMap(identityMap map[string]*Identity) map[string]*openpgp.Identity {
	newMap := make(map[string]*openpgp.Identity)
	for key, value := range identityMap {
		newMap[key] = getRawIdentity(value)
	}
	return newMap
}

type Subkey struct {
	openpgp.Subkey
}

type KeyEntity struct {
	PrimaryKey  *PublicKey
	PrivateKey  *PrivateKey
	Identities  map[string]*Identity // indexed by Identity.Name
	Revocations []*Signature
	Subkeys     []Subkey
}

func (k *KeyEntity) getRawEntity() *openpgp.Entity {
	return &openpgp.Entity{
		PrimaryKey:  &k.PrimaryKey.PublicKey,
		PrivateKey:  &k.PrivateKey.PrivateKey,
		Identities:  genRawIdentityMap(k.Identities),
		Revocations: k.getRawRevocations(),
		Subkeys:     k.getRawSubkeys(),
	}
}

func (k *KeyEntity) getRawRevocations() []*packet.Signature {
	var sigs []*packet.Signature
	for _, s := range k.Revocations {
		sigs = append(sigs, &s.Signature)
	}
	return sigs
}

func (k *KeyEntity) getRawSubkeys() []openpgp.Subkey {
	var subkeys []openpgp.Subkey
	for _, s := range k.Subkeys {
		subkeys = append(subkeys, s.Subkey)
	}
	return subkeys
}

// Serialize writes the public part of the given Entity to w, including
// signatures from other entities. No private key material will be output.
func (k *KeyEntity) Serialize(w io.Writer) error {
	err := k.PrimaryKey.Serialize(w)
	if err != nil {
		return err
	}
	for _, ident := range k.Identities {
		err = ident.UserId.Serialize(w)
		if err != nil {
			return err
		}
		for _, sig := range ident.Signatures {
			err = sig.Serialize(w)
			if err != nil {
				return err
			}
		}
	}
	for _, subkey := range k.Subkeys {
		err = subkey.PublicKey.Serialize(w)
		if err != nil {
			return err
		}
		err = subkey.Sig.Serialize(w)
		if err != nil {
			return err
		}
	}
	return nil
}

type KeyEntityList []*KeyEntity

// KeysById returns the set of keys that have the given key id.
func (el KeyEntityList) KeysById(id uint64) (keys []openpgp.Key) {
	for _, e := range el {
		if e.PrimaryKey.KeyId == id {
			var selfSig *packet.Signature
			for _, ident := range e.Identities {
				if selfSig == nil {
					selfSig = &ident.SelfSignature.Signature
				} else if ident.SelfSignature.IsPrimaryId != nil && *ident.SelfSignature.IsPrimaryId {
					selfSig = &ident.SelfSignature.Signature
					break
				}
			}
			keys = append(keys, openpgp.Key{e.getRawEntity(), &e.PrimaryKey.PublicKey, &e.PrivateKey.PrivateKey, selfSig})
		}

		for _, subKey := range e.Subkeys {
			if subKey.PublicKey.KeyId == id {
				keys = append(keys, openpgp.Key{e.getRawEntity(), subKey.PublicKey, subKey.PrivateKey, subKey.Sig})
			}
		}
	}
	return
}

// KeysByIdAndUsage returns the set of keys with the given id that also meet
// the key usage given by requiredUsage.  The requiredUsage is expressed as
// the bitwise-OR of packet.KeyFlag* values.
func (el KeyEntityList) KeysByIdUsage(id uint64, requiredUsage byte) (keys []openpgp.Key) {
	for _, key := range el.KeysById(id) {
		if len(key.Entity.Revocations) > 0 {
			continue
		}

		if key.SelfSignature.RevocationReason != nil {
			continue
		}

		if key.SelfSignature.FlagsValid && requiredUsage != 0 {
			var usage byte
			if key.SelfSignature.FlagCertify {
				usage |= packet.KeyFlagCertify
			}
			if key.SelfSignature.FlagSign {
				usage |= packet.KeyFlagSign
			}
			if key.SelfSignature.FlagEncryptCommunications {
				usage |= packet.KeyFlagEncryptCommunications
			}
			if key.SelfSignature.FlagEncryptStorage {
				usage |= packet.KeyFlagEncryptStorage
			}
			if usage&requiredUsage != requiredUsage {
				continue
			}
		}

		keys = append(keys, key)
	}
	return
}

// DecryptionKeys returns all private keys that are valid for decryption.
func (el KeyEntityList) DecryptionKeys() (keys []openpgp.Key) {
	for _, e := range el {
		for _, subKey := range e.Subkeys {
			if subKey.PrivateKey != nil && (!subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage || subKey.Sig.FlagEncryptCommunications) {
				keys = append(keys, openpgp.Key{e.getRawEntity(), subKey.PublicKey, subKey.PrivateKey, subKey.Sig})
			}
		}
	}
	return
}
