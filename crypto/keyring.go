package crypto

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"golang.org/x/crypto/openpgp"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	xrsa "golang.org/x/crypto/rsa"

	armorUtils "github.com/DimensionDev/gopenpgp/armor"
	"github.com/DimensionDev/gopenpgp/constants"
)

type KeyRing struct {
	Entities []*KeyEntity
}

func (keyRing *KeyRing) GetEntitiesCount() int {
	return len(keyRing.Entities)
}

func (keyRing *KeyRing) GetEntity(index int) (*KeyEntity, error) {
	if index >= len(keyRing.Entities) {
		return nil, errors.New("openpgp: index out of bounds, there are only " + string(len(keyRing.Entities)) + "entities")
	}
	return keyRing.Entities[index], nil
}

func (keyRing *KeyRing) GetEntities() []*KeyEntity {
	return keyRing.Entities
}

func (keyRing *KeyRing) getRawEntities() openpgp.EntityList {
	var rawEntities openpgp.EntityList
	for _, de := range keyRing.Entities {
		var rawPrivKey *packet.PrivateKey
		if de.PrivateKey != nil {
			rawPrivKey = de.PrivateKey.PrivateKey
		}
		re := &openpgp.Entity{
			PrimaryKey:  &de.PrimaryKey.PublicKey,
			PrivateKey:  rawPrivKey,
			Identities:  genRawIdentityMap(de.Identities),
			Revocations: de.getRawRevocations(),
			Subkeys:     de.getRawSubkeys(),
		}

		rawEntities = append(rawEntities, re)
	}
	return rawEntities
}

// GetSigningEntity returns first private unlocked signing entity from keyring.
func (keyRing *KeyRing) GetSigningEntity() (*KeyEntity, error) {
	var signEntity *KeyEntity

	for _, e := range keyRing.Entities {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			if !e.PrivateKey.GetEncrypted() {
				signEntity = e
				break
			}
		}
	}
	if signEntity == nil {
		err := errors.New("gopenpgp: cannot sign message, unable to unlock signer key")
		return signEntity, err
	}

	return signEntity, nil
}

func (keyRing *KeyRing) GetEncryptionKey() (*PublicKey, error) {
	var pub *packet.PublicKey
	for _, e := range keyRing.GetEntities() {
		if encryptionKey, ok := e.getRawEntity().EncryptionKey(pgp.getNow()); ok {
			pub = encryptionKey.PublicKey
			break
		}
	}
	if pub == nil {
		return nil, errors.New("cannot set key: no public key available")
	}
	return &PublicKey{*pub}, nil
}

// Unlock tries to unlock as many keys as possible with the following password. Note
// that keyrings can contain keys locked with different passwords, and thus
// err == nil does not mean that all keys have been successfully decrypted.
// If err != nil, the password is wrong for every key, and err is the last error
// encountered.
func (keyRing *KeyRing) Unlock(passphrase []byte) error {
	// Build a list of keys to decrypt
	var keys []*packet.PrivateKey
	for _, e := range keyRing.Entities {
		// Entity.PrivateKey must be a signing key
		if e.PrivateKey != nil {
			keys = append(keys, e.PrivateKey.PrivateKey)
		}

		// Entity.Subkeys can be used for encryption
		for _, subKey := range e.Subkeys {
			if subKey.PrivateKey != nil && (!subKey.Sig.FlagsValid || subKey.Sig.FlagEncryptStorage ||
				subKey.Sig.FlagEncryptCommunications) {

				keys = append(keys, subKey.PrivateKey.PrivateKey)
			}
		}
	}

	if len(keys) == 0 {
		//return errors.New("gopenpgp: cannot unlock key ring, no private key available")
		//Why we should return an error?
		return nil
	}

	var err error
	var n int
	for _, key := range keys {
		if !key.Encrypted {
			continue // Key already decrypted
		}

		if err = key.Decrypt(passphrase); err == nil {
			n++
		}
	}

	if n == 0 {
		return err
	}
	return nil
}

// UnlockWithPassphrase is a wrapper for Unlock that uses strings
func (keyRing *KeyRing) UnlockWithPassphrase(passphrase string) error {
	return keyRing.Unlock([]byte(passphrase))
}

// WriteArmoredPublicKey outputs armored public keys from the keyring to w.
func (keyRing *KeyRing) WriteArmoredPublicKey(w io.Writer) (err error) {
	aw, err := armor.Encode(w, openpgp.PublicKeyType, nil)
	if err != nil {
		return
	}

	for _, e := range keyRing.Entities {
		if err = e.Serialize(aw); err != nil {
			aw.Close()
			return
		}
	}

	err = aw.Close()
	return
}

// GetArmoredPublicKey returns the armored public keys from this keyring.
func (keyRing *KeyRing) GetArmoredPublicKey() (s string, err error) {
	b := &bytes.Buffer{}
	if err = keyRing.WriteArmoredPublicKey(b); err != nil {
		return
	}

	s = b.String()
	return
}

// WritePublicKey outputs unarmored public keys from the keyring to w.
func (keyRing *KeyRing) WritePublicKey(w io.Writer) (err error) {
	for _, e := range keyRing.Entities {
		if err = e.Serialize(w); err != nil {
			return
		}
	}

	return
}

// GetPublicKey returns the unarmored public keys from this keyring.
func (keyRing *KeyRing) GetPublicKey() (b []byte, err error) {
	var outBuf bytes.Buffer
	if err = keyRing.WritePublicKey(&outBuf); err != nil {
		return
	}

	b = outBuf.Bytes()
	return
}

func (keyRing *KeyRing) GetArmored(passphrase string) (string, error) {
	var result string
	for _, e := range keyRing.getRawEntities() {
		w := bytes.NewBuffer(nil)

		if err := e.SelfSign(nil); err != nil {
			return "", err
		}
		rawPwd := []byte(passphrase)
		if e.PrivateKey != nil && !e.PrivateKey.Encrypted {
			if err := e.PrivateKey.Encrypt(rawPwd); err != nil {
				continue
			}
		}

		for _, sub := range e.Subkeys {
			if sub.PrivateKey != nil && !sub.PrivateKey.Encrypted {
				if err := sub.PrivateKey.Encrypt(rawPwd); err != nil {
					return "", err
				}
			}
		}

		e.SerializePrivateNoSign(w, nil)
		serializedEntity := w.Bytes()
		armoredEntity, err := armorUtils.ArmorWithType(serializedEntity, constants.PrivateKeyHeader)
		if err != nil {
			return "", err
		}
		result += armoredEntity
		result += "\r\n"
	}
	return result, nil
}

// GetFingerprint gets the fingerprint from the keyring.
func (keyRing *KeyRing) GetFingerprint() (string, error) {
	for _, entity := range keyRing.Entities {
		fp := entity.PrimaryKey.Fingerprint
		return hex.EncodeToString(fp[:]), nil
	}
	return "", errors.New("can't find public key")
}

// CheckPassphrase checks if private key passphrase is correct for every sub key.
func (keyRing *KeyRing) CheckPassphrase(passphrase string) bool {
	var keys []*packet.PrivateKey

	for _, entity := range keyRing.Entities {
		if entity.PrivateKey != nil {
			keys = append(keys, entity.PrivateKey.PrivateKey)
		}
	}
	var decryptError error
	var n int
	for _, key := range keys {
		if !key.Encrypted {
			continue // Key already decrypted
		}
		if decryptError = key.Decrypt([]byte(passphrase)); decryptError == nil {
			n++
		}
	}

	return n != 0
}

// readFrom reads unarmored and armored keys from r and adds them to the keyring.
func (keyRing *KeyRing) readFrom(r io.Reader, armored bool) error {
	var err error
	var entities openpgp.EntityList
	if armored {
		entities, err = openpgp.ReadArmoredKeyRing(r)
	} else {
		entities, err = openpgp.ReadKeyRing(r)
	}
	for _, entity := range entities {
		if entity.PrivateKey != nil {
			switch entity.PrivateKey.PrivateKey.(type) {
			// TODO: type mismatch after crypto lib update, fix this:
			case *rsa.PrivateKey:
				entity.PrimaryKey = packet.NewRSAPublicKey(
					time.Now(),
					entity.PrivateKey.PrivateKey.(*rsa.PrivateKey).Public().(*xrsa.PublicKey))

			case *ecdsa.PrivateKey:
				entity.PrimaryKey = packet.NewECDSAPublicKey(
					time.Now(),
					entity.PrivateKey.PrivateKey.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey))
			}
		}
		for _, subkey := range entity.Subkeys {
			if subkey.PrivateKey != nil {
				switch subkey.PrivateKey.PrivateKey.(type) {
				case *rsa.PrivateKey:
					subkey.PublicKey = packet.NewRSAPublicKey(
						time.Now(),
						subkey.PrivateKey.PrivateKey.(*rsa.PrivateKey).Public().(*xrsa.PublicKey))

				case *ecdsa.PrivateKey:
					subkey.PublicKey = packet.NewECDSAPublicKey(
						time.Now(),
						subkey.PrivateKey.PrivateKey.(*ecdsa.PrivateKey).Public().(*ecdsa.PublicKey))
				}
			}
		}
	}
	if err != nil {
		return err
	}

	if len(entities) == 0 {
		return errors.New("gopenpgp: key ring doesn't contain any key")
	}
	newEntities := genDMSEntities(entities)
	keyRing.Entities = append(keyRing.Entities, newEntities...)
	return nil
}

// BuildKeyRing reads keyring from binary data
func (pgp *GopenPGP) BuildKeyRing(binKeys []byte) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	entriesReader := bytes.NewReader(binKeys)
	err = keyRing.readFrom(entriesReader, false)

	return
}

const privateKeyArmoredStart = "-----BEGIN PGP PRIVATE KEY BLOCK-----"

// BuildKeyRingArmored reads armored string and returns keyring
func (pgp *GopenPGP) BuildKeyRingArmored(key string) (keyRing *KeyRing, err error) {
	toDecodeArmor := key
	privKeyIndex := strings.Index(toDecodeArmor, privateKeyArmoredStart)
	if privKeyIndex >= 0 {
		toDecodeArmor = toDecodeArmor[privKeyIndex:]
	}
	keyRaw, err := armorUtils.Unarmor(toDecodeArmor)
	if err != nil {
		return nil, err
	}
	keyReader := bytes.NewReader(keyRaw)
	keyEntries, err := openpgp.ReadKeyRing(keyReader)
	keyEntities := genDMSEntities(keyEntries)
	return &KeyRing{Entities: keyEntities}, err
}

func (pgp *GopenPGP) CombineKeyRing(keyRing1, keyRing2 *KeyRing) *KeyRing {
	var entities []*KeyEntity
	entities = append(entities, keyRing1.Entities...)
	entities = append(entities, keyRing2.Entities...)
	return &KeyRing{Entities: entities}
}

// KeyIds returns array of IDs of keys in this KeyRing.
func (keyRing *KeyRing) KeyIds() []int {
	var res []int
	for _, e := range keyRing.Entities {
		res = append(res, int(e.PrimaryKey.PublicKey.KeyId))
	}
	return res
}

// ReadArmoredKeyRing reads an armored data into keyring.
func ReadArmoredKeyRing(r io.Reader) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	err = keyRing.readFrom(r, true)
	return
}

// ReadKeyRing reads an binary data into keyring.
func ReadKeyRing(r io.Reader) (keyRing *KeyRing, err error) {
	keyRing = &KeyRing{}
	err = keyRing.readFrom(r, false)
	return
}

// FilterExpiredKeys takes a given KeyRing list and it returns only those
// KeyRings which contain at least, one unexpired Key. It returns only unexpired
// parts of these KeyRings.
func FilterExpiredKeys(contactKeys []*KeyRing) (filteredKeys []*KeyRing, err error) {
	now := time.Now()
	hasExpiredEntity := false
	filteredKeys = make([]*KeyRing, 0)

	for _, contactKeyRing := range contactKeys {
		keyRingHasUnexpiredEntity := false
		keyRingHasTotallyExpiredEntity := false
		for _, entity := range contactKeyRing.GetEntities() {
			hasExpired := false
			hasUnexpired := false
			for _, subkey := range entity.Subkeys {
				if subkey.PublicKey.KeyExpired(&subkey.Sig.Signature, now) {
					hasExpired = true
				} else {
					hasUnexpired = true
				}
			}
			if hasExpired && !hasUnexpired {
				keyRingHasTotallyExpiredEntity = true
			} else if hasUnexpired {
				keyRingHasUnexpiredEntity = true
			}
		}
		if keyRingHasUnexpiredEntity {
			filteredKeys = append(filteredKeys, contactKeyRing)
		} else if keyRingHasTotallyExpiredEntity {
			hasExpiredEntity = true
		}
	}

	if len(filteredKeys) == 0 && hasExpiredEntity {
		return filteredKeys, errors.New("gopenpgp: all contacts keys are expired")
	}

	return filteredKeys, nil
}

func genDMSEntities(rawEntities openpgp.EntityList) []*KeyEntity {
	var dmsEntities []*KeyEntity
	for _, e := range rawEntities {
		de := new(KeyEntity)
		de.PrimaryKey = &PublicKey{*e.PrimaryKey}

		if e.PrivateKey != nil {
			newPrivKey := new(PrivateKey)
			newPrivKey.PublicKey = PublicKey{e.PrivateKey.PublicKey}
			newPrivKey.PrivateKey = e.PrivateKey
			de.PrivateKey = newPrivKey
		}

		de.Identities = genIdentityList(e.Identities)

		var revocations []*Signature
		for _, re := range e.Revocations {
			revocations = append(revocations, &Signature{*re})
		}
		de.Revocations = revocations

		var subkeys []Subkey
		for _, sk := range e.Subkeys {
			newSubPubKey := &PublicKey{*sk.PublicKey}
			newSubPrivKey := new(PrivateKey)
			newSubPrivKey.PublicKey = *newSubPubKey
			newSubPrivKey.PrivateKey = sk.PrivateKey
			subkeys = append(subkeys, Subkey{newSubPubKey, newSubPrivKey, &Signature{*sk.Sig}})
		}
		de.Subkeys = subkeys

		dmsEntities = append(dmsEntities, de)
	}
	return dmsEntities
}

func main() {
	fmt.Println("Hello, DMSGoPGP!")
}
