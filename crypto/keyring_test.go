package crypto

import (
	"encoding/base64"
	"io/ioutil"
	"strings"
	"testing"

	"golang.org/x/crypto/openpgp/armor"

	"github.com/DimensionDev/gopenpgp/constants"
	"github.com/stretchr/testify/assert"
)

var decodedSymmetricKey, _ = base64.StdEncoding.DecodeString("ExXmnSiQ2QCey20YLH6qlLhkY3xnIBC1AwlIXwK/HvY=")

var testSymmetricKey = &SymmetricKey{
	Key:  decodedSymmetricKey,
	Algo: constants.AES256,
}

var testWrongSymmetricKey = &SymmetricKey{
	Key:  []byte("WrongPass"),
	Algo: constants.AES256,
}

// Corresponding key in testdata/keyring_privateKey
const testMailboxPassword = "apple"

// Corresponding key in testdata/keyring_privateKeyLegacy
// const testMailboxPasswordLegacy = "123"

var (
	testPrivateKeyRing *KeyRing
	testPublicKeyRing  *KeyRing
)

// var testIdentity = &Identity{
// 	Name:  "UserID",
// 	Email: "",
// }

func init() {
	var err error

	testPrivateKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	if err != nil {
		panic(err)
	}

	testPublicKeyRing, err = ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_publicKey", false)))
	if err != nil {
		panic(err)
	}

	err = testPrivateKeyRing.UnlockWithPassphrase(testMailboxPassword)
	if err != nil {
		panic(err)
	}
}

func TestKeyRing_ArmoredPublicKeyString(t *testing.T) {

	dmsPrivKeyRing, err := ReadArmoredKeyRing(strings.NewReader(readTestFile("dms_privKey", false)))
	privPubkey, err := dmsPrivKeyRing.GetArmoredPublicKey()
	dmsPrivKeyRing.UnlockWithPassphrase("RSA")
	print(privPubkey)

	dmsKeyPairRing, err := ReadArmoredKeyRing(strings.NewReader(readTestFile("dms_keyPair", false)))
	keypairPubkey, err := dmsKeyPairRing.GetArmoredPublicKey()
	print(keypairPubkey)

	dmsPubKeyRing, err := ReadArmoredKeyRing(strings.NewReader(readTestFile("dms_pubkey", false)))
	pppkey, err := dmsPubKeyRing.GetArmoredPublicKey()
	print(pppkey)
	if err != nil {
		panic(err)
	}

	s, err := testPrivateKeyRing.GetArmoredPublicKey()
	if err != nil {
		t.Fatal("Expected no error while getting armored public key, got:", err)
	}

	// Decode armored keys
	block, err := armor.Decode(strings.NewReader(s))
	if err != nil {
		t.Fatal("Expected no error while decoding armored public key, got:", err)
	}

	expected, err := armor.Decode(strings.NewReader(readTestFile("keyring_publicKey", false)))
	if err != nil {
		t.Fatal("Expected no error while decoding expected armored public key, got:", err)
	}

	assert.Exactly(t, expected.Type, block.Type)

	b, err := ioutil.ReadAll(block.Body)
	if err != nil {
		t.Fatal("Expected no error while reading armored public key body, got:", err)
	}

	eb, err := ioutil.ReadAll(expected.Body)
	if err != nil {
		t.Fatal("Expected no error while reading expected armored public key body, got:", err)
	}

	assert.Exactly(t, eb, b)
}

func TestCheckPassphrase(t *testing.T) {
	encryptedKeyRing, _ := ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_privateKey", false)))
	isCorrect := encryptedKeyRing.CheckPassphrase("Wrong password")
	assert.Exactly(t, false, isCorrect)

	isCorrect = encryptedKeyRing.CheckPassphrase(testMailboxPassword)
	assert.Exactly(t, true, isCorrect)
}

func TestIdentities(t *testing.T) {
	identities := testPrivateKeyRing.Entities[0].Identities
	assert.Len(t, identities, 1)
	assert.Exactly(t, identities[0].Name, "UserID")
	assert.Exactly(t, identities[0].UserId.Email, "")
}

func TestFilterExpiredKeys(t *testing.T) {
	expiredKey, _ := ReadArmoredKeyRing(strings.NewReader(readTestFile("key_expiredKey", false)))
	keys := []*KeyRing{testPrivateKeyRing, expiredKey}
	unexpired, err := FilterExpiredKeys(keys)

	if err != nil {
		t.Fatal("Expected no error while filtering expired keyrings, got:", err)
	}

	assert.Len(t, unexpired, 1)
	assert.Exactly(t, unexpired[0], testPrivateKeyRing)
}

func TestGetPublicKey(t *testing.T) {
	publicKey, err := testPrivateKeyRing.GetPublicKey()
	if err != nil {
		t.Fatal("Expected no error while obtaining public key, got:", err)
	}

	publicKeyRing, err := pgp.BuildKeyRing(publicKey)
	if err != nil {
		t.Fatal("Expected no error while creating public key ring, got:", err)
	}

	privateFingerprint, err := testPrivateKeyRing.GetFingerprint()
	if err != nil {
		t.Fatal("Expected no error while extracting private fingerprint, got:", err)
	}

	publicFingerprint, err := publicKeyRing.GetFingerprint()
	if err != nil {
		t.Fatal("Expected no error while extracting public fingerprint, got:", err)
	}

	assert.Exactly(t, privateFingerprint, publicFingerprint)
}

func TestKeyIds(t *testing.T) {
	keyIDs := testPrivateKeyRing.KeyIds()
	var assertKeyIDs = []int{4518840640391470884}
	assert.Exactly(t, assertKeyIDs, keyIDs)
}

func TestCombineKeyRings(t *testing.T) {
	entityCount1 := len(testPrivateKeyRing.Entities)
	entityCount2 := len(testPublicKeyRing.Entities)
	combinedKeyRing := pgp.CombineKeyRing(testPrivateKeyRing, testPublicKeyRing)
	assert.Equal(t, len(combinedKeyRing.Entities), entityCount1+entityCount2)
}

// func TestReadFromJson(t *testing.T) {
// 	decodedKeyRing := &KeyRing{}
// 	err = decodedKeyRing.ReadFromJSON([]byte(readTestFile("keyring_jsonKeys", false)))
// 	if err != nil {
// 		t.Fatal("Expected no error while reading JSON, got:", err)
// 	}

// 	fingerprint, err := decodedKeyRing.GetFingerprint()
// 	if err != nil {
// 		t.Fatal("Expected no error while extracting fingerprint, got:", err)
// 	}

// 	assert.Exactly(t, "91eacacca6837890efa7000470e569d5c182bef6", fingerprint)
// }

// func TestUnlockJson(t *testing.T) {
// 	userKeyRing, err := ReadArmoredKeyRing(strings.NewReader(readTestFile("keyring_userKey", false)))
// 	if err != nil {
// 		t.Fatal("Expected no error while creating keyring, got:", err)
// 	}

// 	err = userKeyRing.UnlockWithPassphrase("testpassphrase")
// 	if err != nil {
// 		t.Fatal("Expected no error while creating keyring, got:", err)
// 	}

// 	addressKeyRing, err := userKeyRing.UnlockJSONKeyRing([]byte(readTestFile("keyring_newJSONKeys", false)))
// 	if err != nil {
// 		t.Fatal("Expected no error while reading and decrypting JSON, got:", err)
// 	}

// 	for _, e := range addressKeyRing.Entities {
// 		assert.Exactly(t, false, e.PrivateKey.PrivateKey.Encrypted)
// 	}
// }
