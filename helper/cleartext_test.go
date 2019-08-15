package helper

import (
	"regexp"
	"testing"

	"github.com/DimensionDev/gopenpgp/crypto"

	"github.com/stretchr/testify/assert"
)

const signedPlainText = "Signed message\n"
const testTime = 1557754627 // 2019-05-13T13:37:07+00:00
var signedMessageTest = regexp.MustCompile(
	"(?s)^-----BEGIN PGP SIGNED MESSAGE-----.*-----BEGIN PGP SIGNATURE-----.*-----END PGP SIGNATURE-----$")

func TestSignClearText(t *testing.T) {
	// Password defined in base_test
	armored, err := SignCleartextMessageArmored(
		readTestFile("keyring_privateKey", false),
		testMailboxPassword,
		signedPlainText,
	)

	if err != nil {
		t.Fatal("Cannot armor message:", err)
	}

	assert.Regexp(t, signedMessageTest, armored)

	verified, err := VerifyCleartextMessageArmored(
		readTestFile("keyring_publicKey", false),
		armored,
		pgp.GetUnixTime(),
	)
	if err != nil {
		t.Fatal("Cannot verify message:", err)
	}

	assert.Exactly(t, canonicalizeAndTrim(signedPlainText), verified)
}

func TestSignWithGenerateKey(t *testing.T) {
	rsaKey, err := crypto.GetGopenPGP().GenerateKey("Alice", "Alice@gmail.com", "Alice", "rsa", 4096)
	if err != nil {
		t.Fatal("fail to generate key:", err)
	}

	keyRing, err := crypto.GetGopenPGP().BuildKeyRingArmored(rsaKey)
	if err != nil {
		t.Fatal("fail to generate key:", err)
	}

	keyRing.UnlockWithPassphrase("Alice")

	signTime := crypto.GetGopenPGP().GetUnixTime()
	message := "Clear Message"

	// signEntity, err := keyRing.GetSigningEntity()
	// armoredKey, err := signEntity.PrivateKey.GetArmored("", "")
	armoredPubKey, err := keyRing.GetArmoredPublicKey()
	armoredMessage, err := SignCleartextMessageArmored(rsaKey, "Alice", message)

	// armoredPubKey, err := signEntity.PrimaryKey.GetArmored("", "")
	result, err := VerifyCleartextMessageArmored(armoredPubKey, armoredMessage, signTime)
	print(result)
}

func TestMessageCanonicalizeAndTrim(t *testing.T) {
	text := "Hi  \ntest!\r\n\n"
	canon := canonicalizeAndTrim(text)
	assert.Exactly(t, "Hi\r\ntest!\r\n\r\n", canon)
}
