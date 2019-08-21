package helper

import (
	"testing"

	"github.com/DimensionDev/gopenpgp/crypto"
	"github.com/stretchr/testify/assert"
)

func TestAESEncryption(t *testing.T) {
	var plaintext = "Symmetric secret"
	var passphrase = "passphrase"

	ciphertext, err := EncryptMessageWithToken(passphrase, plaintext)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	_, err = DecryptMessageWithToken("Wrong passphrase", ciphertext)
	assert.EqualError(t, err, "gopenpgp: wrong password in symmetric decryption")

	decrypted, err := DecryptMessageWithToken(passphrase, ciphertext)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestArmoredTextMessageEncryption(t *testing.T) {
	var plaintext = "Secret message"

	publicKeyRing, err := pgp.BuildKeyRingArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	armored, err := EncryptMessageArmored(publicKeyRing, plaintext)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, pgp.IsPGPMessage(armored))

	privateKeyRing, err := pgp.BuildKeyRingArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	decrypted, err := DecryptMessageArmored(
		privateKeyRing,
		testMailboxPassword, // Password defined in base_test
		armored,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestArmoredTextMessageEncryptionVerification(t *testing.T) {
	var plaintext = "Secret message"

	keyring_publicKey, err := pgp.BuildKeyRingArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	keyring_privateKey, err := pgp.BuildKeyRingArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	armored, err := EncryptSignMessageArmored(
		keyring_publicKey,
		keyring_privateKey,
		testMailboxPassword, // Password defined in base_test
		plaintext,
	)
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	assert.Exactly(t, true, pgp.IsPGPMessage(armored))

	testMessage, err := crypto.NewPGPMessageFromArmored(armored)
	//keyring_privateKey.UnlockWithPassphrase(testMailboxPassword)
	detail, err := testMessage.GetMessageDetails(keyring_privateKey)
	print(detail.EncryptedToKeyIds)

	mime_publicKey, err := pgp.BuildKeyRingArmored(readTestFile("mime_publicKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	_, err = DecryptVerifyMessageArmored(
		mime_publicKey, // Wrong public key
		keyring_privateKey,
		testMailboxPassword, // Password defined in base_test
		armored,
	)
	assert.EqualError(t, err, "Signature Verification Error: No matching signature")

	decrypted, err := DecryptVerifyMessageArmored(
		keyring_publicKey,
		keyring_privateKey,
		testMailboxPassword, // Password defined in base_test
		armored,
	)

	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, plaintext, decrypted)
}

func TestAttachmentEncryptionVerification(t *testing.T) {
	var attachment = []byte("Secret file\r\nRoot password:hunter2")

	keyring_publicKey, err := pgp.BuildKeyRingArmored(readTestFile("keyring_publicKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	keyring_privateKey, err := pgp.BuildKeyRingArmored(readTestFile("keyring_privateKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	enctypedSignAttachmentData, err := EncryptSignAttachment(
		keyring_publicKey,
		keyring_privateKey,
		testMailboxPassword, // Password defined in base_test
		"password.txt",
		attachment,
	)
	// keyPacket, dataPacket, signature, err := EncryptSignAttachment(
	// 	readTestFile("keyring_publicKey", false),
	// 	readTestFile("keyring_privateKey", false),
	// 	testMailboxPassword, // Password defined in base_test
	// 	"password.txt",
	// 	attachment,
	// )
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}

	sig := crypto.NewPGPSignature(enctypedSignAttachmentData.Signature)
	armoredSig, err := sig.GetArmored()
	if err != nil {
		t.Fatal("Expected no error when armoring signature, got:", err)
	}

	mime_publicKey, err := pgp.BuildKeyRingArmored(readTestFile("mime_publicKey", false))
	if err != nil {
		t.Fatal("Expected no error when encrypting, got:", err)
	}
	_, err = DecryptVerifyAttachment(
		mime_publicKey, // Wrong public key
		keyring_privateKey,
		testMailboxPassword, // Password defined in base_test
		enctypedSignAttachmentData.KeyPacket,
		enctypedSignAttachmentData.DataPacket,
		armoredSig,
	)
	assert.EqualError(t, err, "gopenpgp: unable to verify attachment")

	decrypted, err := DecryptVerifyAttachment(
		keyring_publicKey,
		keyring_privateKey,
		testMailboxPassword, // Password defined in base_test
		enctypedSignAttachmentData.KeyPacket,
		enctypedSignAttachmentData.DataPacket,
		armoredSig,
	)
	if err != nil {
		t.Fatal("Expected no error when decrypting, got:", err)
	}

	assert.Exactly(t, attachment, decrypted)
}
