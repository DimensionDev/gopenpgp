package helper

import (
	"errors"

	"github.com/DimensionDev/gopenpgp/constants"
	"github.com/DimensionDev/gopenpgp/crypto"
)

var pgp = crypto.GetGopenPGP()

type EncryptedSignAttachment struct {
	KeyPacket  []byte
	DataPacket []byte
	Signature  []byte
}

// EncryptMessageWithToken encrypts a string with a passphrase using AES256
func EncryptMessageWithToken(
	passphrase, plaintext string,
) (ciphertext string, err error) {
	return EncryptMessageWithTokenAlgo(passphrase, plaintext, constants.AES256)
}

// EncryptMessageWithTokenAlgo encrypts a string with a random token and an algorithm chosen from constants.*
func EncryptMessageWithTokenAlgo(
	token, plaintext, algo string,
) (ciphertext string, err error) {
	var pgpMessage *crypto.PGPMessage

	var message = crypto.NewPlainMessageFromString(plaintext)
	var key = crypto.NewSymmetricKeyFromToken(token, algo)

	if pgpMessage, err = key.Encrypt(message); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

// DecryptMessageWithToken decrypts an armored message with a random token.
// The algorithm is derived from the armoring.
func DecryptMessageWithToken(token, ciphertext string) (plaintext string, err error) {
	var message *crypto.PlainMessage
	var pgpMessage *crypto.PGPMessage

	var key = crypto.NewSymmetricKeyFromToken(token, "")

	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if message, err = key.Decrypt(pgpMessage); err != nil {
		return "", err
	}

	return message.GetString(), nil
}

// EncryptMessageArmored generates an armored PGP message given a plaintext and an armored public key
// func EncryptMessageArmored(publicKey, plaintext string) (ciphertext string, err error) {
// 	var publicKeyRing *crypto.KeyRing
// 	var pgpMessage *crypto.PGPMessage

// 	var message = crypto.NewPlainMessageFromString(plaintext)

// 	if publicKeyRing, err = pgp.BuildKeyRingArmored(publicKey); err != nil {
// 		return "", err
// 	}

// 	if pgpMessage, err = publicKeyRing.Encrypt(message, nil); err != nil {
// 		return "", err
// 	}

// 	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
// 		return "", err
// 	}

// 	return ciphertext, nil
// }

func EncryptMessageArmored(publicKeyRing *crypto.KeyRing, plaintext string) (ciphertext string, err error) {
	var pgpMessage *crypto.PGPMessage

	var message = crypto.NewPlainMessageFromString(plaintext)

	if pgpMessage, err = publicKeyRing.Encrypt(message, nil); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

// EncryptSignMessageArmored generates an armored signed PGP message given a plaintext and an armored public key
// a private key and its passphrase
// func EncryptSignMessageArmored(
// 	publicKeyRing, privateKeyRing, passphrase, plaintext string,
// ) (ciphertext string, err error) {
// 	var publicKeyRing, privateKeyRing *crypto.KeyRing
// 	var pgpMessage *crypto.PGPMessage

// 	var message = crypto.NewPlainMessageFromString(plaintext)

// 	if publicKeyRing, err = pgp.BuildKeyRingArmored(publicKey); err != nil {
// 		return "", err
// 	}

// 	if privateKeyRing, err = pgp.BuildKeyRingArmored(privateKey); err != nil {
// 		return "", err
// 	}

// 	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
// 		return "", err
// 	}

// 	if pgpMessage, err = publicKeyRing.Encrypt(message, privateKeyRing); err != nil {
// 		return "", err
// 	}

// 	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
// 		return "", err
// 	}

// 	return ciphertext, nil
// }
func EncryptSignMessageArmored(
	publicKeyRing, privateKeyRing *crypto.KeyRing, passphrase, plaintext string,
) (ciphertext string, err error) {
	var pgpMessage *crypto.PGPMessage

	var message = crypto.NewPlainMessageFromString(plaintext)

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return "", err
	}

	if pgpMessage, err = publicKeyRing.Encrypt(message, privateKeyRing); err != nil {
		return "", err
	}

	if ciphertext, err = pgpMessage.GetArmored(); err != nil {
		return "", err
	}

	return ciphertext, nil
}

// DecryptMessageArmored decrypts an armored PGP message given a private key and its passphrase
// func DecryptMessageArmored(
// 	privateKey, passphrase, ciphertext string,
// ) (plaintext string, err error) {
// 	var privateKeyRing *crypto.KeyRing
// 	var pgpMessage *crypto.PGPMessage
// 	var message *crypto.PlainMessage

// 	if privateKeyRing, err = pgp.BuildKeyRingArmored(privateKey); err != nil {
// 		return "", err
// 	}

// 	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
// 		return "", err
// 	}

// 	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
// 		return "", err
// 	}

// 	if message, err = privateKeyRing.Decrypt(pgpMessage, nil, 0); err != nil {
// 		return "", err
// 	}

// 	return message.GetString(), nil
// }
func DecryptMessageArmored(
	privateKeyRing *crypto.KeyRing, passphrase, ciphertext string,
) (plaintext string, err error) {
	var pgpMessage *crypto.PGPMessage
	var message *crypto.PlainMessage

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return "", err
	}

	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if message, err = privateKeyRing.Decrypt(pgpMessage, nil, 0); err != nil {
		return "", err
	}

	return message.GetString(), nil
}

// DecryptVerifyMessageArmored decrypts an armored PGP message given a private key and its passphrase
// and verifies the embedded signature.
// Returns the plain data or an error on signature verification failure.
// func DecryptVerifyMessageArmored(
// 	publicKey, privateKey, passphrase, ciphertext string,
// ) (plaintext string, err error) {
// 	var publicKeyRing, privateKeyRing *crypto.KeyRing
// 	var pgpMessage *crypto.PGPMessage
// 	var message *crypto.PlainMessage

// 	if publicKeyRing, err = pgp.BuildKeyRingArmored(publicKey); err != nil {
// 		return "", err
// 	}

// 	if privateKeyRing, err = pgp.BuildKeyRingArmored(privateKey); err != nil {
// 		return "", err
// 	}

// 	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
// 		return "", err
// 	}

// 	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
// 		return "", err
// 	}

// 	if message, err = privateKeyRing.Decrypt(pgpMessage, publicKeyRing, pgp.GetUnixTime()); err != nil {
// 		return "", err
// 	}

// 	return message.GetString(), nil
// }
func DecryptVerifyMessageArmored(
	publicKeyRing, privateKeyRing *crypto.KeyRing, passphrase, ciphertext string,
) (plaintext string, err error) {
	var pgpMessage *crypto.PGPMessage
	var message *crypto.PlainMessage

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return "", err
	}

	if pgpMessage, err = crypto.NewPGPMessageFromArmored(ciphertext); err != nil {
		return "", err
	}

	if message, err = privateKeyRing.Decrypt(pgpMessage, publicKeyRing, pgp.GetUnixTime()); err != nil {
		return "", err
	}

	return message.GetString(), nil
}

// EncryptSignAttachment encrypts an attachment using a detached signature, given a publicKey, a privateKey
// and its passphrase, the filename, and the unencrypted file data.
// Returns keypacket, dataPacket and unarmored (!) signature separate.
func EncryptSignAttachment(
	publicKeyRing, privateKeyRing *crypto.KeyRing, passphrase, fileName string,
	plainData []byte,
) (encryptedSignAttachment *EncryptedSignAttachment, err error) {
	var packets *crypto.PGPSplitMessage
	var signatureObj *crypto.PGPSignature

	var binMessage = crypto.NewPlainMessage(plainData)

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return nil, err
	}

	if packets, err = publicKeyRing.EncryptAttachment(binMessage, fileName); err != nil {
		return nil, err
	}

	if signatureObj, err = privateKeyRing.SignDetached(binMessage); err != nil {
		return nil, err
	}

	return &EncryptedSignAttachment{
		KeyPacket:  packets.GetKeyPacket(),
		DataPacket: packets.GetDataPacket(),
		Signature:  signatureObj.GetBinary(),
	}, nil
}

// DecryptVerifyAttachment decrypts and verifies an attachment split into the keyPacket, dataPacket
// and an armored (!) signature, given a publicKey, and a privateKey with its passphrase.
// Returns the plain data or an error on signature verification failure.
func DecryptVerifyAttachment(
	publicKeyRing, privateKeyRing *crypto.KeyRing, passphrase string,
	keyPacket, dataPacket []byte,
	armoredSignature string,
) (plainData []byte, err error) {
	var detachedSignature *crypto.PGPSignature
	var message *crypto.PlainMessage

	var packets = crypto.NewPGPSplitMessage(keyPacket, dataPacket)

	if err = privateKeyRing.UnlockWithPassphrase(passphrase); err != nil {
		return nil, err
	}

	if detachedSignature, err = crypto.NewPGPSignatureFromArmored(armoredSignature); err != nil {
		return nil, err
	}

	if message, err = privateKeyRing.DecryptAttachment(packets); err != nil {
		return nil, err
	}

	if publicKeyRing.VerifyDetached(message, detachedSignature, pgp.GetUnixTime()) != nil {
		return nil, errors.New("gopenpgp: unable to verify attachment")
	}

	return message.GetBinary(), nil
}
