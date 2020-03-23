// Objective-C API for talking to github.com/DimensionDev/gopenpgp/crypto Go package.
//   gobind -lang=objc github.com/DimensionDev/gopenpgp/crypto
//
// File is generated by gobind. Do not edit.

#ifndef __Crypto_H__
#define __Crypto_H__

@import Foundation;
#include "ref.h"
#include "Universe.objc.h"

#include "Armor.objc.h"
#include "Constants.objc.h"

@class CryptoAttachmentProcessor;
@class CryptoClearTextMessage;
@class CryptoGopenPGP;
@class CryptoIdentity;
@class CryptoKeyEntity;
@class CryptoKeyRing;
@class CryptoMessageDetail;
@class CryptoPGPMessage;
@class CryptoPGPSignature;
@class CryptoPGPSplitMessage;
@class CryptoPlainMessage;
@class CryptoPrivateKey;
@class CryptoPublicKey;
@class CryptoSignature;
@class CryptoSignatureCollector;
@class CryptoSignatureVerificationError;
@class CryptoSubkey;
@class CryptoSymmetricKey;
@class CryptoUserId;
@protocol CryptoMIMECallbacks;
@class CryptoMIMECallbacks;

@protocol CryptoMIMECallbacks <NSObject>
- (void)onAttachment:(NSString* _Nullable)headers data:(NSData* _Nullable)data;
- (void)onBody:(NSString* _Nullable)body mimetype:(NSString* _Nullable)mimetype;
- (void)onEncryptedHeaders:(NSString* _Nullable)headers;
- (void)onError:(NSError* _Nullable)err;
- (void)onVerified:(long)verified;
@end

/**
 * AttachmentProcessor keeps track of the progress of encrypting an attachment
(optimized for encrypting large files).
 */
@interface CryptoAttachmentProcessor : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
/**
 * Finish closes the attachment and returns the encrypted data
 */
- (CryptoPGPSplitMessage* _Nullable)finish:(NSError* _Nullable* _Nullable)error;
/**
 * Process writes attachment data to be encrypted
 */
- (void)process:(NSData* _Nullable)plainData;
@end

/**
 * ClearTextMessage, split signed clear text message container
 */
@interface CryptoClearTextMessage : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewClearTextMessage generates a new ClearTextMessage from data and signature
 */
- (nullable instancetype)init:(NSData* _Nullable)data signature:(NSData* _Nullable)signature;
/**
 * NewClearTextMessageFromArmored returns the message body and unarmored signature from a clearsigned message.
 */
- (nullable instancetype)initFromArmored:(NSString* _Nullable)signedMessage;
@property (nonatomic) NSData* _Nullable data;
/**
 * GetArmored armors plaintext and signature with the PGP SIGNED MESSAGE armoring
 */
- (NSString* _Nonnull)getArmored:(NSError* _Nullable* _Nullable)error;
/**
 * GetBinary returns the unarmored signed data as a []byte
 */
- (NSData* _Nullable)getBinary;
- (CryptoMessageDetail* _Nullable)getMessageDetails:(CryptoKeyRing* _Nullable)keyRing error:(NSError* _Nullable* _Nullable)error;
/**
 * GetSignature returns the unarmored binary signature as a []byte
 */
- (NSData* _Nullable)getSignature;
/**
 * GetString returns the unarmored signed data as a string
 */
- (NSString* _Nonnull)getString;
@end

/**
 * GopenPGP is used as a "namespace" for many of the functions in this package.
It is a struct that keeps track of time skew between server and client.
 */
@interface CryptoGopenPGP : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
/**
 * BuildKeyRing reads keyring from binary data
 */
- (CryptoKeyRing* _Nullable)buildKeyRing:(NSData* _Nullable)binKeys error:(NSError* _Nullable* _Nullable)error;
/**
 * BuildKeyRingArmored reads armored string and returns keyring
 */
- (CryptoKeyRing* _Nullable)buildKeyRingArmored:(NSString* _Nullable)key error:(NSError* _Nullable* _Nullable)error;
- (CryptoKeyRing* _Nullable)combineKeyRing:(CryptoKeyRing* _Nullable)keyRing1 keyRing2:(CryptoKeyRing* _Nullable)keyRing2;
/**
 * GenerateKey generates a key of the given keyType ("rsa" or "x25519").
If keyType is "rsa", bits is the RSA bitsize of the key.
If keyType is "x25519" bits is unused.
 */
- (NSString* _Nonnull)generateKey:(NSString* _Nullable)name email:(NSString* _Nullable)email passphrase:(NSString* _Nullable)passphrase keyType:(NSString* _Nullable)keyType bits:(long)bits error:(NSError* _Nullable* _Nullable)error;
/**
 * GenerateRSAKeyWithPrimes generates a RSA key using the given primes.
 */
- (NSString* _Nonnull)generateRSAKeyWithPrimes:(NSString* _Nullable)name email:(NSString* _Nullable)email passphrase:(NSString* _Nullable)passphrase bits:(long)bits primeone:(NSData* _Nullable)primeone primetwo:(NSData* _Nullable)primetwo primethree:(NSData* _Nullable)primethree primefour:(NSData* _Nullable)primefour error:(NSError* _Nullable* _Nullable)error;
// skipped method GopenPGP.GetTime with unsupported parameter or return types

/**
 * GetUnixTime gets latest cached time
 */
- (int64_t)getUnixTime;
/**
 * IsArmoredKeyExpired checks whether the given armored key is expired.
 */
- (BOOL)isArmoredKeyExpired:(NSString* _Nullable)publicKey ret0_:(BOOL* _Nullable)ret0_ error:(NSError* _Nullable* _Nullable)error;
/**
 * IsKeyExpired checks whether the given (unarmored, binary) key is expired.
 */
- (BOOL)isKeyExpired:(NSData* _Nullable)publicKey ret0_:(BOOL* _Nullable)ret0_ error:(NSError* _Nullable* _Nullable)error;
/**
 * IsPGPMessage checks if data if has armored PGP message format.
 */
- (BOOL)isPGPMessage:(NSString* _Nullable)data;
/**
 * PrintFingerprints is a debug helper function that prints the key and subkey fingerprints.
 */
- (NSString* _Nonnull)printFingerprints:(NSString* _Nullable)pubKey error:(NSError* _Nullable* _Nullable)error;
/**
 * RandomToken generated a random token of the same size of the keysize of the default cipher.
 */
- (NSData* _Nullable)randomToken:(NSError* _Nullable* _Nullable)error;
/**
 * RandomTokenSize generates a random token with the specified key size
 */
- (NSData* _Nullable)randomTokenSize:(long)size error:(NSError* _Nullable* _Nullable)error;
/**
 * UpdatePrivateKeyPassphrase decrypts the given armored privateKey with oldPassphrase,
re-encrypts it with newPassphrase, and returns the new armored key.
 */
- (NSString* _Nonnull)updatePrivateKeyPassphrase:(NSString* _Nullable)privateKey oldPassphrase:(NSString* _Nullable)oldPassphrase newPassphrase:(NSString* _Nullable)newPassphrase error:(NSError* _Nullable* _Nullable)error;
/**
 * UpdateTime updates cached time
 */
- (void)updateTime:(int64_t)newTime;
@end

@interface CryptoIdentity : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) NSString* _Nonnull name;
@property (nonatomic) CryptoUserId* _Nullable userId;
@property (nonatomic) CryptoSignature* _Nullable selfSignature;
// skipped field Identity.Signatures with unsupported type: []*github.com/DimensionDev/gopenpgp/crypto.Signature

- (BOOL)isPrimaryId;
@end

@interface CryptoKeyEntity : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) CryptoPublicKey* _Nullable primaryKey;
@property (nonatomic) CryptoPrivateKey* _Nullable privateKey;
// skipped field KeyEntity.Identities with unsupported type: []*github.com/DimensionDev/gopenpgp/crypto.Identity

// skipped field KeyEntity.Revocations with unsupported type: []*github.com/DimensionDev/gopenpgp/crypto.Signature

// skipped field KeyEntity.Subkeys with unsupported type: []github.com/DimensionDev/gopenpgp/crypto.Subkey

- (CryptoIdentity* _Nullable)getIdentity:(long)index error:(NSError* _Nullable* _Nullable)error;
- (long)getIdentityCount;
- (CryptoSubkey* _Nullable)getSubkey:(long)index error:(NSError* _Nullable* _Nullable)error;
- (long)getSubkeyCount;
// skipped method KeyEntity.Serialize with unsupported parameter or return types

@end

@interface CryptoKeyRing : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * Creates a new KeyRing with empty key entities
 */
- (nullable instancetype)init;
// skipped field KeyRing.Entities with unsupported type: []*github.com/DimensionDev/gopenpgp/crypto.KeyEntity

/**
 * Add key entity to keyring
 */
- (BOOL)addKeyEntity:(CryptoKeyEntity* _Nullable)keyEntity error:(NSError* _Nullable* _Nullable)error;
/**
 * CheckPassphrase checks if private key passphrase is correct for every sub key.
 */
- (BOOL)checkPassphrase:(NSString* _Nullable)passphrase;
/**
 * Decrypt decrypts encrypted string using pgp keys, returning a PlainMessage
message    : The encrypted input as a PGPMessage
verifyKey  : Public key for signature verification (optional)
verifyTime : Time at verification (necessary only if verifyKey is not nil)
 */
- (CryptoPlainMessage* _Nullable)decrypt:(CryptoPGPMessage* _Nullable)message verifyKey:(CryptoKeyRing* _Nullable)verifyKey verifyTime:(int64_t)verifyTime error:(NSError* _Nullable* _Nullable)error;
- (CryptoPlainMessage* _Nullable)decryptAttachment:(CryptoPGPSplitMessage* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
/**
 * DecryptMIMEMessage decrypts a MIME message.
 */
- (void)decryptMIMEMessage:(CryptoPGPMessage* _Nullable)message verifyKey:(CryptoKeyRing* _Nullable)verifyKey callbacks:(id<CryptoMIMECallbacks> _Nullable)callbacks verifyTime:(int64_t)verifyTime;
/**
 * DecryptSessionKey returns the decrypted session key from a binary encrypted session key packet.
 */
- (CryptoSymmetricKey* _Nullable)decryptSessionKey:(NSData* _Nullable)keyPacket error:(NSError* _Nullable* _Nullable)error;
/**
 * Encrypt encrypts a PlainMessage, outputs a PGPMessage.
If an unlocked private key is also provided it will also sign the message.
message    : The plaintext input as a PlainMessage
privateKey : (optional) an unlocked private keyring to include signature in the message
 */
- (CryptoPGPMessage* _Nullable)encrypt:(CryptoPlainMessage* _Nullable)message privateKey:(CryptoKeyRing* _Nullable)privateKey error:(NSError* _Nullable* _Nullable)error;
- (CryptoPGPSplitMessage* _Nullable)encryptAttachment:(CryptoPlainMessage* _Nullable)message fileName:(NSString* _Nullable)fileName error:(NSError* _Nullable* _Nullable)error;
/**
 * EncryptSessionKey encrypts the session key with the unarmored
publicKey and returns a binary public-key encrypted session key packet.
 */
- (NSData* _Nullable)encryptSessionKey:(CryptoSymmetricKey* _Nullable)sessionSplit error:(NSError* _Nullable* _Nullable)error;
- (NSString* _Nonnull)getArmored:(NSString* _Nullable)passphrase error:(NSError* _Nullable* _Nullable)error;
/**
 * GetArmoredPublicKey returns the armored public keys from this keyring.
 */
- (NSString* _Nonnull)getArmoredPublicKey:(NSError* _Nullable* _Nullable)error;
- (CryptoPublicKey* _Nullable)getEncryptionKey:(NSError* _Nullable* _Nullable)error;
// skipped method KeyRing.GetEntities with unsupported parameter or return types

- (long)getEntitiesCount;
- (CryptoKeyEntity* _Nullable)getEntity:(long)index error:(NSError* _Nullable* _Nullable)error;
/**
 * GetFingerprint gets the fingerprint from the keyring.
 */
- (NSString* _Nonnull)getFingerprint:(NSError* _Nullable* _Nullable)error;
/**
 * GetPublicKey returns the unarmored public keys from this keyring.
 */
- (NSData* _Nullable)getPublicKey:(NSError* _Nullable* _Nullable)error;
/**
 * GetSigningEntity returns first private unlocked signing entity from keyring.
 */
- (CryptoKeyEntity* _Nullable)getSigningEntity:(NSError* _Nullable* _Nullable)error;
// skipped method KeyRing.KeyIds with unsupported parameter or return types

- (CryptoAttachmentProcessor* _Nullable)newLowMemoryAttachmentProcessor:(long)estimatedSize fileName:(NSString* _Nullable)fileName error:(NSError* _Nullable* _Nullable)error;
/**
 * SignDetached generates and returns a PGPSignature for a given PlainMessage
 */
- (CryptoPGPSignature* _Nullable)signDetached:(CryptoPlainMessage* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
/**
 * Unlock tries to unlock as many keys as possible with the following password. Note
that keyrings can contain keys locked with different passwords, and thus
err == nil does not mean that all keys have been successfully decrypted.
If err != nil, the password is wrong for every key, and err is the last error
encountered.
 */
- (BOOL)unlock:(NSData* _Nullable)passphrase error:(NSError* _Nullable* _Nullable)error;
/**
 * UnlockWithPassphrase is a wrapper for Unlock that uses strings
 */
- (BOOL)unlockWithPassphrase:(NSString* _Nullable)passphrase error:(NSError* _Nullable* _Nullable)error;
/**
 * VerifyDetached verifies a PlainMessage with embedded a PGPSignature
and returns a SignatureVerificationError if fails
 */
- (BOOL)verifyDetached:(CryptoPlainMessage* _Nullable)message signature:(CryptoPGPSignature* _Nullable)signature verifyTime:(int64_t)verifyTime error:(NSError* _Nullable* _Nullable)error;
// skipped method KeyRing.WriteArmoredPublicKey with unsupported parameter or return types

// skipped method KeyRing.WritePublicKey with unsupported parameter or return types

@end

@interface CryptoMessageDetail : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) BOOL isEncrypted;
// skipped field MessageDetail.EncryptedToKeyIds with unsupported type: []string

@property (nonatomic) BOOL isSymmetricallyEncrypted;
@property (nonatomic) BOOL isSigned;
@property (nonatomic) NSString* _Nonnull signedByKeyId;
- (NSString* _Nonnull)getEncryptedToKeyId:(long)index error:(NSError* _Nullable* _Nullable)error;
- (long)getEncryptedToKeyIdsCount;
- (NSString* _Nonnull)getSignedUserID;
@end

/**
 * PGPMessage stores a PGP-encrypted message.
 */
@interface CryptoPGPMessage : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewPGPMessage generates a new PGPMessage from the unarmored binary data.
 */
- (nullable instancetype)init:(NSData* _Nullable)data;
/**
 * NewPGPMessageFromArmored generates a new PGPMessage from an armored string ready for decryption.
 */
- (nullable instancetype)initFromArmored:(NSString* _Nullable)armored;
/**
 * The content of the message
 */
@property (nonatomic) NSData* _Nullable data;
/**
 * GetArmored returns the armored message as a string
 */
- (NSString* _Nonnull)getArmored:(NSError* _Nullable* _Nullable)error;
/**
 * GetBinary returns the unarmored binary content of the message as a []byte
 */
- (NSData* _Nullable)getBinary;
- (CryptoMessageDetail* _Nullable)getMessageDetails:(CryptoKeyRing* _Nullable)keyRing error:(NSError* _Nullable* _Nullable)error;
// skipped method PGPMessage.NewReader with unsupported parameter or return types

/**
 * SeparateKeyAndData returns the first keypacket and the (hopefully unique) dataPacket (not verified)
 */
- (CryptoPGPSplitMessage* _Nullable)separateKeyAndData:(long)estimatedLength garbageCollector:(long)garbageCollector error:(NSError* _Nullable* _Nullable)error;
@end

/**
 * PGPSignature stores a PGP-encoded detached signature.
 */
@interface CryptoPGPSignature : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewPGPSignature generates a new PGPSignature from the unarmored binary data.
 */
- (nullable instancetype)init:(NSData* _Nullable)data;
/**
 * NewPGPSignatureFromArmored generates a new PGPSignature from the armored string ready for verification.
 */
- (nullable instancetype)initFromArmored:(NSString* _Nullable)armored;
/**
 * The content of the signature
 */
@property (nonatomic) NSData* _Nullable data;
/**
 * GetArmored returns the armored signature as a string
 */
- (NSString* _Nonnull)getArmored:(NSError* _Nullable* _Nullable)error;
/**
 * GetBinary returns the unarmored binary content of the signature as a []byte
 */
- (NSData* _Nullable)getBinary;
@end

/**
 * PGPSplitMessage contains a separate session key packet and symmetrically
encrypted data packet.
 */
@interface CryptoPGPSplitMessage : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewPGPSplitMessage generates a new PGPSplitMessage from the binary unarmored keypacket,
datapacket, and encryption algorithm.
 */
- (nullable instancetype)init:(NSData* _Nullable)keyPacket dataPacket:(NSData* _Nullable)dataPacket;
/**
 * NewPGPSplitMessageFromArmored generates a new PGPSplitMessage by splitting an armored message into its
session key packet and symmetrically encrypted data packet.
 */
- (nullable instancetype)initFromArmored:(NSString* _Nullable)encrypted;
/**
 * GetDataPacket returns the unarmored binary datapacket as a []byte
 */
- (NSData* _Nullable)getDataPacket;
/**
 * GetKeyPacket returns the unarmored binary keypacket as a []byte
 */
- (NSData* _Nullable)getKeyPacket;
@end

/**
 * PlainMessage stores an unencrypted message.
 */
@interface CryptoPlainMessage : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewPlainMessage generates a new binary PlainMessage ready for encryption,
signature, or verification from the unencrypted binary data.
 */
- (nullable instancetype)init:(NSData* _Nullable)data;
/**
 * NewPlainMessageFromString generates a new text PlainMessage,
ready for encryption, signature, or verification from an unencrypted string.
 */
- (nullable instancetype)initFromString:(NSString* _Nullable)text;
/**
 * The content of the message
 */
@property (nonatomic) NSData* _Nullable data;
/**
 * if the content is text or binary
 */
@property (nonatomic) BOOL textType;
/**
 * GetBase64 returns the base-64 encoded binary content of the message as a string
 */
- (NSString* _Nonnull)getBase64;
/**
 * GetBinary returns the binary content of the message as a []byte
 */
- (NSData* _Nullable)getBinary;
- (CryptoMessageDetail* _Nullable)getMessageDetails:(CryptoKeyRing* _Nullable)keyRing error:(NSError* _Nullable* _Nullable)error;
/**
 * GetString returns the content of the message as a string
 */
- (NSString* _Nonnull)getString;
/**
 * IsBinary returns whether the message is a binary message
 */
- (BOOL)isBinary;
/**
 * IsText returns whether the message is a text message
 */
- (BOOL)isText;
// skipped method PlainMessage.NewReader with unsupported parameter or return types

@end

@interface CryptoPrivateKey : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field PrivateKey.PublicKey with unsupported type: github.com/DimensionDev/gopenpgp/crypto.PublicKey

// skipped field PrivateKey.PrivateKey with unsupported type: *golang.org/x/crypto/openpgp/packet.PrivateKey

- (BOOL)decrypt:(NSData* _Nullable)passphrase error:(NSError* _Nullable* _Nullable)error;
- (BOOL)encrypt:(NSData* _Nullable)passphrase error:(NSError* _Nullable* _Nullable)error;
- (long)getAlgorithm;
- (NSString* _Nonnull)getArmored:(NSString* _Nullable)headerKey headerValue:(NSString* _Nullable)headerValue error:(NSError* _Nullable* _Nullable)error;
- (BOOL)getBitLength:(long* _Nullable)ret0_ error:(NSError* _Nullable* _Nullable)error;
- (long)getCreationTimestamp;
- (BOOL)getEncrypted;
- (NSString* _Nonnull)getFingerprint;
- (NSString* _Nonnull)getKeyId;
- (NSString* _Nonnull)keyIdShortString;
- (NSString* _Nonnull)keyIdString;
// skipped method PrivateKey.Serialize with unsupported parameter or return types

// skipped method PrivateKey.SerializeEncrypted with unsupported parameter or return types

// skipped method PrivateKey.SerializeUnEncrypted with unsupported parameter or return types

@end

@interface CryptoPublicKey : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field PublicKey.PublicKey with unsupported type: golang.org/x/crypto/openpgp/packet.PublicKey

// skipped method PublicKey.BitLength with unsupported parameter or return types

- (BOOL)canSign;
- (long)getAlgorithm;
- (NSString* _Nonnull)getArmored:(NSString* _Nullable)headerKey headerValue:(NSString* _Nullable)headerValue error:(NSError* _Nullable* _Nullable)error;
- (BOOL)getBitLength:(long* _Nullable)ret0_ error:(NSError* _Nullable* _Nullable)error;
- (long)getCreationTimestamp;
- (NSString* _Nonnull)getFingerprint;
- (NSString* _Nonnull)getKeyId;
// skipped method PublicKey.KeyExpired with unsupported parameter or return types

/**
 * KeyIdShortString returns the short form of public key's fingerprint
in capital hex, as shown by gpg --list-keys (e.g. "621CC013").
 */
- (NSString* _Nonnull)keyIdShortString;
/**
 * KeyIdString returns the public key's fingerprint in capital hex
(e.g. "6C7EE1B8621CC013").
 */
- (NSString* _Nonnull)keyIdString;
// skipped method PublicKey.Serialize with unsupported parameter or return types

// skipped method PublicKey.SerializeSignaturePrefix with unsupported parameter or return types

// skipped method PublicKey.VerifyKeySignature with unsupported parameter or return types

// skipped method PublicKey.VerifyRevocationSignature with unsupported parameter or return types

// skipped method PublicKey.VerifySignature with unsupported parameter or return types

// skipped method PublicKey.VerifySignatureV3 with unsupported parameter or return types

// skipped method PublicKey.VerifyUserIdSignature with unsupported parameter or return types

// skipped method PublicKey.VerifyUserIdSignatureV3 with unsupported parameter or return types

@end

@interface CryptoSignature : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field Signature.Signature with unsupported type: golang.org/x/crypto/openpgp/packet.Signature

// skipped method Signature.Serialize with unsupported parameter or return types

// skipped method Signature.SigExpired with unsupported parameter or return types

// skipped method Signature.Sign with unsupported parameter or return types

// skipped method Signature.SignKey with unsupported parameter or return types

// skipped method Signature.SignUserId with unsupported parameter or return types

@end

/**
 * SignatureCollector structure
 */
@interface CryptoSignatureCollector : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped method SignatureCollector.Accept with unsupported parameter or return types

/**
 * GetSignature collected by Accept
 */
- (NSString* _Nonnull)getSignature;
@end

/**
 * SignatureVerificationError is returned from Decrypt and VerifyDetached functions when signature verification fails
 */
@interface CryptoSignatureVerificationError : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
@property (nonatomic) long status;
@property (nonatomic) NSString* _Nonnull message;
/**
 * Error is the base method for all errors
 */
- (NSString* _Nonnull)error;
@end

@interface CryptoSubkey : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
/**
 * openpgp.Subkey
 */
@property (nonatomic) CryptoPublicKey* _Nullable publicKey;
@property (nonatomic) CryptoPrivateKey* _Nullable privateKey;
@property (nonatomic) CryptoSignature* _Nullable sig;
@end

/**
 * SymmetricKey stores a decrypted session key.
 */
@interface CryptoSymmetricKey : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
/**
 * NewSymmetricKeyFromKeyPacket decrypts the binary symmetrically encrypted
session key packet and returns the session key.
 */
- (nullable instancetype)initFromKeyPacket:(NSData* _Nullable)keyPacket password:(NSString* _Nullable)password;
- (nullable instancetype)initFromToken:(NSString* _Nullable)passphrase algo:(NSString* _Nullable)algo;
/**
 * The decrypted binary session key.
 */
@property (nonatomic) NSData* _Nullable key;
/**
 * The symmetric encryption algorithm used with this key.
 */
@property (nonatomic) NSString* _Nonnull algo;
/**
 * Decrypt decrypts password protected pgp binary messages
encrypted: PGPMessage
output: PlainMessage
 */
- (CryptoPlainMessage* _Nullable)decrypt:(CryptoPGPMessage* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
/**
 * Encrypt encrypts a PlainMessage to PGPMessage with a SymmetricKey
message : The plain data as a PlainMessage
output  : The encrypted data as PGPMessage
 */
- (CryptoPGPMessage* _Nullable)encrypt:(CryptoPlainMessage* _Nullable)message error:(NSError* _Nullable* _Nullable)error;
/**
 * EncryptToKeyPacket encrypts the session key with the password and
returns a binary symmetrically encrypted session key packet.
 */
- (NSData* _Nullable)encryptToKeyPacket:(NSString* _Nullable)password error:(NSError* _Nullable* _Nullable)error;
/**
 * GetBase64Key returns the session key as base64 encoded string.
 */
- (NSString* _Nonnull)getBase64Key;
// skipped method SymmetricKey.GetCipherFunc with unsupported parameter or return types

@end

@interface CryptoUserId : NSObject <goSeqRefInterface> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (nonnull instancetype)init;
// skipped field UserId.UserId with unsupported type: golang.org/x/crypto/openpgp/packet.UserId

- (NSString* _Nonnull)getComment;
- (NSString* _Nonnull)getEmail;
- (NSString* _Nonnull)getId;
- (NSString* _Nonnull)getName;
// skipped method UserId.Serialize with unsupported parameter or return types

@end

/**
 *  DMS customized KeyEntity and Key structs
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoDSA;
/**
 * RFC 6637, Section 5.
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoECDH;
/**
 *  DMS customized KeyEntity and Key structs
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoECDSA;
/**
 * https://www.ietf.org/archive/id/draft-koch-eddsa-for-openpgp-04.txt
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoEdDSA;
/**
 *  DMS customized KeyEntity and Key structs
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoElGamal;
/**
 *  DMS customized KeyEntity and Key structs
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoRSA;
/**
 * Deprecated in RFC 4880, Section 13.5. Use key flags instead.
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoRSAEncryptOnly;
/**
 *  DMS customized KeyEntity and Key structs
 */
FOUNDATION_EXPORT const long CryptoPubKeyAlgoRSASignOnly;

// skipped function FilterExpiredKeys with unsupported parameter or return types


/**
 * GetGopenPGP return global GopenPGP
 */
FOUNDATION_EXPORT CryptoGopenPGP* _Nullable CryptoGetGopenPGP(void);

/**
 * NewClearTextMessage generates a new ClearTextMessage from data and signature
 */
FOUNDATION_EXPORT CryptoClearTextMessage* _Nullable CryptoNewClearTextMessage(NSData* _Nullable data, NSData* _Nullable signature);

/**
 * NewClearTextMessageFromArmored returns the message body and unarmored signature from a clearsigned message.
 */
FOUNDATION_EXPORT CryptoClearTextMessage* _Nullable CryptoNewClearTextMessageFromArmored(NSString* _Nullable signedMessage, NSError* _Nullable* _Nullable error);

/**
 * Creates a new KeyRing with empty key entities
 */
FOUNDATION_EXPORT CryptoKeyRing* _Nullable CryptoNewKeyRing(void);

/**
 * NewPGPMessage generates a new PGPMessage from the unarmored binary data.
 */
FOUNDATION_EXPORT CryptoPGPMessage* _Nullable CryptoNewPGPMessage(NSData* _Nullable data);

/**
 * NewPGPMessageFromArmored generates a new PGPMessage from an armored string ready for decryption.
 */
FOUNDATION_EXPORT CryptoPGPMessage* _Nullable CryptoNewPGPMessageFromArmored(NSString* _Nullable armored, NSError* _Nullable* _Nullable error);

/**
 * NewPGPSignature generates a new PGPSignature from the unarmored binary data.
 */
FOUNDATION_EXPORT CryptoPGPSignature* _Nullable CryptoNewPGPSignature(NSData* _Nullable data);

/**
 * NewPGPSignatureFromArmored generates a new PGPSignature from the armored string ready for verification.
 */
FOUNDATION_EXPORT CryptoPGPSignature* _Nullable CryptoNewPGPSignatureFromArmored(NSString* _Nullable armored, NSError* _Nullable* _Nullable error);

/**
 * NewPGPSplitMessage generates a new PGPSplitMessage from the binary unarmored keypacket,
datapacket, and encryption algorithm.
 */
FOUNDATION_EXPORT CryptoPGPSplitMessage* _Nullable CryptoNewPGPSplitMessage(NSData* _Nullable keyPacket, NSData* _Nullable dataPacket);

/**
 * NewPGPSplitMessageFromArmored generates a new PGPSplitMessage by splitting an armored message into its
session key packet and symmetrically encrypted data packet.
 */
FOUNDATION_EXPORT CryptoPGPSplitMessage* _Nullable CryptoNewPGPSplitMessageFromArmored(NSString* _Nullable encrypted, NSError* _Nullable* _Nullable error);

/**
 * NewPlainMessage generates a new binary PlainMessage ready for encryption,
signature, or verification from the unencrypted binary data.
 */
FOUNDATION_EXPORT CryptoPlainMessage* _Nullable CryptoNewPlainMessage(NSData* _Nullable data);

/**
 * NewPlainMessageFromString generates a new text PlainMessage,
ready for encryption, signature, or verification from an unencrypted string.
 */
FOUNDATION_EXPORT CryptoPlainMessage* _Nullable CryptoNewPlainMessageFromString(NSString* _Nullable text);

/**
 * NewSymmetricKeyFromKeyPacket decrypts the binary symmetrically encrypted
session key packet and returns the session key.
 */
FOUNDATION_EXPORT CryptoSymmetricKey* _Nullable CryptoNewSymmetricKeyFromKeyPacket(NSData* _Nullable keyPacket, NSString* _Nullable password, NSError* _Nullable* _Nullable error);

FOUNDATION_EXPORT CryptoSymmetricKey* _Nullable CryptoNewSymmetricKeyFromToken(NSString* _Nullable passphrase, NSString* _Nullable algo);

// skipped function ReadArmoredKeyRing with unsupported parameter or return types


// skipped function ReadKeyRing with unsupported parameter or return types


@class CryptoMIMECallbacks;

/**
 * MIMECallbacks defines callback methods to process a MIME message.
 */
@interface CryptoMIMECallbacks : NSObject <goSeqRefInterface, CryptoMIMECallbacks> {
}
@property(strong, readonly) _Nonnull id _ref;

- (nonnull instancetype)initWithRef:(_Nonnull id)ref;
- (void)onAttachment:(NSString* _Nullable)headers data:(NSData* _Nullable)data;
- (void)onBody:(NSString* _Nullable)body mimetype:(NSString* _Nullable)mimetype;
/**
 * Encrypted headers can be in an attachment and thus be placed at the end of the mime structure.
 */
- (void)onEncryptedHeaders:(NSString* _Nullable)headers;
- (void)onError:(NSError* _Nullable)err;
- (void)onVerified:(long)verified;
@end

#endif
