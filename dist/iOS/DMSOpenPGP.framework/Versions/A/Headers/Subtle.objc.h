// Objective-C API for talking to github.com/DimensionDev/gopenpgp/subtle Go package.
//   gobind -lang=objc github.com/DimensionDev/gopenpgp/subtle
//
// File is generated by gobind. Do not edit.

#ifndef __Subtle_H__
#define __Subtle_H__

@import Foundation;
#include "ref.h"
#include "Universe.objc.h"


/**
 * DecryptWithoutIntegrity decrypts data encrypted with AES-CTR.
 */
FOUNDATION_EXPORT NSData* _Nullable SubtleDecryptWithoutIntegrity(NSData* _Nullable key, NSData* _Nullable input, NSData* _Nullable iv, NSError* _Nullable* _Nullable error);

/**
 * DeriveKey derives a key from a password using scrypt. N should be set to the
highest power of 2 you can derive within 100 milliseconds.
 */
FOUNDATION_EXPORT NSData* _Nullable SubtleDeriveKey(NSString* _Nullable password, NSData* _Nullable salt, long N, NSError* _Nullable* _Nullable error);

/**
 * EncryptWithoutIntegrity encrypts data with AES-CTR. Note: this encryption
mode is not secure when stored/sent on an untrusted medium.
 */
FOUNDATION_EXPORT NSData* _Nullable SubtleEncryptWithoutIntegrity(NSData* _Nullable key, NSData* _Nullable input, NSData* _Nullable iv, NSError* _Nullable* _Nullable error);

#endif
