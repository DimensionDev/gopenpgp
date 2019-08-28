//
//  Helper.swift
//  DMSGoPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-8-22.
//

import Foundation
import DMSGoPGP

public struct KeyInfo {
    public let name: String
    public let email: String
    public let passphrase: String
    public let keyType: KeyType
    public let keyBits: Int
}

extension KeyInfo {

    public enum KeyType: String, CaseIterable {
        case rsa
        case x25519

        public var defaultBits: Int {
            switch self {
            case .rsa:      return 3072
            case .x25519:   return 256
            }
        }
    }

}

extension KeyInfo {

    private func _createPrivateKey() throws -> String? {
        let pgp = CryptoGetGopenPGP()

        var error: NSError?
        let key = pgp?.generateKey(name, email: email, passphrase: passphrase, keyType: keyType.rawValue, bits: keyBits, error: &error)

        if let error = error {
            throw error
        }
        return key
    }

    public func createPrivateKeyRing() throws -> CryptoKeyRing? {
        let pgp = CryptoGetGopenPGP()

        let armored = try _createPrivateKey()
        let keyRing = try pgp?.buildKeyRingArmored(armored ?? "")

        return keyRing
    }

}

extension CryptoKeyRing {

    public func publicKeyRing() throws -> CryptoKeyRing? {
        let pgp = CryptoGetGopenPGP()

        var error: NSError?
        let publicKey = getArmoredPublicKey(&error)
        return try pgp?.buildKeyRingArmored(publicKey)
    }

}

extension CryptoKeyRing {
    public func armored(passphrase: String? = nil) throws -> String {
        var error: NSError?
        if let passphrase = passphrase {
            let armored = getArmored(passphrase, error: &error)
            if let error = error {
                throw error
            }

            return armored
        } else {
            let armored = getArmoredPublicKey(&error)
            if let error = error {
                throw error
            }

            return armored
        }
    }
}
