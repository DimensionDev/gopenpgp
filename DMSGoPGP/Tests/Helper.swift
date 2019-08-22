//
//  Helper.swift
//  DMSGoPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-8-22.
//

import Foundation
import DMSGoPGP

public struct GenerateKeyInfo {
    public let name: String
    public let email: String
    public let passphrase: String
    public let keyType: KeyType
    public let keyBits: Int


}

extension GenerateKeyInfo {

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

extension GenerateKeyInfo {

    public func generatePrivateKey() throws -> String? {
        let pgp = CryptoGetGopenPGP()

        var error: NSError?
        let key = pgp?.generateKey(name, email: email, passphrase: passphrase, keyType: keyType.rawValue, bits: keyBits, error: &error)

        if let error = error {
            throw error
        }
        return key
    }

    public func generateKeyRing() throws -> CryptoKeyRing? {
        let pgp = CryptoGetGopenPGP()

        let privateKey = try generatePrivateKey()
        let keyRing = try pgp?.buildKeyRingArmored(privateKey ?? "")

        return keyRing
    }

}
