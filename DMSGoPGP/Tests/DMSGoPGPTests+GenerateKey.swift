//
//  DMSGoPGPTests+GenerateKey.swift
//  DMSGoPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-8-22.
//

import XCTest
import DMSGoPGP

class DMSGoPGPTests_GenerateKey: XCTestCase {

    func testGenerateKeys() {
        for keyType in GenerateKeyInfo.KeyType.allCases {
            do {
                try DMSGoPGPTests_GenerateKey.privateKey(name: keyType.rawValue, for: keyType)
            } catch {
                XCTFail(error.localizedDescription)
            }
        }
    }

    // avg: ~0.7s
    func testGenerateKey_Measure_RSA() {
        let keyInfo = DMSGoPGPTests_GenerateKey.keyInfo(for: "RSA", keyType: .rsa)

        measure {
            do {
                _ = try keyInfo.generatePrivateKey()
            } catch {
                XCTFail(error.localizedDescription)
            }
        }
    }

    // avg: ~0.001s
    func testGenerateKey_Measure_X25519() {
        let keyInfo = DMSGoPGPTests_GenerateKey.keyInfo(for: "X25519", keyType: .x25519)

        measure {
            do {
                _ = try keyInfo.generatePrivateKey()
            } catch {
                XCTFail(error.localizedDescription)
            }
        }
    }

}

extension DMSGoPGPTests_GenerateKey {

    @discardableResult
    static func privateKey(name: String, for keyType: GenerateKeyInfo.KeyType) throws -> String? {
        let keyInfo = DMSGoPGPTests_GenerateKey.keyInfo(for: name, keyType: .rsa)
        let key = try keyInfo.generatePrivateKey()
        XCTAssertNotNil(key)
        XCTAssertFalse(key!.isEmpty)
        return key
    }

    static func keyInfo(for name: String, keyType: GenerateKeyInfo.KeyType) -> GenerateKeyInfo {
        let email = "\(name)@\(name).com"
        let passphrase = name

        return GenerateKeyInfo(name: name, email: email, passphrase: passphrase, keyType: keyType, keyBits: keyType.defaultBits)
    }
}
