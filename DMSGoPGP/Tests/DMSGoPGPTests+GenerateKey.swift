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
        for keyType in KeyInfo.KeyType.allCases {
            do {
                _ = try DMSGoPGPTests_GenerateKey.keyInfo(for: keyType.rawValue, keyType: keyType).createPrivateKeyRing()
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
                _ = try keyInfo.createPrivateKeyRing()
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
                _ = try keyInfo.createPrivateKeyRing()
            } catch {
                XCTFail(error.localizedDescription)
            }
        }
    }

}

extension DMSGoPGPTests_GenerateKey {

    static func keyInfo(for name: String, keyType: KeyInfo.KeyType) -> KeyInfo {
        let email = "\(name)@\(name).com"
        let passphrase = name

        return KeyInfo(name: name, email: email, passphrase: passphrase, keyType: keyType, keyBits: keyType.defaultBits)
    }
}
