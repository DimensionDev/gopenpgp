//
//  DMSGoPGP+PGP.swift
//  DMSGoPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-8-22.
//

import XCTest
import DMSGoPGP

class DMSGoPGP_PGP: XCTestCase {

    let aliceRSA = DMSGoPGPTests_GenerateKey.keyInfo(for: "Alice", keyType: .rsa)
    let bobRSA = DMSGoPGPTests_GenerateKey.keyInfo(for: "Bob", keyType: .rsa)
    let eveRSA = DMSGoPGPTests_GenerateKey.keyInfo(for: "Eve", keyType: .rsa)

}

// MARK: - Encrypt / Decrypt with PGP keys
extension DMSGoPGP_PGP {

    func testEncryptDecrypt_singleKey() {
        let privateKey = try? aliceRSA.createPrivateKeyRing()
        XCTAssertNotNil(privateKey)
        let publicKey = try? privateKey?.publicKeyRing()
        XCTAssertNotNil(publicKey)


        let message = "Message"
        var error: NSError?
        let ciphertext = HelperEncryptMessageArmored(publicKey, message, &error)
        XCTAssertNil(error)
        let decrypted = HelperDecryptMessageArmored(privateKey, "Alice", ciphertext, &error)
        XCTAssertNil(error)

        XCTAssertEqual(message, decrypted)
    }

    func testEncryptDecryptSign_singleKey() {
        let privateKey = try? aliceRSA.createPrivateKeyRing()
        XCTAssertNotNil(privateKey)
        let publicKey = try? privateKey?.publicKeyRing()
        XCTAssertNotNil(publicKey)


        let message = "Message"
        var error: NSError?
        let ciphertextWithSign = HelperEncryptSignMessageArmored(publicKey, privateKey, "Alice", message, &error)
        XCTAssertNil(error)
        let decrypted = HelperDecryptMessageArmored(privateKey, "Alice", ciphertextWithSign, &error)
        XCTAssertNil(error)
        let decryptedVerified = HelperDecryptVerifyMessageArmored(publicKey, privateKey, "Alice", ciphertextWithSign, &error)

        XCTAssertEqual(message, decrypted)
        XCTAssertEqual(message, decryptedVerified)
    }
}

// MARK: - With signatures:
extension DMSGoPGP_PGP {

    func testEncryptDecryptSign_signByAlice_encryptToBob() {

        let bobPrivateKey = try? bobRSA.createPrivateKeyRing()
        let bobPublicKey = try? bobPrivateKey?.publicKeyRing()
        XCTAssertNotNil(bobPrivateKey)
        XCTAssertNotNil(bobPublicKey)

        let alicePrivateKey = try? aliceRSA.createPrivateKeyRing()
        let alicePublicKey = try? alicePrivateKey?.publicKeyRing()
        XCTAssertNotNil(alicePrivateKey)
        XCTAssertNotNil(alicePublicKey)

        let message = "Message"

        do {
            let pgp = CryptoGetGopenPGP()!


            var error: NSError?
            let ciphertextWithSign = HelperEncryptSignMessageArmored(bobPublicKey, alicePrivateKey, "Alice", message, &error)
            XCTAssertNil(error)

            let decrypted = HelperDecryptMessageArmored(bobPrivateKey, "Bob", ciphertextWithSign, &error)
            XCTAssertNil(error)

            let decryptedVerified = HelperDecryptVerifyMessageArmored(alicePublicKey, bobPrivateKey, "Bob", ciphertextWithSign, &error)
            XCTAssertNil(error)

            XCTAssertEqual(message, decrypted)
            XCTAssertEqual(message, decryptedVerified)

        } catch {
            XCTFail(error.localizedDescription)
        }

    }

    // Normally, also encrypt to alice self
    // FIXME: can no merge two public key into one keyRing
    func testEncryptDecryptSign_signByAlice_encryptToBobAndEve() {

        let bobPrivateKey = try? bobRSA.createPrivateKeyRing()
        let bobPublicKey = try? bobPrivateKey?.publicKeyRing()
        XCTAssertNotNil(bobPrivateKey)
        XCTAssertNotNil(bobPublicKey)

        let evePrivateKey = try? eveRSA.createPrivateKeyRing()
        let evePublicKey = try? evePrivateKey?.publicKeyRing()
        XCTAssertNotNil(evePrivateKey)
        XCTAssertNotNil(evePublicKey)

        let alicePrivateKey = try? aliceRSA.createPrivateKeyRing()
        XCTAssertNotNil(alicePrivateKey)

        let message = "Message"

        do {
            let pgp = CryptoGetGopenPGP()!
            let publicKeyRingArmor = [bobPublicKey, evePublicKey].compactMap { try? $0?.armored() }.joined(separator: "\n")
            let publicKeyRing = try pgp.buildKeyRingArmored(publicKeyRingArmor)
            XCTAssertEqual(publicKeyRing.getEntitiesCount(), 2)

            var error: NSError?
            let armor = HelperEncryptSignMessageArmored(publicKeyRing, alicePrivateKey, "Alice", message, &error)
            XCTAssertNil(error)

            let decryptMessage_Bob = HelperDecryptMessageArmored(bobPrivateKey, "Bob", armor, &error)
            XCTAssertNil(error)

            let decryptMessage_Eve = HelperDecryptMessageArmored(evePrivateKey, "Eve", armor, &error)
            XCTAssertNil(error)

            XCTAssertEqual(message, decryptMessage_Bob)
            XCTAssertEqual(message, decryptMessage_Eve)

        } catch {
            XCTFail(error.localizedDescription)
        }

    }

}

// MARK: - With binary data or advanced modes:
extension DMSGoPGP_PGP {

    func testEncryptDecrypt_binary() {
        let data = Data("Message".utf8)
        let binaryMessage = CryptoNewPlainMessage(data)
        XCTAssertNotNil(binaryMessage)

        let privateKey = try? aliceRSA.createPrivateKeyRing()
        XCTAssertNotNil(privateKey)
        let publicKey = try? privateKey?.publicKeyRing()
        XCTAssertNotNil(publicKey)

        do {
            try privateKey?.unlock(withPassphrase: "Alice")

            // optional unlocked privateKey for signature
            let pgpMessage = try publicKey?.encrypt(binaryMessage, privateKey: privateKey)
            let decryptedBinaryMessage = try privateKey?.decrypt(pgpMessage, verifyKey: publicKey, verifyTime: CryptoGetGopenPGP()!.getUnixTime())

            XCTAssertNotNil(decryptedBinaryMessage)
            XCTAssertEqual(data, decryptedBinaryMessage!.data)
            XCTAssertEqual("Message", String(data: decryptedBinaryMessage!.data!, encoding: .utf8)) // FIXME: XCTAssertEqual failed: ("Optional("Message")") is not equal to ("Optional("refnum\0")")
        } catch {
            XCTFail(error.localizedDescription)
        }
    }

}
