//
//  DMSGoPGP+Signature.swift
//  DMSGoPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-8-28.
//

import XCTest
import DMSGoPGP

class DMSGoPGP_Signature: XCTestCase {

    let aliceRSA = DMSGoPGPTests_GenerateKey.keyInfo(for: "Alice", keyType: .rsa)
    let bobRSA = DMSGoPGPTests_GenerateKey.keyInfo(for: "Bob", keyType: .rsa)

}

// MARK: - Detached signatures for plain text messages
extension DMSGoPGP_Signature {

    func testDetachedSignatureAndVerify() {

        let signingKeyRing = try? aliceRSA.createPrivateKeyRing()
        XCTAssertNotNil(signingKeyRing)
        try? signingKeyRing?.unlock(withPassphrase: "Alice")

        do {
            let message = CryptoNewPlainMessageFromString("Message")
            let signature = try signingKeyRing?.signDetached(message)   // FIXME: should .sign(message, trimnewlines)

            var error: NSError?
            let armored = signature?.getArmored(&error)
            XCTAssertNil(error)
            XCTAssertNotNil(armored)

            let signedText = message?.getString()
            XCTAssertNotNil(signedText)
            XCTAssertEqual("Message", signedText ?? "")

            // verify signature
            let pgpSignature = CryptoNewPGPSignatureFromArmored(armored!, &error)
            XCTAssertNil(error)

            let verifyKeyRing = try signingKeyRing?.publicKeyRing()
            XCTAssertNotNil(verifyKeyRing)
            try verifyKeyRing?.verifyDetached(message, signature: pgpSignature, verifyTime: CryptoGetGopenPGP()!.getUnixTime())
            // should pass verify and no throw

        } catch {
            XCTFail(error.localizedDescription)
        }

    }

}

// MARK: - Detached signatures for binary data
extension DMSGoPGP_Signature {

    func testDetachedSignatureAndVerify_binary() {
        let data = Data("Message".utf8)
        let message = CryptoNewPlainMessage(data)
        XCTAssertNotNil(message)

        let privateKey = try? aliceRSA.createPrivateKeyRing()
        XCTAssertNotNil(privateKey)
        let publicKey = try? privateKey?.publicKeyRing()
        XCTAssertNotNil(publicKey)

        do {
            try privateKey?.unlock(withPassphrase: "Alice")
            let signature = try privateKey?.signDetached(message)

            var error: NSError?
            let armored = signature?.getArmored(&error)
            XCTAssertNil(error)
            XCTAssertNotNil(armored)

            let signedBinary = message?.getBinary()
            XCTAssertNotNil(signedBinary)
            XCTAssertEqual(data, signedBinary ?? Data())
            XCTAssertEqual("Message", String(data: signedBinary ?? Data(), encoding: .utf8))    // FIXME: ("Optional("Message")") is not equal to ("Optional("refnum\0")")

            // verify
            let pgpSignature = CryptoNewPGPSignatureFromArmored(armored!, &error)
            XCTAssertNil(error)

            try publicKey?.verifyDetached(message, signature: pgpSignature, verifyTime: CryptoGetGopenPGP()!.getUnixTime())
            // should pass verify and no throw

        } catch {
            XCTFail(error.localizedDescription)
        }
    }

}

// MARK: - Cleartext signed messages
extension DMSGoPGP_Signature {

    func testClearSign() {
        let privateKey = try? aliceRSA.createPrivateKeyRing()
        XCTAssertNotNil(privateKey)
        let publicKey = try? privateKey?.publicKeyRing()
        XCTAssertNotNil(publicKey)

        var error: NSError?
        let cleartext = HelperSignCleartextMessageArmored(privateKey, "Alice", "Message", &error)
        XCTAssertNil(error)

        let verifyTime = CryptoGetGopenPGP()!.getUnixTime()
        let plaintext = HelperVerifyCleartextMessage(publicKey, cleartext, verifyTime, &error)
        XCTAssertNil(error)

        XCTAssertEqual("Message", plaintext)
    }

}


