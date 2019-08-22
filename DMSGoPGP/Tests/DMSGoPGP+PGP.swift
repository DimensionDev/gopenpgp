//
//  DMSGoPGP+PGP.swift
//  DMSGoPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-8-22.
//

import XCTest
import DMSGoPGP

class DMSGoPGP_PGP: XCTestCase {

    lazy var alice_RSA_KeyRing: CryptoKeyRing = {
        return try! DMSGoPGPTests_GenerateKey.keyInfo(for: "Alice", keyType: .rsa).generateKeyRing()!
    }()
    lazy var bob_RSA_KeyRing: CryptoKeyRing = {
        return try! DMSGoPGPTests_GenerateKey.keyInfo(for: "Bob", keyType: .rsa).generateKeyRing()!
    }()
    lazy var eve_RSA_KeyRing: CryptoKeyRing = {
        return try! DMSGoPGPTests_GenerateKey.keyInfo(for: "Eve", keyType: .rsa).generateKeyRing()!
    }()

    // FIXME:
    func testEncryptAndDecryptWithPGPKeys() {
        let pgp = CryptoGetGopenPGP()!

        var error: NSError?
        let bobPublicKey = bob_RSA_KeyRing.getArmoredPublicKey(&error)
        XCTAssertNil(error)
        let evePublicKey = eve_RSA_KeyRing.getArmoredPublicKey(&error)
        XCTAssertNil(error)

        let message = "Message"

        do {
            let publicKeyRingArmor = [bobPublicKey, evePublicKey].joined(separator: "\n")
            let publicKeyRing = try pgp.buildKeyRingArmored(publicKeyRingArmor)
            XCTAssertEqual(publicKeyRing.getEntitiesCount(), 2)

            let armor = HelperEncryptSignMessageArmored(publicKeyRing, alice_RSA_KeyRing, "Alice", message, &error)
            XCTAssertNil(error)

            let decryptMessage_Bob = HelperDecryptMessageArmored(bob_RSA_KeyRing, "Bob", armor, &error)
            XCTAssertNil(error)

            let decryptMessage_Eve = HelperDecryptMessageArmored(eve_RSA_KeyRing, "Eve", armor, &error)
            XCTAssertNil(error)

            XCTAssertEqual(message, decryptMessage_Bob)
            XCTAssertEqual(message, decryptMessage_Eve)

        } catch {
            XCTFail(error.localizedDescription)
        }

    }

}
