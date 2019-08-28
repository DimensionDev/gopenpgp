//
//  DMSGoPGPTests+Password.swift
//  DMSGoPGP-Unit-Tests
//
//  Created by Cirno MainasuK on 2019-8-22.
//

import XCTest
import DMSGoPGP

class DMSGoPGPTests_Password: XCTestCase {

    func testSmoke() {

    }

    func testEncryptAndDecryptWithPassword() {
        let password = "my secret password"
        let message = "my message"

        // Encrypt data with password
        var error: NSError?
        let armor = HelperEncryptMessageWithToken(password, message, &error)
        XCTAssertNil(error)

        // Decrypt data with password
        let decryptedMessage = HelperDecryptMessageWithToken(password, armor, &error)
        XCTAssertNil(error)
        XCTAssertEqual(message, decryptedMessage)

        // Encrypt data with password use DES
        let armor_DES = HelperEncryptMessageWithTokenAlgo(password, message, ConstantsThreeDES, &error)
        XCTAssertNil(error)

        // Decrypt data with password
        let decryptedMessage_DES = HelperDecryptMessageWithToken(password, armor_DES, &error)
        XCTAssertNil(error)
        XCTAssertEqual(message, decryptedMessage_DES)

        let key = CryptoNewSymmetricKeyFromToken(password, ConstantsAES256)
        let cryptoMessage = CryptoNewPlainMessage(Data(message.utf8))
        XCTAssertNotNil(key)
        XCTAssertNotNil(cryptoMessage)

        // Encrypt data with key
        let encrypted_AES256 = try? key!.encrypt(cryptoMessage)
        XCTAssertNotNil(encrypted_AES256)

        let decrypted_AES256 = try? key!.decrypt(encrypted_AES256)  // FIXME: should be: decrypted, err := key.Decrypt(password, encrypted)
        XCTAssertNotNil(decrypted_AES256)
        XCTAssertNotNil(decrypted_AES256?.data)
        XCTAssertEqual(decrypted_AES256!.data, cryptoMessage!.data)

        let decrypted_AES256_Message = String(data: decrypted_AES256!.data!, encoding: .utf8)
        XCTAssertEqual(message, decrypted_AES256_Message)
    }

}
