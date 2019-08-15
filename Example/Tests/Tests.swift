import XCTest
import DMSOpenPGP

class DMSGopenPGPTests: XCTestCase {
    
    static let pgp = CryptoGetGopenPGP()!
    
    static var alice = generateKeyRing(name: "Alice", email: "Alice@gmail.com", passphrase: "Alice")!
    static var bob = generateKeyRing(name: "Bob", email: "Bob@gmail.com", passphrase: "Bob")!
    static var eve = generateKeyRing(name: "Eve", email: "Eve@gmail.com", passphrase: "Eve")!
    
    static var testKeyRings: [(CryptoKeyRing, String)] {
        return [
            (alice, "Alice"),
            (bob, "Bob"),
            (eve, "Eve")
        ]
    }
    
    override func setUp() {
        super.setUp()
        // Put setup code here. This method is called before the invocation of each test method in the class.
    }
    
    override func tearDown() {
        // Put teardown code here. This method is called after the invocation of each test method in the class.
        super.tearDown()
    }
    
    func testSimpleEncDec() {
        let message = "simple message"
        let password = "simple password"
        
        var error: NSError?
        let armored = HelperEncryptMessageWithToken(password, message, &error)
        XCTAssertNil(error, "Fail to encrypt, error :\(error?.localizedDescription)")
        
        let decrypted = HelperDecryptMessageWithToken(password, armored, &error)
        XCTAssertNil(error, "Fail to decrypt, error :\(error?.localizedDescription)")
        
        XCTAssertEqual(decrypted, message, "Decrypted message not equal to origin msg!")
        
    }
    
    func testEncDecBinaryData() {
        let message = "simple message"
        let password = "simple password"
        let key = CryptoNewSymmetricKeyFromToken(password, ConstantsAES256)
        let cryptoMessage = CryptoNewPlainMessageFromString(message)
        XCTAssertNotNil(cryptoMessage, "Fail to create crypto message")
        
        do {
            let encrypted = try key?.encrypt(cryptoMessage)
            XCTAssertNotNil(encrypted, "Fail to encrypt plain message")
            
            let decrypted = try key?.decrypt(encrypted!)
            XCTAssertNotNil(decrypted, "Fail to decrypt crypto message")
            
            XCTAssertEqual(cryptoMessage!.getString(), decrypted!.getString(), "Decrypted message not equal to origin msg!")
        } catch {
            XCTAssertTrue(false, "Fail to Enc/Dec binary data, error: \(error.localizedDescription)")
        }
    }
    
    func testRSAKey() {
        do {
            var error: NSError?
            let rsaKeyRing = try DMSGopenPGPTests.pgp.buildKeyRingArmored(RSAKey)
            try rsaKeyRing.unlock(withPassphrase: "RSA")
            let entity = try rsaKeyRing.getEntity(0)
            let pKey = entity.primaryKey
            
            let fingerprint = pKey?.getFingerprint()
            XCTAssertNil(error, "Fail to get fingerprint fo RSA, error: \(String(describing: error?.localizedDescription))")
            XCTAssertEqual(fingerprint?.uppercased(), "E42B2DA77D952A02AE982612BF56D1DCD6DAEE91")
            
            var bitsLength: Int = 0
            try pKey?.getBitLength(UnsafeMutablePointer<Int>(&bitsLength))
            XCTAssertEqual(bitsLength, 4096, "Wrong Bit Length")
            
            let algo = pKey?.getAlgorithm()
            XCTAssertEqual(algo, CryptoPubKeyAlgoRSA, "Wrong Bit Length")
            
            let identity = try entity.getIdentity(0)
            XCTAssertEqual(identity.userId?.getId(), "RSA <RSA@pgp.key>")
            
            let signKey = try rsaKeyRing.getSigningEntity().primaryKey
            XCTAssertNotNil(signKey)
            
            XCTAssertEqual(signKey?.keyIdString(), "BF56D1DCD6DAEE91")
            XCTAssertEqual(signKey?.keyIdShortString(), "D6DAEE91")
            
            
            let encrypttionKey = try rsaKeyRing.getEncryptionKey()
            XCTAssertNotNil(encrypttionKey)
            XCTAssertEqual(encrypttionKey.getFingerprint().uppercased(), "EBED6EC3479D859D3838512E38A151F162F8FFF6")
            XCTAssertEqual(encrypttionKey.keyIdString(), "38A151F162F8FFF6")
            XCTAssertEqual(encrypttionKey.keyIdShortString(), "62F8FFF6")
            
            var encKeybitsLength: Int = 0
            try encrypttionKey.getBitLength(UnsafeMutablePointer<Int>(&encKeybitsLength))
            XCTAssertEqual(encKeybitsLength, 4096)
            XCTAssertEqual(encrypttionKey.getAlgorithm(), CryptoPubKeyAlgoRSA)
            
            
        } catch {
            XCTAssertTrue(false, "Fail to Enc/Dec binary data, error: \(error.localizedDescription)")
        }
    }
    
    // 3072 DSA + 3072 ELG-E PGP Key
    func testDSAKey() {
        do {
            let key = DSAKey
            let dsaKeyRing = try DMSGopenPGPTests.pgp.buildKeyRingArmored(key)
            try dsaKeyRing.unlock(withPassphrase: "DSA")
            let primaryKey = try dsaKeyRing.getEntity(0).primaryKey
            let primarySiningKey = try dsaKeyRing.getSigningEntity().primaryKey
            let primaryEncryptionKey = try dsaKeyRing.getEncryptionKey()
            XCTAssertEqual(primaryKey?.getFingerprint().uppercased(), "4E208F2768671661679869E99D709FFE1D0DAC7F")
            
            var bitsLength: Int = 0
            try primaryKey?.getBitLength(UnsafeMutablePointer<Int>(&bitsLength))
            XCTAssertEqual(bitsLength, 3072)
            XCTAssertEqual(primaryKey?.getAlgorithm(), CryptoPubKeyAlgoDSA)
            
            let userID = try dsaKeyRing.getEntity(0).getIdentity(0).userId
            XCTAssertNotNil(userID)
            XCTAssertEqual(userID?.getId(), "DSA <DSA@pgp.key>")
            
            XCTAssertNotNil(primarySiningKey)
            XCTAssertEqual(primaryKey?.getFingerprint(), primarySiningKey?.getFingerprint())
            XCTAssertEqual(primarySiningKey?.keyIdString(), "9D709FFE1D0DAC7F")
            XCTAssertEqual(primarySiningKey?.keyIdShortString(), "1D0DAC7F")
            
            XCTAssertNotNil(primaryEncryptionKey)
            XCTAssertEqual(primaryEncryptionKey.getFingerprint().uppercased(), "0A40D7E300A14D01E23D3C5A7A298C4EDFEE2E69")
            XCTAssertEqual(primaryEncryptionKey.keyIdString(), "7A298C4EDFEE2E69")
            XCTAssertEqual(primaryEncryptionKey.keyIdShortString(), "DFEE2E69")
            var encbitsLength: Int = 0
            try primaryEncryptionKey.getBitLength(UnsafeMutablePointer<Int>(&encbitsLength))
            XCTAssertEqual(encbitsLength, 3072)
            XCTAssertEqual(primaryEncryptionKey.getAlgorithm(), CryptoPubKeyAlgoElGamal)
        } catch {
            XCTAssertTrue(false, "Fail to Enc/Dec binary data, error: \(error.localizedDescription)")
        }
    }
    
    func testDMSPGPSign_ClearText() {
        measure {
            DMSGopenPGPTests.testKeyRings.forEach { keyring in
                DMSGopenPGPTests.signClearText(keyRing: keyring.0)
            }
        }
    }
    
    func testDMSPGPEncryptWithoutSign() {
        measure {
            DMSGopenPGPTests.testKeyRings.forEach { keyring in
                DMSGopenPGPTests.encryptWithoutSign(keyRing: keyring.0, passphrase: keyring.1)
            }
        }
    }
    
    func testDMSPGPEncryptWithSign() {
        measure {
            DMSGopenPGPTests.testKeyRings.forEach { keyring in
                DMSGopenPGPTests.encryptWithSign(keyRing: keyring.0, passphrase: keyring.1)
            }
        }
    }
}

extension DMSGopenPGPTests {
    static func signClearText(keyRing: CryptoKeyRing) {
        do {
            let time = pgp.getUnixTime()
            var error: NSError?
            let message = "Clear Message"
            let clearText = HelperSignCleartextMessage(keyRing, message, &error)
            XCTAssertNil(error)
            
            let result = HelperVerifyCleartextMessage(keyRing, clearText, time, &error)
            XCTAssertNil(error)
            XCTAssertEqual(message, result)
            
            let plainMessage = CryptoNewPlainMessageFromString(clearText)
            let detached = try keyRing.signDetached(plainMessage)
            
            try keyRing.verifyDetached(plainMessage, signature: detached, verifyTime: time)
        } catch {
            XCTAssertTrue(false, "Fail to sign clear text, error: \(error.localizedDescription)")
        }
    }
    
    static func encryptWithoutSign(keyRing: CryptoKeyRing, passphrase: String) {
        var error: NSError?
        let plaintext = "Secret message"
        let armoredMessage = HelperEncryptMessageArmored(keyRing, plaintext, &error)
        
        let decrypted = HelperDecryptMessageArmored(keyRing, passphrase, armoredMessage, &error)
        XCTAssertEqual(decrypted, plaintext)
    }
    
    static func encryptWithSign(keyRing: CryptoKeyRing, passphrase: String) {
        do {
            let time = pgp.getUnixTime()
            var error: NSError?
            let message = "Secret Message"
            let signEncMessage = HelperEncryptSignMessageArmored(keyRing, keyRing, passphrase, message, &error)
            XCTAssertNil(error)
            
            let decrypted = HelperDecryptVerifyMessageArmored(keyRing, keyRing, passphrase, signEncMessage, &error)
            
            let testDec = HelperDecryptMessageArmored(keyRing, passphrase, signEncMessage, &error)
            XCTAssertNil(error)
            XCTAssertEqual(message, decrypted)
            
        } catch {
            XCTAssertTrue(false, "Fail to sign clear text, error: \(error.localizedDescription)")
        }
    }
}

extension DMSGopenPGPTests {
    static func generateKeyRing(name: String, email: String, passphrase: String) -> CryptoKeyRing? {
        do {
            var error: NSError?
            let rsaKey = pgp.generateKey(name, email: email, passphrase: passphrase, keyType: "rsa", bits: 4096, error: &error)
            let keyring = try pgp.buildKeyRingArmored(rsaKey)
            try keyring.unlock(withPassphrase: passphrase)
            return keyring
        } catch {
            return nil
        }
    }
}

private let DSAKey = """
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
EoJHdlyouFGgiNj92kEvZOZa+po=
=nBSC
-----END PGP PRIVATE KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
GTY0RJgfsBKCR3ZcqLhRoIjY/dpBL2TmWvqa
=nRVX
-----END PGP PUBLIC KEY BLOCK-----
"""

private let RSAKey = """
-----BEGIN PGP PRIVATE KEY BLOCK-----

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
LM0RDOTU65fryL/E7NJ3q15McH+umnEb86tq
=2UzT
-----END PGP PRIVATE KEY BLOCK-----
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=8I6w
-----END PGP PUBLIC KEY BLOCK-----
"""

let RSAPubKey = """
-----BEGIN PGP PUBLIC KEY BLOCK-----

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
=8I6w
-----END PGP PUBLIC KEY BLOCK-----
"""
