import Foundation
import Security

public struct SigningKeyMaterial {
    public var securityPrivateKey: SecKey?
    public var publicKey: SecKey
    public var signer: String
    public var keySource: String
    public var certificateDER: Data?
    public var tokenID: String?
    public var directYubiKeySlot: UInt8?

    public init(
        securityPrivateKey: SecKey? = nil,
        publicKey: SecKey,
        signer: String,
        keySource: String,
        certificateDER: Data? = nil,
        tokenID: String? = nil,
        directYubiKeySlot: UInt8? = nil
    ) {
        self.securityPrivateKey = securityPrivateKey
        self.publicKey = publicKey
        self.signer = signer
        self.keySource = keySource
        self.certificateDER = certificateDER
        self.tokenID = tokenID
        self.directYubiKeySlot = directYubiKeySlot
    }
}

public enum PolicySigner {
    private static let algorithm = SecKeyAlgorithm.ecdsaSignatureMessageX962SHA256

    public static func generateSecureEnclaveKey(label: String) throws -> String {
        try generateKey(label: label, secureEnclave: true)
    }

    public static func generateKeychainKey(label: String) throws -> String {
        try generateKey(label: label, secureEnclave: false)
    }

    public static func listIdentities() throws -> [SigningIdentitySummary] {
        try allIdentityRecords().map {
            SigningIdentitySummary(
                commonName: $0.commonName,
                keySource: "keychain-identity:\($0.commonName)",
                tokenID: $0.tokenID,
                isTokenBacked: $0.tokenID != nil && $0.tokenID != (kSecAttrTokenIDSecureEnclave as String),
                certificatePresent: true
            )
        }
    }

    public static func doctorIdentity(commonName: String) throws -> SigningIdentityDoctorReport {
        let material = try loadIdentity(commonName: commonName)
        let summaryKeySource = material.directYubiKeySlot.map {
            "yubikey-piv:\(commonName):\(String(format: "%02x", $0))"
        } ?? material.keySource
        let summary = SigningIdentitySummary(
            commonName: commonName,
            keySource: summaryKeySource,
            tokenID: material.tokenID,
            isTokenBacked: material.tokenID != nil && material.tokenID != (kSecAttrTokenIDSecureEnclave as String),
            certificatePresent: material.certificateDER != nil
        )
        let signingChallengePassed = try verifySigningChallenge(material: material)
        let trust = try certificateTrustStatus(certificateDER: material.certificateDER)
        return SigningIdentityDoctorReport(
            identity: summary,
            signingChallengePassed: signingChallengePassed,
            certificateTrustStatus: trust.status,
            certificateTrustDetail: trust.detail
        )
    }

    private static func generateKey(label: String, secureEnclave: Bool) throws -> String {
        let applicationTag = Data(label.utf8)
        let access = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage], nil)

        var attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: applicationTag,
                kSecAttrAccessControl as String: access as Any,
                kSecAttrLabel as String: label,
            ],
        ]
        if secureEnclave {
            attributes[kSecAttrTokenID as String] = kSecAttrTokenIDSecureEnclave
        }

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            let descriptor = secureEnclave ? "Secure Enclave" : "keychain"
            throw CassPolicyError.signingFailed(error?.takeRetainedValue().localizedDescription ?? "Unable to create \(descriptor) key.")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CassPolicyError.signingFailed("Unable to export public key.")
        }
        let publicData = try externalRepresentation(of: publicKey, allowEmpty: false)
        return publicData.base64EncodedString()
    }

    public static func loadKey(label: String) throws -> SigningKeyMaterial {
        let query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: Data(label.utf8),
            kSecAttrKeyClass as String: kSecAttrKeyClassPrivate,
            kSecReturnRef as String: true,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let privateKey = result as! SecKey? else {
            throw CassPolicyError.signerNotFound("Key label '\(label)' not found.")
        }
        guard let publicKey = SecKeyCopyPublicKey(privateKey) else {
            throw CassPolicyError.signingFailed("Unable to load public key for '\(label)'.")
        }
        let attributes = SecKeyCopyAttributes(privateKey) as NSDictionary? as? [String: Any]
        let tokenID = attributes?[kSecAttrTokenID as String] as? String
        let keySource: String
        if tokenID == (kSecAttrTokenIDSecureEnclave as String) {
            keySource = "secure-enclave:\(label)"
        } else {
            keySource = "keychain-key:\(label)"
        }
        return SigningKeyMaterial(
            securityPrivateKey: privateKey,
            publicKey: publicKey,
            signer: label,
            keySource: keySource,
            tokenID: tokenID
        )
    }

    public static func loadIdentity(commonName: String) throws -> SigningKeyMaterial {
        let record = try allIdentityRecords().first { $0.commonName == commonName }
        guard let record else {
            throw CassPolicyError.signerNotFound("Identity '\(commonName)' not found.")
        }
        return SigningKeyMaterial(
            securityPrivateKey: record.privateKey,
            publicKey: record.publicKey,
            signer: record.commonName,
            keySource: "keychain-identity:\(record.commonName)",
            certificateDER: record.certificateDER,
            tokenID: record.tokenID,
            directYubiKeySlot: directYubiKeySlot(for: record)
        )
    }

    public static func sign(policy: PolicyDocument, using material: SigningKeyMaterial) throws -> SignedPolicyEnvelope {
        let normalized = policy.normalized()
        return SignedPolicyEnvelope(
            policy: normalized,
            signature: try signPayload(normalized, using: material)
        )
    }

    public static func sign(lease: BreakglassLease, using material: SigningKeyMaterial) throws -> SignedBreakglassLeaseEnvelope {
        let normalized = lease.normalized()
        return SignedBreakglassLeaseEnvelope(
            lease: normalized,
            signature: try signPayload(normalized, using: material)
        )
    }

    public static func verify(envelope: SignedPolicyEnvelope) throws {
        try verifyPayload(envelope.policy.normalized(), signature: envelope.signature)
    }

    public static func verify(leaseEnvelope: SignedBreakglassLeaseEnvelope) throws {
        try verifyPayload(leaseEnvelope.lease.normalized(), signature: leaseEnvelope.signature)
    }

    private static func signPayload<T: Encodable>(_ payload: T, using material: SigningKeyMaterial) throws -> ArtifactSignature {
        let bytes = try CanonicalJSON.data(for: payload)
        let (signature, keySource) = try createSignature(for: bytes, using: material)
        let publicKeyData = try externalRepresentation(of: material.publicKey, allowEmpty: material.certificateDER != nil)
        return ArtifactSignature(
            algorithm: "ecdsa-p256-sha256",
            publicKeyBase64: publicKeyData.base64EncodedString(),
            signatureBase64: signature.base64EncodedString(),
            signer: material.signer,
            keySource: keySource,
            certificateDERBase64: material.certificateDER?.base64EncodedString()
        )
    }

    private static func verifyPayload<T: Encodable>(_ payload: T, signature: ArtifactSignature) throws {
        let bytes = try CanonicalJSON.data(for: payload)
        let publicKey = try makePublicKey(from: signature)
        guard let signatureData = Data(base64Encoded: signature.signatureBase64) else {
            throw CassPolicyError.verificationFailed("Signature is not valid base64.")
        }
        var error: Unmanaged<CFError>?
        let ok = SecKeyVerifySignature(publicKey, algorithm, bytes as CFData, signatureData as CFData, &error)
        if !ok {
            throw CassPolicyError.verificationFailed(error?.takeRetainedValue().localizedDescription ?? "Signature check failed.")
        }
    }

    private static func verifySigningChallenge(material: SigningKeyMaterial) throws -> Bool {
        let challenge = Data((0..<32).map { _ in UInt8.random(in: 0...UInt8.max) })
        let (signature, _) = try createSignature(for: challenge, using: material)
        var error: Unmanaged<CFError>?
        let verified = SecKeyVerifySignature(material.publicKey, algorithm, challenge as CFData, signature as CFData, &error)
        if !verified, let error {
            throw CassPolicyError.verificationFailed(error.takeRetainedValue().localizedDescription)
        }
        return verified
    }

    private static func createSignature(for message: Data, using material: SigningKeyMaterial) throws -> (signature: Data, keySource: String) {
        if let slot = material.directYubiKeySlot {
            let signature = try DirectYubiKeySigner.sign(message: message, commonName: material.signer)
            return (signature, "yubikey-piv:\(material.signer):\(String(format: "%02x", slot))")
        }

        guard let privateKey = material.securityPrivateKey else {
            throw CassPolicyError.signingFailed("No signing backend is available for '\(material.signer)'.")
        }
        var error: Unmanaged<CFError>?
        guard SecKeyIsAlgorithmSupported(privateKey, .sign, algorithm) else {
            throw CassPolicyError.signingFailed("Key does not support ECDSA P-256 SHA-256 signing.")
        }
        guard let signature = SecKeyCreateSignature(privateKey, algorithm, message as CFData, &error) as Data? else {
            throw CassPolicyError.signingFailed(error?.takeRetainedValue().localizedDescription ?? "Unable to create signature.")
        }
        return (signature, material.keySource)
    }

    private static func certificateTrustStatus(certificateDER: Data?) throws -> (status: HealthStatus, detail: String?) {
        guard
            let certificateDER,
            let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData)
        else {
            return (.warn, "No certificate is attached to this signing material.")
        }

        let policy = SecPolicyCreateBasicX509()
        var trust: SecTrust?
        guard SecTrustCreateWithCertificates(certificate, policy, &trust) == errSecSuccess, let trust else {
            return (.fail, "Unable to build trust object for the identity certificate.")
        }
        var error: CFError?
        let ok = SecTrustEvaluateWithError(trust, &error)
        if ok {
            return (.pass, "Certificate trust evaluation succeeded.")
        }
        return (.fail, (error as Error?)?.localizedDescription ?? "Certificate trust evaluation failed.")
    }

    private static func makePublicKey(from signature: ArtifactSignature) throws -> SecKey {
        if let certificateDERBase64 = signature.certificateDERBase64,
           let certificateDER = Data(base64Encoded: certificateDERBase64),
           let certificate = SecCertificateCreateWithData(nil, certificateDER as CFData),
           let publicKey = SecCertificateCopyKey(certificate) {
            return publicKey
        }
        guard let publicKeyData = Data(base64Encoded: signature.publicKeyBase64), !publicKeyData.isEmpty else {
            throw CassPolicyError.verificationFailed("Public key is not valid base64.")
        }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeyClass as String: kSecAttrKeyClassPublic,
            kSecAttrKeySizeInBits as String: 256,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(publicKeyData as CFData, attributes as CFDictionary, &error) else {
            throw CassPolicyError.verificationFailed(error?.takeRetainedValue().localizedDescription ?? "Unable to reconstruct public key.")
        }
        return key
    }

    private static func externalRepresentation(of key: SecKey, allowEmpty: Bool) throws -> Data {
        var error: Unmanaged<CFError>?
        if let data = SecKeyCopyExternalRepresentation(key, &error) as Data? {
            return data
        }
        if allowEmpty {
            return Data()
        }
        throw CassPolicyError.signingFailed(error?.takeRetainedValue().localizedDescription ?? "Unable to export public key bytes.")
    }

    private static func allIdentityRecords() throws -> [IdentityRecord] {
        let query: [String: Any] = [
            kSecClass as String: kSecClassIdentity,
            kSecReturnRef as String: true,
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else {
            throw CassPolicyError.signerNotFound("No signing identities are available in the keychain.")
        }
        let identities = result as? [SecIdentity] ?? []
        return identities.compactMap { identity in
            var certificate: SecCertificate?
            guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess, let certificate else {
                return nil
            }
            var name: CFString?
            guard SecCertificateCopyCommonName(certificate, &name) == errSecSuccess, let name else {
                return nil
            }
            var privateKey: SecKey?
            guard SecIdentityCopyPrivateKey(identity, &privateKey) == errSecSuccess, let privateKey else {
                return nil
            }
            guard let publicKey = SecCertificateCopyKey(certificate) else {
                return nil
            }
            let attributes = SecKeyCopyAttributes(privateKey) as NSDictionary? as? [String: Any]
            let tokenID = attributes?[kSecAttrTokenID as String] as? String
            return IdentityRecord(
                commonName: name as String,
                privateKey: privateKey,
                publicKey: publicKey,
                certificateDER: SecCertificateCopyData(certificate) as Data,
                tokenID: tokenID
            )
        }.sorted { $0.commonName < $1.commonName }
    }

    private static func directYubiKeySlot(for record: IdentityRecord) -> UInt8? {
        guard let tokenID = record.tokenID, tokenID.hasPrefix("com.apple.pivtoken:") else {
            return nil
        }
        guard DirectYubiKeySigner.isAvailable(for: record.commonName) else {
            return nil
        }
        return DirectYubiKeySlotResolver.slot(forCommonName: record.commonName)
    }
}

private struct IdentityRecord {
    let commonName: String
    let privateKey: SecKey
    let publicKey: SecKey
    let certificateDER: Data
    let tokenID: String?
}
