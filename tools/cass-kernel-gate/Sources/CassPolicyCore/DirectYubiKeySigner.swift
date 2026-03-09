import CryptoKit
import Darwin
import Foundation
import Security

enum DirectYubiKeySlotResolver {
    static func slot(forCommonName commonName: String) -> UInt8? {
        if let override = explicitOverride(commonName: commonName) {
            return override
        }

        let normalized = commonName.lowercased()
        if normalized.contains("policy") || normalized.contains("digital signature") {
            return 0x9c
        }
        if normalized.contains("authentication") {
            return 0x9a
        }
        if normalized.contains("key management") {
            return 0x9d
        }
        return nil
    }

    private static func explicitOverride(commonName: String) -> UInt8? {
        let environment = ProcessInfo.processInfo.environment
        let keys = [
            "CASS_YUBIKEY_SLOT",
            "CASS_YUBIKEY_SLOT_\(sanitized(commonName))",
        ]

        for key in keys {
            guard let rawValue = environment[key], let slot = parse(slotValue: rawValue) else {
                continue
            }
            return slot
        }
        return nil
    }

    private static func sanitized(_ commonName: String) -> String {
        let scalars = commonName.unicodeScalars.map { scalar -> Character in
            if CharacterSet.alphanumerics.contains(scalar) {
                return Character(scalar)
            }
            return "_"
        }
        return String(scalars)
    }

    private static func parse(slotValue: String) -> UInt8? {
        let normalized = slotValue.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if normalized.hasPrefix("0x"), let value = UInt8(normalized.dropFirst(2), radix: 16) {
            return value
        }
        if normalized.hasPrefix("9"), let value = UInt8(normalized, radix: 16) {
            return value
        }
        if let value = UInt8(normalized) {
            return value
        }
        return nil
    }
}

enum DirectYubiKeySigner {
    fileprivate static let defaultLibraryCandidates = [
        ProcessInfo.processInfo.environment["CASS_YKPIV_DYLIB"],
        "/opt/homebrew/lib/libykpiv.dylib",
        "/opt/homebrew/Cellar/yubico-piv-tool/2.7.3/lib/libykpiv.dylib",
        "/usr/local/lib/libykpiv.dylib",
        "libykpiv.dylib",
    ].compactMap { $0 }

    static func isAvailable(for commonName: String) -> Bool {
        DirectYubiKeySlotResolver.slot(forCommonName: commonName) != nil && (try? runtime()) != nil
    }

    static func sign(message: Data, commonName: String) throws -> Data {
        let digest = Data(SHA256.hash(data: message))
        return try signDigest(digest, commonName: commonName)
    }

    static func signDigest(_ digest: Data, commonName: String) throws -> Data {
        guard let slot = DirectYubiKeySlotResolver.slot(forCommonName: commonName) else {
            throw CassPolicyError.signingFailed("Unable to resolve a YubiKey PIV slot for '\(commonName)'.")
        }
        guard digest.count == 32 else {
            throw CassPolicyError.signingFailed("Direct YubiKey signing expects a SHA-256 digest.")
        }

        let runtime = try runtime()
        let pin = try loadPIN()
        let readerName = ProcessInfo.processInfo.environment["CASS_YUBIKEY_READER"] ?? "Yubikey"

        var state: OpaquePointer?
        try runtime.throwing(runtime.initFn(&state, 0), action: "initialize YubiKey state")
        defer { _ = runtime.doneFn(state) }

        try readerName.withCString { readerCString in
            try runtime.throwing(runtime.connectFn(state, readerCString), action: "connect to the YubiKey reader")
        }

        var tries: Int32 = 0
        try pin.withCString { pinCString in
            try runtime.throwing(runtime.verifyFn(state, pinCString, &tries), action: "verify the YubiKey PIN")
        }

        var signature = Data(count: 512)
        var signatureLength = signature.count
        let rc = signature.withUnsafeMutableBytes { signatureBytes in
            digest.withUnsafeBytes { digestBytes in
                runtime.signFn(
                    state,
                    digestBytes.bindMemory(to: UInt8.self).baseAddress,
                    digest.count,
                    signatureBytes.bindMemory(to: UInt8.self).baseAddress,
                    &signatureLength,
                    0x11,
                    slot
                )
            }
        }
        try runtime.throwing(rc, action: "sign with YubiKey slot \(String(format: "%02x", slot))")
        signature.count = signatureLength
        return signature
    }

    private static func loadPIN() throws -> String {
        let environment = ProcessInfo.processInfo.environment
        if let pin = environment["CASS_YUBIKEY_PIN"], !pin.isEmpty {
            return pin
        }

        let service = environment["CASS_YUBIKEY_PIN_SERVICE"] ?? "com.orxaq.cass.yubikey.piv.pin"
        let account = environment["CASS_YUBIKEY_PIN_ACCOUNT"] ?? NSUserName()
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        if !account.isEmpty {
            query[kSecAttrAccount as String] = account
        }

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data, let pin = String(data: data, encoding: .utf8), !pin.isEmpty else {
            throw CassPolicyError.signingFailed("Unable to load the YubiKey PIN from Keychain service '\(service)'.")
        }
        return pin
    }

    private static func runtime() throws -> YKPIVRuntime {
        try YKPIVRuntime()
    }
}

private struct YKPIVRuntime {
    let handle: UnsafeMutableRawPointer
    let initFn: @convention(c) (UnsafeMutablePointer<OpaquePointer?>?, Int32) -> Int32
    let doneFn: @convention(c) (OpaquePointer?) -> Int32
    let connectFn: @convention(c) (OpaquePointer?, UnsafePointer<CChar>?) -> Int32
    let verifyFn: @convention(c) (OpaquePointer?, UnsafePointer<CChar>?, UnsafeMutablePointer<Int32>?) -> Int32
    let signFn: @convention(c) (OpaquePointer?, UnsafePointer<UInt8>?, Int, UnsafeMutablePointer<UInt8>?, UnsafeMutablePointer<Int>?, UInt8, UInt8) -> Int32
    let errorNameFn: @convention(c) (Int32) -> UnsafePointer<CChar>?

    init() throws {
        guard let (handle, path) = YKPIVRuntime.openLibrary() else {
            throw CassPolicyError.signingFailed("libykpiv.dylib is not available. Install `yubico-piv-tool` or set CASS_YKPIV_DYLIB.")
        }

        self.handle = handle
        do {
            initFn = try Self.symbol("ykpiv_init", from: handle)
            doneFn = try Self.symbol("ykpiv_done", from: handle)
            connectFn = try Self.symbol("ykpiv_connect", from: handle)
            verifyFn = try Self.symbol("ykpiv_verify", from: handle)
            signFn = try Self.symbol("ykpiv_sign_data", from: handle)
            errorNameFn = try Self.symbol("ykpiv_strerror_name", from: handle)
        } catch {
            dlclose(handle)
            throw CassPolicyError.signingFailed("Failed to load libykpiv symbols from \(path).")
        }
    }

    func throwing(_ rc: Int32, action: String) throws {
        guard rc == 0 else {
            let detail = errorNameFn(rc).map { String(cString: $0) } ?? "rc=\(rc)"
            throw CassPolicyError.signingFailed("Unable to \(action): \(detail)")
        }
    }

    private static func symbol<T>(_ name: String, from handle: UnsafeMutableRawPointer) throws -> T {
        guard let pointer = dlsym(handle, name) else {
            throw CassPolicyError.signingFailed("Missing libykpiv symbol '\(name)'.")
        }
        return unsafeBitCast(pointer, to: T.self)
    }

    private static func openLibrary() -> (UnsafeMutableRawPointer, String)? {
        for candidate in DirectYubiKeySigner.defaultLibraryCandidates {
            guard let handle = dlopen(candidate, RTLD_NOW | RTLD_LOCAL) else {
                continue
            }
            return (handle, candidate)
        }
        return nil
    }
}
