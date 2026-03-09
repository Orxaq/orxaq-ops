import Foundation

public enum PolicyLoader {
    public static func loadPolicy(at path: String) throws -> PolicyDocument {
        try loadJSON(PolicyDocument.self, at: path).normalized()
    }

    public static func loadSignedPolicy(at path: String) throws -> SignedPolicyEnvelope {
        let envelope = try loadJSON(SignedPolicyEnvelope.self, at: path)
        return SignedPolicyEnvelope(policy: envelope.policy.normalized(), signature: envelope.signature)
    }

    public static func loadSignedLease(at path: String) throws -> SignedBreakglassLeaseEnvelope {
        let envelope = try loadJSON(SignedBreakglassLeaseEnvelope.self, at: path)
        return SignedBreakglassLeaseEnvelope(lease: envelope.lease.normalized(), signature: envelope.signature)
    }

    public static func loadJSON<T: Decodable>(_ type: T.Type, at path: String) throws -> T {
        let data = try Data(contentsOf: URL(fileURLWithPath: path))
        return try JSONDecoder().decode(T.self, from: data)
    }

    public static func writePolicy(_ policy: PolicyDocument, to path: String) throws {
        try writeJSON(policy.normalized(), to: path)
    }

    public static func writeSignedPolicy(_ envelope: SignedPolicyEnvelope, to path: String) throws {
        try writeJSON(envelope, to: path)
    }

    public static func writeSignedLease(_ envelope: SignedBreakglassLeaseEnvelope, to path: String) throws {
        try writeJSON(envelope, to: path)
    }

    public static func writeJSON<T: Encodable>(_ value: T, to path: String) throws {
        let directory = URL(fileURLWithPath: path).deletingLastPathComponent()
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        try CanonicalJSON.string(for: value).write(toFile: path, atomically: true, encoding: .utf8)
    }
}
