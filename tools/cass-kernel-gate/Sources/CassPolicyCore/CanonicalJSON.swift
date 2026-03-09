import Foundation

public enum CanonicalJSON {
    public static func data<T: Encodable>(for value: T) throws -> Data {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .prettyPrinted, .withoutEscapingSlashes]
        return try encoder.encode(value)
    }

    public static func string<T: Encodable>(for value: T) throws -> String {
        let encoded = try data(for: value)
        guard let string = String(data: encoded, encoding: .utf8) else {
            throw CassPolicyError.invalidUTF8
        }
        return string + (string.hasSuffix("\n") ? "" : "\n")
    }
}
