import Foundation

public enum CLIHelpers {
    public static func value(after flag: String, in arguments: [String]) throws -> String {
        guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else {
            throw CassPolicyError.missingArgument(flag)
        }
        return arguments[index + 1]
    }

    public static func optionalValue(after flag: String, in arguments: [String]) -> String? {
        guard let index = arguments.firstIndex(of: flag), index + 1 < arguments.count else {
            return nil
        }
        return arguments[index + 1]
    }

    public static func hasFlag(_ flag: String, in arguments: [String]) -> Bool {
        arguments.contains(flag)
    }

    public static func commaSeparatedValues(after flag: String, in arguments: [String]) throws -> [String] {
        try value(after: flag, in: arguments)
            .split(separator: ",")
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            .filter { !$0.isEmpty }
    }

    public static func printJSON<T: Encodable>(_ value: T) throws {
        FileHandle.standardOutput.write(try CanonicalJSON.data(for: value))
        FileHandle.standardOutput.write(Data("\n".utf8))
    }
}
