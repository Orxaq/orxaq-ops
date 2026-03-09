import Foundation

public enum PathMatcher {
    public static func matches(glob: String, path: String, caseInsensitive: Bool = false) -> Bool {
        let candidates = candidatePaths(for: path)
        let normalizedGlob = normalize(glob)
        guard let regex = try? NSRegularExpression(
            pattern: regexPattern(for: normalizedGlob),
            options: caseInsensitive ? [.caseInsensitive] : []
        ) else {
            return false
        }
        return candidates.contains { candidate in
            let range = NSRange(location: 0, length: candidate.utf16.count)
            return regex.firstMatch(in: candidate, options: [], range: range) != nil
        }
    }

    public static func regexPattern(for glob: String) -> String {
        var output = "^"
        let characters = Array(glob)
        var index = 0
        while index < characters.count {
            let character = characters[index]
            if character == "*" {
                let nextIsStar = index + 1 < characters.count && characters[index + 1] == "*"
                output += nextIsStar ? ".*" : "[^/]*"
                index += nextIsStar ? 2 : 1
                continue
            }
            if character == "?" {
                output += "[^/]"
                index += 1
                continue
            }
            output += NSRegularExpression.escapedPattern(for: String(character))
            index += 1
        }
        output += "$"
        return output
    }

    public static func normalize(_ path: String) -> String {
        var normalized = URL(fileURLWithPath: path).standardized.path
        if normalized.count > 1, normalized.hasSuffix("/") {
            normalized.removeLast()
        }
        return normalized.precomposedStringWithCanonicalMapping
    }

    public static func candidatePaths(for path: String) -> [String] {
        var candidates: [String] = []
        let normalized = normalize(path)
        candidates.append(normalized)

        let resolved = URL(fileURLWithPath: path).resolvingSymlinksInPath().standardized.path.precomposedStringWithCanonicalMapping
        if resolved != normalized {
            candidates.append(resolved)
        }

        let parentURL = URL(fileURLWithPath: path).deletingLastPathComponent()
        let basename = URL(fileURLWithPath: path).lastPathComponent
        let resolvedParent = parentURL.resolvingSymlinksInPath().standardized.path
        let parentResolvedPath = URL(fileURLWithPath: resolvedParent).appendingPathComponent(basename).path.precomposedStringWithCanonicalMapping
        if parentResolvedPath != normalized && parentResolvedPath != resolved {
            candidates.append(parentResolvedPath)
        }

        return candidates
    }
}
