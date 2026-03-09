import CryptoKit
import Foundation

public enum CassTime {
    private static func formatter() -> ISO8601DateFormatter {
        let formatter = ISO8601DateFormatter()
        formatter.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
        return formatter
    }

    public static func string(from date: Date = Date()) -> String {
        formatter().string(from: date)
    }

    public static func date(from string: String) -> Date? {
        formatter().date(from: string) ?? ISO8601DateFormatter().date(from: string)
    }
}

public enum RuntimeSupport {
    public static func fingerprint(for data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }

    public static func fingerprint<T: Encodable>(for value: T) throws -> String {
        fingerprint(for: try CanonicalJSON.data(for: value))
    }

    public static func ensureRuntimeDirectories(layout: CassRuntimeLayout) throws {
        let fileManager = FileManager.default
        for directory in [
            layout.rootDirectory,
            layout.policiesDirectory,
            layout.leasesDirectory,
            layout.auditDirectory,
            layout.statusDirectory,
        ] {
            try fileManager.createDirectory(at: URL(fileURLWithPath: directory), withIntermediateDirectories: true)
        }
    }

    public static func ownerAccountID(for path: String) -> UInt32? {
        let attributes = try? FileManager.default.attributesOfItem(atPath: path)
        return attributes?[.ownerAccountID] as? UInt32
    }
}

extension BreakglassLease {
    public func createdDate() -> Date? {
        CassTime.date(from: createdAt)
    }

    public func expiresDate() -> Date? {
        CassTime.date(from: expiresAt)
    }

    public func isActive(at date: Date = Date()) -> Bool {
        guard let createdDate = createdDate(), let expiresDate = expiresDate() else {
            return false
        }
        return createdDate <= date && date < expiresDate
    }
}

public final class AuditLogger {
    private let layout: CassRuntimeLayout
    private let lock = NSLock()

    public init(layout: CassRuntimeLayout) {
        self.layout = layout
    }

    public func append(_ record: AuditRecord) throws {
        try RuntimeSupport.ensureRuntimeDirectories(layout: layout)
        let data = try CanonicalJSON.data(for: record)
        lock.lock()
        defer { lock.unlock() }
        let fileURL = URL(fileURLWithPath: layout.auditLogPath)
        if !FileManager.default.fileExists(atPath: fileURL.path) {
            FileManager.default.createFile(atPath: fileURL.path, contents: nil)
        }
        let handle = try FileHandle(forWritingTo: fileURL)
        defer { try? handle.close() }
        try handle.seekToEnd()
        handle.write(data)
        handle.write(Data("\n".utf8))
    }
}

public final class LeaseStore {
    private let layout: CassRuntimeLayout
    private let fileManager: FileManager
    private let lock = NSLock()
    private var cachedSnapshot: String?
    private var cachedRecords: [StoredLeaseRecord] = []

    public init(layout: CassRuntimeLayout, fileManager: FileManager = .default) {
        self.layout = layout
        self.fileManager = fileManager
    }

    public func save(_ envelope: SignedBreakglassLeaseEnvelope) throws {
        try PolicySigner.verify(leaseEnvelope: envelope)
        try RuntimeSupport.ensureRuntimeDirectories(layout: layout)
        let path = leasePath(for: envelope.lease.leaseID)
        try PolicyLoader.writeSignedLease(envelope, to: path)
        invalidateCache()
    }

    public func revoke(leaseID: String, reason: String, revokedAt: Date = Date()) throws {
        try RuntimeSupport.ensureRuntimeDirectories(layout: layout)
        let record = LeaseRevocationRecord(
            leaseID: leaseID,
            revokedAt: CassTime.string(from: revokedAt),
            reason: reason
        )
        try PolicyLoader.writeJSON(record, to: revocationPath(for: leaseID))
        invalidateCache()
    }

    public func list(now: Date = Date()) throws -> [StoredLeaseRecord] {
        try reloadIfNeeded(now: now)
        lock.lock()
        defer { lock.unlock() }
        return cachedRecords
    }

    public func activeLeases(for profile: PolicyProfile? = nil, now: Date = Date()) throws -> [BreakglassLease] {
        try list(now: now)
            .filter(\.active)
            .map(\.envelope.lease)
            .filter { lease in
                lease.isActive(at: now) && (profile == nil || lease.profile == profile)
            }
    }

    public func validate(now: Date = Date()) throws {
        _ = try list(now: now)
    }

    private func leasePath(for leaseID: String) -> String {
        "\(layout.leasesDirectory)/\(leaseID).signed.json"
    }

    private func revocationPath(for leaseID: String) -> String {
        "\(layout.leasesDirectory)/\(leaseID).revoked.json"
    }

    private func invalidateCache() {
        lock.lock()
        cachedSnapshot = nil
        cachedRecords = []
        lock.unlock()
    }

    private func reloadIfNeeded(now: Date) throws {
        try RuntimeSupport.ensureRuntimeDirectories(layout: layout)
        let snapshot = try directorySnapshot()
        lock.lock()
        let cachedSnapshot = self.cachedSnapshot
        lock.unlock()
        guard snapshot != cachedSnapshot else {
            return
        }

        let records = try loadRecords(now: now)
        lock.lock()
        self.cachedSnapshot = snapshot
        self.cachedRecords = records
        lock.unlock()
    }

    private func loadRecords(now: Date) throws -> [StoredLeaseRecord] {
        let directory = URL(fileURLWithPath: layout.leasesDirectory)
        let entries = try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
            .filter { $0.lastPathComponent.hasSuffix(".signed.json") }
            .sorted { $0.lastPathComponent < $1.lastPathComponent }

        return try entries.map { entry in
            let envelope = try PolicyLoader.loadSignedLease(at: entry.path)
            try PolicySigner.verify(leaseEnvelope: envelope)
            let revocation = try loadRevocation(for: envelope.lease.leaseID)
            let active = revocation == nil && envelope.lease.isActive(at: now)
            return StoredLeaseRecord(envelope: envelope, revokedAt: revocation?.revokedAt, active: active)
        }
    }

    private func loadRevocation(for leaseID: String) throws -> LeaseRevocationRecord? {
        let path = revocationPath(for: leaseID)
        guard fileManager.fileExists(atPath: path) else {
            return nil
        }
        return try PolicyLoader.loadJSON(LeaseRevocationRecord.self, at: path)
    }

    private func directorySnapshot() throws -> String {
        let directory = URL(fileURLWithPath: layout.leasesDirectory)
        guard fileManager.fileExists(atPath: directory.path) else {
            return "missing"
        }
        let entries = try fileManager.contentsOfDirectory(at: directory, includingPropertiesForKeys: [.contentModificationDateKey, .fileSizeKey])
            .sorted { $0.lastPathComponent < $1.lastPathComponent }
        let components = try entries.map { url -> String in
            let values = try url.resourceValues(forKeys: [.contentModificationDateKey, .fileSizeKey])
            let modified = values.contentModificationDate?.timeIntervalSince1970 ?? 0
            let fileSize = values.fileSize ?? 0
            return "\(url.lastPathComponent):\(modified):\(fileSize)"
        }
        return components.joined(separator: "|")
    }
}
