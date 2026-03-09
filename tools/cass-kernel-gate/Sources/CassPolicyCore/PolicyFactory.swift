import Foundation

public enum PolicyFactory {
    public static func makeClaudeCodePolicy(
        homeDirectory: String,
        repoDirectory: String,
        verifierPath: String,
        profile: PolicyProfile,
        memoryControl: MemoryControlMode = .disabled
    ) -> PolicyDocument {
        let home = URL(fileURLWithPath: homeDirectory).standardized.path
        let repo = URL(fileURLWithPath: repoDirectory).standardized.path
        let isoTimestamp = CassTime.string()
        let mutableOps: [GovernedOperation] = [
            .openWrite,
            .create,
            .rename,
            .unlink,
            .truncate,
            .setFlags,
            .setMode,
            .setExtAttr,
            .copyFile,
            .clone,
            .exchangeData,
        ]
        let escapedRepo = NSRegularExpression.escapedPattern(for: repo)
        let escapedHome = NSRegularExpression.escapedPattern(for: home)
        let governedPaths = makeGovernedPaths(home: home, repo: repo, mutableOps: mutableOps, profile: profile)
        let referencePaths = makeWritableReferencePaths(repo: repo)

        return PolicyDocument(
            policyID: "claude-code-cass-kernel-gate-\(profile.rawValue)",
            createdAt: isoTimestamp,
            description: "\(profile.rawValue.capitalized) CASS policy for Claude Code on \(repo).",
            profile: profile,
            memoryControl: memoryControl,
            monitoredExecutables: [
                "\(home)/.local/bin/claude",
                "\(home)/.local/share/claude/versions/*/claude",
            ],
            governedPaths: governedPaths,
            governedCommands: [
                CommandRule(
                    id: "deny-chflags-nouchg",
                    commandRegex: #"(^|.*\s)chflags\s+nouchg(\s|$)"#,
                    action: .deny,
                    reason: "Removing immutable flags from governed control surfaces is denied."
                ),
                CommandRule(
                    id: "deny-chmod-7xx",
                    commandRegex: #"(^|.*\s)chmod\s+7[0-7]{2}(\s|$)"#,
                    action: .deny,
                    reason: "Restoring broad write permissions is denied."
                ),
                CommandRule(
                    id: "deny-rm-violations",
                    commandRegex: ".*\\brm\\s+.*\(escapedHome)/Documents/Orxaq/obsidian_vault/Violations/.*",
                    action: .deny,
                    reason: "Deleting violation records is denied."
                ),
            ],
            verificationRules: [
                VerificationRule(
                    id: "python-promotion-verify",
                    targetPathRegex: "^\(escapedRepo)/.*\\.py$",
                    verifierCommand: [verifierPath],
                    reason: "Governed Python writes require staged verification before promotion."
                ),
            ],
            writableReferencePaths: referencePaths
        )
    }

    private static func makeGovernedPaths(
        home: String,
        repo: String,
        mutableOps: [GovernedOperation],
        profile: PolicyProfile
    ) -> [GovernedPathRule] {
        var rules: [GovernedPathRule] = [
            GovernedPathRule(
                id: "project-claude-settings",
                pathPattern: "\(repo)/.claude/settings.json",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not rewrite project Claude settings."
            ),
            GovernedPathRule(
                id: "project-claude-settings-local",
                pathPattern: "\(repo)/.claude/settings.local.json",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not rewrite project-local Claude settings."
            ),
            GovernedPathRule(
                id: "project-claude-hooks",
                pathPattern: "\(repo)/.claude/hooks/*",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not edit or replace governance hook scripts."
            ),
            GovernedPathRule(
                id: "project-claude-rules",
                pathPattern: "\(repo)/.claude/rules/**",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not rewrite repo governance rules."
            ),
            GovernedPathRule(
                id: "project-claude-agents-index",
                pathPattern: "\(repo)/.claude/agents.md",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not rewrite agent governance metadata."
            ),
            GovernedPathRule(
                id: "project-claude-agents",
                pathPattern: "\(repo)/.claude/agents/**",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not rewrite agent governance instructions."
            ),
            GovernedPathRule(
                id: "project-claude-mcp",
                pathPattern: "\(repo)/.claude/mcp.json",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not rewrite MCP governance wiring."
            ),
            GovernedPathRule(
                id: "project-claude-md",
                pathPattern: "\(repo)/CLAUDE.md",
                operations: mutableOps,
                action: .deny,
                reason: "Claude must not rewrite repo-level Claude instructions."
            ),
        ]

        if profile == .strict {
            rules.append(
                contentsOf: [
                    GovernedPathRule(
                        id: "global-claude-settings",
                        pathPattern: "\(home)/.claude/settings.json",
                        operations: mutableOps,
                        action: .deny,
                        reason: "Claude must not rewrite global Claude settings."
                    ),
                    GovernedPathRule(
                        id: "global-claude-settings-local",
                        pathPattern: "\(home)/.claude/settings.local.json",
                        operations: mutableOps,
                        action: .deny,
                        reason: "Claude must not rewrite local Claude allowlists."
                    ),
                    GovernedPathRule(
                        id: "global-claude-md",
                        pathPattern: "\(home)/CLAUDE.md",
                        operations: mutableOps,
                        action: .deny,
                        reason: "Claude must not rewrite operator-global Claude instructions."
                    ),
                    GovernedPathRule(
                        id: "violation-records",
                        pathPattern: "\(home)/Documents/Orxaq/obsidian_vault/Violations/**",
                        operations: mutableOps,
                        action: .deny,
                        reason: "Claude must not remove or alter violation records."
                    ),
                    GovernedPathRule(
                        id: "harness-plan",
                        pathPattern: "\(home)/Documents/Orxaq/obsidian_vault/Plans/claude-code-harness.md",
                        operations: mutableOps,
                        action: .deny,
                        reason: "Claude must not rewrite the governed harness plan."
                    ),
                ]
            )
        }

        return rules
    }

    private static func makeWritableReferencePaths(repo: String) -> [String] {
        [
            "\(repo)/.claude/api-routes.md",
            "\(repo)/.claude/codebase-map.md",
            "\(repo)/.claude/data-registry.md",
            "\(repo)/.claude/env-vars.md",
            "\(repo)/.claude/surface.md",
            "\(repo)/.claude/test-guide.md",
            "\(repo)/.claude/training.md",
            "\(repo)/.claude/troubleshooting.md",
        ]
    }
}
