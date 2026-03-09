import AppKit
import SwiftUI

@main
struct CASSControlApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var appDelegate

    var body: some Scene {
        Settings {
            EmptyView()
        }
    }
}

final class AppDelegate: NSObject, NSApplicationDelegate {
    private let coordinator = SystemExtensionCoordinator()

    func applicationDidFinishLaunching(_ notification: Notification) {
        coordinator.handleLaunch(arguments: CommandLine.arguments)
    }
}
