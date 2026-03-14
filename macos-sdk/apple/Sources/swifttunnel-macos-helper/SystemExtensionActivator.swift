import Foundation
import SystemExtensions

enum SystemExtensionActivatorError: Error, CustomStringConvertible {
    case timedOut
    case requestFailed(String)

    var description: String {
        switch self {
        case .timedOut:
            "Timed out waiting for system extension activation result"
        case .requestFailed(let message):
            "System extension activation failed: \(message)"
        }
    }
}

final class SystemExtensionActivationDelegate: NSObject, OSSystemExtensionRequestDelegate {
    private let semaphore = DispatchSemaphore(value: 0)
    private(set) var outcome = "submitted"
    private(set) var failure: Error?

    func wait() throws -> String {
        if semaphore.wait(timeout: .now() + 30) == .timedOut {
            throw SystemExtensionActivatorError.timedOut
        }

        if let failure {
            throw failure
        }

        return outcome
    }

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        outcome = "needs_user_approval"
    }

    func request(
        _ request: OSSystemExtensionRequest,
        didFinishWithResult result: OSSystemExtensionRequest.Result
    ) {
        switch result {
        case .completed:
            outcome = "completed"
        case .willCompleteAfterReboot:
            outcome = "will_complete_after_reboot"
        @unknown default:
            outcome = "completed_with_unknown_result"
        }
        semaphore.signal()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        failure = SystemExtensionActivatorError.requestFailed(error.localizedDescription)
        semaphore.signal()
    }
}

enum SystemExtensionActivator {
    static func activate(extensionBundleIdentifier: String) throws -> String {
        let delegate = SystemExtensionActivationDelegate()
        let queue = DispatchQueue(label: "net.swifttunnel.macos.system-extension-activation")
        let request = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleIdentifier,
            queue: queue
        )
        request.delegate = delegate

        OSSystemExtensionManager.shared.submitRequest(request)
        return try delegate.wait()
    }
}
