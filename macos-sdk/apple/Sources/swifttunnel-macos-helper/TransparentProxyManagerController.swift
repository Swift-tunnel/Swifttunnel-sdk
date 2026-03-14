import Foundation
@preconcurrency import NetworkExtension
import SwiftTunnelMacOSShared

struct TransparentProxyManagerStatus: Codable {
    var providerBundleIdentifier: String
    var localizedDescription: String?
    var enabled: Bool
    var statusRawValue: Int
    var status: String
}

enum TransparentProxyManagerControllerError: Error, CustomStringConvertible {
    case managerLoadFailed(String)
    case managerSaveFailed(String)
    case tunnelStartFailed(String)
    case providerSessionUnavailable
    case providerMessageFailed(String)

    var description: String {
        switch self {
        case .managerLoadFailed(let message):
            "Failed to load transparent proxy manager: \(message)"
        case .managerSaveFailed(let message):
            "Failed to save transparent proxy manager: \(message)"
        case .tunnelStartFailed(let message):
            "Failed to start transparent proxy manager: \(message)"
        case .providerSessionUnavailable:
            "Manager connection is not a NETunnelProviderSession"
        case .providerMessageFailed(let message):
            "Provider message failed: \(message)"
        }
    }
}

final class CallbackBox<T>: @unchecked Sendable {
    var value: T

    init(_ value: T) {
        self.value = value
    }
}

enum TransparentProxyManagerController {
    static func save(
        providerBundleIdentifier: String,
        configuration: ProviderConfiguration
    ) throws -> NETransparentProxyManager {
        let manager = try loadOrCreateManager(providerBundleIdentifier: providerBundleIdentifier)
        let tunnelProtocol = NETunnelProviderProtocol()
        tunnelProtocol.providerBundleIdentifier = providerBundleIdentifier
        tunnelProtocol.providerConfiguration = configuration.asProviderDictionary()
        tunnelProtocol.serverAddress = configuration.bridgeHost

        manager.localizedDescription = configuration.localizedDescription
        manager.protocolConfiguration = tunnelProtocol
        manager.isEnabled = true

        try waitForSave(on: manager)
        try waitForLoad(on: manager)
        return manager
    }

    static func start(
        providerBundleIdentifier: String,
        configuration: ProviderConfiguration
    ) throws -> TransparentProxyManagerStatus {
        let manager = try save(
            providerBundleIdentifier: providerBundleIdentifier,
            configuration: configuration
        )

        do {
            try manager.connection.startVPNTunnel()
        } catch {
            throw TransparentProxyManagerControllerError.tunnelStartFailed(error.localizedDescription)
        }

        return status(for: manager, providerBundleIdentifier: providerBundleIdentifier)
    }

    static func stop(providerBundleIdentifier: String) throws -> TransparentProxyManagerStatus {
        let manager = try loadOrCreateManager(providerBundleIdentifier: providerBundleIdentifier)
        manager.connection.stopVPNTunnel()
        return status(for: manager, providerBundleIdentifier: providerBundleIdentifier)
    }

    static func status(providerBundleIdentifier: String) throws -> TransparentProxyManagerStatus {
        let manager = try loadOrCreateManager(providerBundleIdentifier: providerBundleIdentifier)
        return status(for: manager, providerBundleIdentifier: providerBundleIdentifier)
    }

    static func sendProviderMessage(
        providerBundleIdentifier: String,
        messageJSON: String
    ) throws -> String? {
        let manager = try loadOrCreateManager(providerBundleIdentifier: providerBundleIdentifier)
        guard let session = manager.connection as? NETunnelProviderSession else {
            throw TransparentProxyManagerControllerError.providerSessionUnavailable
        }

        let payload = Data(messageJSON.utf8)
        let semaphore = DispatchSemaphore(value: 0)
        var responseData: Data?
        var responseError: Error?

        do {
            try session.sendProviderMessage(payload) { data in
                responseData = data
                semaphore.signal()
            }
        } catch {
            throw TransparentProxyManagerControllerError.providerMessageFailed(error.localizedDescription)
        }

        if semaphore.wait(timeout: .now() + 10) == .timedOut {
            responseError = TransparentProxyManagerControllerError.providerMessageFailed("Timed out")
        }

        if let responseError {
            throw responseError
        }

        guard let responseData else {
            return nil
        }

        return String(data: responseData, encoding: .utf8)
    }

    private static func loadOrCreateManager(
        providerBundleIdentifier: String
    ) throws -> NETransparentProxyManager {
        let semaphore = DispatchSemaphore(value: 0)
        let resultBox = CallbackBox<Result<NETransparentProxyManager, Error>?>(nil)

        NETransparentProxyManager.loadAllFromPreferences { managers, error in
            if let error {
                resultBox.value = .failure(
                    TransparentProxyManagerControllerError.managerLoadFailed(error.localizedDescription)
                )
                semaphore.signal()
                return
            }

            let matchingManager = managers?.first { manager in
                guard let tunnelProtocol = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                    return false
                }
                return tunnelProtocol.providerBundleIdentifier == providerBundleIdentifier
            }

            resultBox.value = .success(matchingManager ?? NETransparentProxyManager())
            semaphore.signal()
        }

        semaphore.wait()
        return try resultBox.value!.get()
    }

    private static func waitForSave(on manager: NETransparentProxyManager) throws {
        let semaphore = DispatchSemaphore(value: 0)
        let errorBox = CallbackBox<Error?>(nil)

        manager.saveToPreferences { error in
            errorBox.value = error
            semaphore.signal()
        }

        semaphore.wait()
        if let result = errorBox.value {
            throw TransparentProxyManagerControllerError.managerSaveFailed(result.localizedDescription)
        }
    }

    private static func waitForLoad(on manager: NETransparentProxyManager) throws {
        let semaphore = DispatchSemaphore(value: 0)
        let errorBox = CallbackBox<Error?>(nil)

        manager.loadFromPreferences { error in
            errorBox.value = error
            semaphore.signal()
        }

        semaphore.wait()
        if let result = errorBox.value {
            throw TransparentProxyManagerControllerError.managerLoadFailed(result.localizedDescription)
        }
    }

    private static func status(
        for manager: NETransparentProxyManager,
        providerBundleIdentifier: String
    ) -> TransparentProxyManagerStatus {
        TransparentProxyManagerStatus(
            providerBundleIdentifier: providerBundleIdentifier,
            localizedDescription: manager.localizedDescription,
            enabled: manager.isEnabled,
            statusRawValue: manager.connection.status.rawValue,
            status: statusName(manager.connection.status)
        )
    }

    private static func statusName(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid:
            "invalid"
        case .disconnected:
            "disconnected"
        case .connecting:
            "connecting"
        case .connected:
            "connected"
        case .reasserting:
            "reasserting"
        case .disconnecting:
            "disconnecting"
        @unknown default:
            "unknown"
        }
    }
}
