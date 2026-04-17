import Darwin
import Foundation
import SwiftTunnelMacOSShared

do {
    let command = try HelperCommand.parse(arguments: Array(CommandLine.arguments.dropFirst()))
    let output = try run(command)
    FileHandle.standardOutput.write(Data(output.utf8))
    FileHandle.standardOutput.write(Data("\n".utf8))
} catch {
    let message = String(describing: error)
    FileHandle.standardError.write(Data(message.utf8))
    FileHandle.standardError.write(Data("\n".utf8))
    Darwin.exit(1)
}

private func run(_ command: HelperCommand) throws -> String {
    switch command {
    case .activate(let extensionBundleIdentifier):
        return try jsonString([
            "result": SystemExtensionActivator.activate(
                extensionBundleIdentifier: extensionBundleIdentifier
            )
        ])
    case .status(let providerBundleIdentifier):
        let status = try TransparentProxyManagerController.status(
            providerBundleIdentifier: providerBundleIdentifier
        )
        return try jsonString(status)
    case .save(let providerBundleIdentifier, let configuration):
        let manager = try TransparentProxyManagerController.save(
            providerBundleIdentifier: providerBundleIdentifier,
            configuration: configuration
        )
        let status = TransparentProxyManagerStatus(
            providerBundleIdentifier: providerBundleIdentifier,
            localizedDescription: manager.localizedDescription,
            enabled: manager.isEnabled,
            statusRawValue: manager.connection.status.rawValue,
            status: "saved"
        )
        return try jsonString(status)
    case .start(let providerBundleIdentifier, let configuration):
        let status = try TransparentProxyManagerController.start(
            providerBundleIdentifier: providerBundleIdentifier,
            configuration: configuration
        )
        return try jsonString(status)
    case .stop(let providerBundleIdentifier):
        let status = try TransparentProxyManagerController.stop(
            providerBundleIdentifier: providerBundleIdentifier
        )
        return try jsonString(status)
    case .send(let providerBundleIdentifier, let messageJSON):
        let response = try TransparentProxyManagerController.sendProviderMessage(
            providerBundleIdentifier: providerBundleIdentifier,
            messageJSON: messageJSON
        )
        return response ?? "{}"
    }
}

private func jsonString<T: Encodable>(_ value: T) throws -> String {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
    let data = try encoder.encode(value)
    return String(decoding: data, as: UTF8.self)
}

private func jsonString(_ value: [String: String]) throws -> String {
    let data = try JSONSerialization.data(withJSONObject: value, options: [.prettyPrinted, .sortedKeys])
    return String(decoding: data, as: UTF8.self)
}
