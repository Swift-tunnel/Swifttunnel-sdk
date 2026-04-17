import Foundation
import SwiftTunnelMacOSShared

enum HelperCommand {
    case activate(extensionBundleIdentifier: String)
    case status(providerBundleIdentifier: String)
    case save(providerBundleIdentifier: String, configuration: ProviderConfiguration)
    case start(providerBundleIdentifier: String, configuration: ProviderConfiguration)
    case stop(providerBundleIdentifier: String)
    case send(providerBundleIdentifier: String, messageJSON: String)

    static func parse(arguments: [String]) throws -> HelperCommand {
        guard let command = arguments.first else {
            throw HelperCLIError.usage
        }

        let options = try parseOptions(Array(arguments.dropFirst()))

        switch command {
        case "activate":
            return .activate(
                extensionBundleIdentifier: try requiredOption("extension-bundle-id", from: options)
            )
        case "status":
            return .status(
                providerBundleIdentifier: try requiredOption("provider-bundle-id", from: options)
            )
        case "save":
            return .save(
                providerBundleIdentifier: try requiredOption("provider-bundle-id", from: options),
                configuration: try decodeConfiguration(from: options)
            )
        case "start":
            return .start(
                providerBundleIdentifier: try requiredOption("provider-bundle-id", from: options),
                configuration: try decodeConfiguration(from: options)
            )
        case "stop":
            return .stop(
                providerBundleIdentifier: try requiredOption("provider-bundle-id", from: options)
            )
        case "send":
            return .send(
                providerBundleIdentifier: try requiredOption("provider-bundle-id", from: options),
                messageJSON: try requiredOption("message-json", from: options)
            )
        default:
            throw HelperCLIError.unknownCommand(command)
        }
    }

    private static func parseOptions(_ arguments: [String]) throws -> [String: String] {
        var options: [String: String] = [:]
        var index = 0

        while index < arguments.count {
            let argument = arguments[index]
            guard argument.hasPrefix("--") else {
                throw HelperCLIError.invalidOption(argument)
            }

            let key = String(argument.dropFirst(2))
            let valueIndex = index + 1
            guard valueIndex < arguments.count else {
                throw HelperCLIError.missingValue(key)
            }

            options[key] = arguments[valueIndex]
            index += 2
        }

        return options
    }

    private static func requiredOption(
        _ key: String,
        from options: [String: String]
    ) throws -> String {
        guard let value = options[key], !value.isEmpty else {
            throw HelperCLIError.missingOption(key)
        }
        return value
    }

    private static func decodeConfiguration(from options: [String: String]) throws -> ProviderConfiguration {
        let json = try requiredOption("config-json", from: options)
        let data = Data(json.utf8)
        return try JSONDecoder().decode(ProviderConfiguration.self, from: data)
    }
}

enum HelperCLIError: Error, CustomStringConvertible {
    case usage
    case unknownCommand(String)
    case invalidOption(String)
    case missingOption(String)
    case missingValue(String)
    case invalidResponse

    var description: String {
        switch self {
        case .usage:
            """
            Usage:
              swifttunnel-macos-helper activate --extension-bundle-id <bundle-id>
              swifttunnel-macos-helper status --provider-bundle-id <bundle-id>
              swifttunnel-macos-helper save --provider-bundle-id <bundle-id> --config-json <json>
              swifttunnel-macos-helper start --provider-bundle-id <bundle-id> --config-json <json>
              swifttunnel-macos-helper stop --provider-bundle-id <bundle-id>
              swifttunnel-macos-helper send --provider-bundle-id <bundle-id> --message-json <json>
            """
        case .unknownCommand(let command):
            "Unknown helper command: \(command)"
        case .invalidOption(let option):
            "Invalid option syntax: \(option)"
        case .missingOption(let key):
            "Missing required option --\(key)"
        case .missingValue(let key):
            "Missing value for option --\(key)"
        case .invalidResponse:
            "Provider did not return a valid response"
        }
    }
}
