import Foundation

public enum ProviderConfigurationError: Error, CustomStringConvertible {
    case missingKey(String)
    case invalidType(String)
    case invalidPort(Int)

    public var description: String {
        switch self {
        case .missingKey(let key):
            "Missing provider configuration key: \(key)"
        case .invalidType(let key):
            "Invalid provider configuration type for key: \(key)"
        case .invalidPort(let port):
            "Invalid bridge port: \(port)"
        }
    }
}

public struct ProviderConfiguration: Codable, Equatable, Sendable {
    public var bridgeHost: String
    public var bridgePort: Int
    public var tunnelAppIdentifiers: [String]
    public var captureIPv6: Bool
    public var localizedDescription: String

    public init(
        bridgeHost: String,
        bridgePort: Int,
        tunnelAppIdentifiers: [String],
        captureIPv6: Bool = false,
        localizedDescription: String = "SwiftTunnel Transparent Proxy"
    ) {
        self.bridgeHost = bridgeHost
        self.bridgePort = bridgePort
        self.tunnelAppIdentifiers = tunnelAppIdentifiers
        self.captureIPv6 = captureIPv6
        self.localizedDescription = localizedDescription
    }

    public init(dictionary: [String: Any]) throws {
        guard let bridgeHost = dictionary["bridge_host"] as? String else {
            throw ProviderConfigurationError.missingKey("bridge_host")
        }

        let bridgePort: Int
        if let port = dictionary["bridge_port"] as? Int {
            bridgePort = port
        } else if let port = dictionary["bridge_port"] as? NSNumber {
            bridgePort = port.intValue
        } else {
            throw ProviderConfigurationError.missingKey("bridge_port")
        }

        guard (1...65535).contains(bridgePort) else {
            throw ProviderConfigurationError.invalidPort(bridgePort)
        }

        let identifiers: [String]
        if let values = dictionary["tunnel_app_identifiers"] as? [String] {
            identifiers = values
        } else if dictionary["tunnel_app_identifiers"] == nil {
            identifiers = []
        } else {
            throw ProviderConfigurationError.invalidType("tunnel_app_identifiers")
        }

        let captureIPv6 = (dictionary["capture_ipv6"] as? Bool) ?? false
        let localizedDescription =
            (dictionary["localized_description"] as? String) ?? "SwiftTunnel Transparent Proxy"

        self.init(
            bridgeHost: bridgeHost,
            bridgePort: bridgePort,
            tunnelAppIdentifiers: identifiers,
            captureIPv6: captureIPv6,
            localizedDescription: localizedDescription
        )
    }

    public var normalizedAppIdentifiers: [String] {
        tunnelAppIdentifiers
            .map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .filter { !$0.isEmpty }
    }

    public func asProviderDictionary() -> [String: Any] {
        [
            "bridge_host": bridgeHost,
            "bridge_port": bridgePort,
            "tunnel_app_identifiers": tunnelAppIdentifiers,
            "capture_ipv6": captureIPv6,
            "localized_description": localizedDescription,
        ]
    }
}

public struct ProviderMessageEnvelope: Codable, Sendable {
    public var command: String
    public var configuration: ProviderConfiguration?

    public init(command: String, configuration: ProviderConfiguration? = nil) {
        self.command = command
        self.configuration = configuration
    }
}

public struct ProviderStatusPayload: Codable, Sendable {
    public var bridgeHost: String
    public var bridgePort: Int
    public var activeFlowCount: Int
    public var tunneledSigningIdentifiers: [String]
    public var configuredSigningIdentifiers: [String]

    public init(
        bridgeHost: String,
        bridgePort: Int,
        activeFlowCount: Int,
        tunneledSigningIdentifiers: [String],
        configuredSigningIdentifiers: [String]
    ) {
        self.bridgeHost = bridgeHost
        self.bridgePort = bridgePort
        self.activeFlowCount = activeFlowCount
        self.tunneledSigningIdentifiers = tunneledSigningIdentifiers
        self.configuredSigningIdentifiers = configuredSigningIdentifiers
    }
}
