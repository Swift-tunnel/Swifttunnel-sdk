import Foundation
import Network
@preconcurrency import NetworkExtension
import SwiftTunnelMacOSShared

open class SwiftTunnelTransparentProxyProviderBase: NETransparentProxyProvider, @unchecked Sendable {
    private let stateLock = NSLock()
    private let flowRegistry = FlowRegistry()
    private var configuration: ProviderConfiguration?
    private var bridgeSocket: BridgeSocket?
    private var nextFlowID: UInt64 = 1

    open override func startProxy(
        options: [String: Any]? = nil,
        completionHandler: @escaping (Error?) -> Void
    ) {
        do {
            let configuration = try resolveConfiguration(options: options)
            try installBridgeSocket(configuration: configuration)
            try applyTransparentProxySettings(configuration: configuration, completionHandler: completionHandler)
        } catch {
            completionHandler(error)
        }
    }

    open override func stopProxy(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        for context in flowRegistry.removeAll() {
            context.readTask?.cancel()
            _ = try? sendToBridge(.closeFlow(flowID: context.flowID))
            context.flow.closeReadWithError(nil)
            context.flow.closeWriteWithError(nil)
        }

        stateLock.lock()
        bridgeSocket?.close()
        bridgeSocket = nil
        configuration = nil
        stateLock.unlock()
        completionHandler()
    }

    open override func handleAppMessage(
        _ messageData: Data,
        completionHandler: ((Data?) -> Void)? = nil
    ) {
        do {
            let envelope = try JSONDecoder().decode(ProviderMessageEnvelope.self, from: messageData)
            switch envelope.command {
            case "ping":
                completionHandler?(Data("pong".utf8))
            case "status":
                completionHandler?(try statusPayload())
            case "update_config":
                guard let configuration = envelope.configuration else {
                    completionHandler?(nil)
                    return
                }
                updateConfiguration(configuration, completionHandler: completionHandler)
            default:
                completionHandler?(nil)
            }
        } catch {
            completionHandler?(Data("error:\(error)".utf8))
        }
    }

    open func handleNewUDPFlow(
        _ flow: NEAppProxyUDPFlow,
        initialRemoteFlowEndpoint remoteFlowEndpoint: Network.NWEndpoint
    ) -> Bool {
        guard let configuration = currentConfiguration(),
              let remoteEndpoint = BridgeEndpoint(flowEndpoint: remoteFlowEndpoint),
              remoteEndpoint.isIPv4
        else {
            return false
        }

        let signingIdentifier = flow.metaData.sourceAppSigningIdentifier
            .trimmingCharacters(in: .whitespacesAndNewlines)

        guard shouldTunnel(signingIdentifier: signingIdentifier, configuration: configuration) else {
            return false
        }

        let flowID = allocateFlowID()
        let context = FlowContext(
            flowID: flowID,
            flow: flow,
            defaultRemoteEndpoint: remoteEndpoint,
            signingIdentifier: signingIdentifier
        )
        let localEndpoint = bridgeLocalEndpoint(for: flow)

        flow.open(withLocalFlowEndpoint: flow.localFlowEndpoint) { [weak self] error in
            guard let self else {
                return
            }

            if let error {
                NSLog("SwiftTunnel provider failed to open UDP flow \(flowID): \(error)")
                return
            }

            do {
                try self.sendToBridge(
                    .openFlow(
                        BridgeOpenFlow(
                            flowID: flowID,
                            localEndpoint: localEndpoint,
                            remoteEndpoint: remoteEndpoint,
                            signingIdentifier: signingIdentifier
                        )
                    )
                )
                self.flowRegistry.register(context)
                self.readLoop(for: context)
            } catch {
                NSLog("SwiftTunnel provider failed to register UDP flow \(flowID): \(error)")
                self.closeFlow(flowID: flowID)
            }
        }

        return true
    }

    private func updateConfiguration(
        _ configuration: ProviderConfiguration,
        completionHandler: ((Data?) -> Void)?
    ) {
        do {
            try installBridgeSocket(configuration: configuration)
            try applyTransparentProxySettings(configuration: configuration) { [weak self] error in
                if let error {
                    completionHandler?(Data("error:\(error.localizedDescription)".utf8))
                    return
                }

                guard let self else {
                    completionHandler?(Data("error:provider_unavailable".utf8))
                    return
                }

                do {
                    completionHandler?(try self.statusPayload())
                } catch {
                    completionHandler?(Data("error:\(error)".utf8))
                }
            }
        } catch {
            completionHandler?(Data("error:\(error)".utf8))
        }
    }

    private func resolveConfiguration(options: [String: Any]?) throws -> ProviderConfiguration {
        if let options, !options.isEmpty {
            return try ProviderConfiguration(dictionary: options)
        }

        guard let tunnelProtocol = protocolConfiguration as? NETunnelProviderProtocol,
              let providerConfiguration = tunnelProtocol.providerConfiguration
        else {
            throw ProviderConfigurationError.missingKey("providerConfiguration")
        }

        return try ProviderConfiguration(dictionary: providerConfiguration)
    }

    private func installBridgeSocket(configuration: ProviderConfiguration) throws {
        let socket = try BridgeSocket(configuration: configuration) { [weak self] message in
            self?.handleBridgeMessage(message)
        }

        stateLock.lock()
        bridgeSocket?.close()
        bridgeSocket = socket
        self.configuration = configuration
        stateLock.unlock()
    }

    private func currentConfiguration() -> ProviderConfiguration? {
        stateLock.lock()
        defer { stateLock.unlock() }
        return configuration
    }

    private func sendToBridge(_ message: BridgeMessage) throws {
        stateLock.lock()
        let socket = bridgeSocket
        stateLock.unlock()

        guard let socket else {
            throw BridgeSocketError.connectFailed(ENOTCONN)
        }

        try socket.send(message)
    }

    private func allocateFlowID() -> UInt64 {
        stateLock.lock()
        defer { stateLock.unlock() }
        let value = nextFlowID
        nextFlowID &+= 1
        return value
    }

    private func shouldTunnel(
        signingIdentifier: String,
        configuration: ProviderConfiguration
    ) -> Bool {
        let configured = configuration.normalizedAppIdentifiers
        guard !configured.isEmpty else {
            return true
        }

        let normalizedSigningIdentifier = signingIdentifier.lowercased()
        return configured.contains { identifier in
            normalizedSigningIdentifier == identifier
                || normalizedSigningIdentifier.hasSuffix(".\(identifier)")
        }
    }

    private func bridgeLocalEndpoint(for flow: NEAppProxyUDPFlow) -> BridgeEndpoint {
        guard let localFlowEndpoint = flow.localFlowEndpoint,
              let endpoint = BridgeEndpoint(flowEndpoint: localFlowEndpoint)
        else {
            return BridgeEndpoint(host: "0.0.0.0", port: 0)
        }

        return endpoint
    }

    private func networkRuleEndpoint(host: String) throws -> Network.NWEndpoint {
        guard let endpoint = BridgeEndpoint(host: host, port: 0).asFlowEndpoint() else {
            throw ProviderConfigurationError.invalidType("network_rule_\(host)")
        }
        return endpoint
    }

    private func applyTransparentProxySettings(
        configuration: ProviderConfiguration,
        completionHandler: @escaping (Error?) -> Void
    ) throws {
        let settings = NETransparentProxyNetworkSettings(tunnelRemoteAddress: configuration.bridgeHost)
        settings.includedNetworkRules = try includedRules(captureIPv6: configuration.captureIPv6)
        settings.excludedNetworkRules = try excludedRules()

        setTunnelNetworkSettings(settings) { error in
            completionHandler(error)
        }
    }

    private func includedRules(captureIPv6: Bool) throws -> [NENetworkRule] {
        var rules = [
            NENetworkRule(
                destinationNetworkEndpoint: try networkRuleEndpoint(host: "0.0.0.0"),
                prefix: 0,
                protocol: .UDP
            ),
        ]

        if captureIPv6 {
            rules.append(
                NENetworkRule(
                    destinationNetworkEndpoint: try networkRuleEndpoint(host: "::"),
                    prefix: 0,
                    protocol: .UDP
                )
            )
        }

        return rules
    }

    private func excludedRules() throws -> [NENetworkRule] {
        [
            NENetworkRule(
                destinationNetworkEndpoint: try networkRuleEndpoint(host: "127.0.0.0"),
                prefix: 8,
                protocol: .any
            ),
            NENetworkRule(
                destinationNetworkEndpoint: try networkRuleEndpoint(host: "::1"),
                prefix: 128,
                protocol: .any
            ),
        ]
    }

    private func handleBridgeMessage(_ message: BridgeMessage) {
        guard case .serverDatagram(let datagram) = message,
              let context = flowRegistry.context(for: datagram.flowID),
              let flowEndpoint = datagram.remoteEndpoint.asFlowEndpoint()
        else {
            return
        }

        Task { [weak self] in
            do {
                try await context.flow.writeDatagrams([(datagram.payload, flowEndpoint)])
            } catch {
                guard !Task.isCancelled else {
                    return
                }
                NSLog("SwiftTunnel provider failed to write datagram for flow \(datagram.flowID): \(error)")
                self?.closeFlow(flowID: datagram.flowID)
            }
        }
    }

    private func readLoop(for context: FlowContext) {
        context.readTask = Task { [weak self] in
            guard let self else {
                return
            }

            do {
                while !Task.isCancelled {
                    let (datagramsAndEndpoints, error) = await context.flow.readDatagrams()
                    if let error {
                        NSLog("SwiftTunnel provider read loop failed for flow \(context.flowID): \(error)")
                        self.closeFlow(flowID: context.flowID)
                        return
                    }

                    guard let datagramsAndEndpoints, !datagramsAndEndpoints.isEmpty else {
                        self.closeFlow(flowID: context.flowID)
                        return
                    }

                    for (payload, endpoint) in datagramsAndEndpoints {
                        let remoteEndpoint = BridgeEndpoint(flowEndpoint: endpoint)
                            ?? context.defaultRemoteEndpoint

                        guard remoteEndpoint.isIPv4 else {
                            continue
                        }

                        try self.sendToBridge(
                            .clientDatagram(
                                BridgeDatagram(
                                    flowID: context.flowID,
                                    remoteEndpoint: remoteEndpoint,
                                    payload: payload
                                )
                            )
                        )
                    }
                }
            } catch {
                guard !Task.isCancelled else {
                    return
                }
                NSLog("SwiftTunnel provider read loop failed for flow \(context.flowID): \(error)")
                self.closeFlow(flowID: context.flowID)
            }
        }
    }

    private func statusPayload() throws -> Data {
        let configuration = currentConfiguration()
        let payload = ProviderStatusPayload(
            bridgeHost: configuration?.bridgeHost ?? "",
            bridgePort: configuration?.bridgePort ?? 0,
            activeFlowCount: flowRegistry.count,
            tunneledSigningIdentifiers: flowRegistry.activeSigningIdentifiers(),
            configuredSigningIdentifiers: configuration?.normalizedAppIdentifiers ?? []
        )
        return try JSONEncoder().encode(payload)
    }

    private func closeFlow(flowID: UInt64) {
        _ = try? sendToBridge(.closeFlow(flowID: flowID))

        guard let context = flowRegistry.remove(flowID: flowID) else {
            return
        }

        context.readTask?.cancel()
        context.flow.closeReadWithError(nil)
        context.flow.closeWriteWithError(nil)
    }
}
