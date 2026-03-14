import Foundation
import NetworkExtension
import SwiftTunnelMacOSShared

final class FlowContext: @unchecked Sendable {
    let flowID: UInt64
    let flow: NEAppProxyUDPFlow
    let defaultRemoteEndpoint: BridgeEndpoint
    let signingIdentifier: String
    var readTask: Task<Void, Never>?

    init(
        flowID: UInt64,
        flow: NEAppProxyUDPFlow,
        defaultRemoteEndpoint: BridgeEndpoint,
        signingIdentifier: String
    ) {
        self.flowID = flowID
        self.flow = flow
        self.defaultRemoteEndpoint = defaultRemoteEndpoint
        self.signingIdentifier = signingIdentifier
    }
}

final class FlowRegistry {
    private let lock = NSLock()
    private var flows: [UInt64: FlowContext] = [:]

    func register(_ context: FlowContext) {
        lock.lock()
        defer { lock.unlock() }
        flows[context.flowID] = context
    }

    func context(for flowID: UInt64) -> FlowContext? {
        lock.lock()
        defer { lock.unlock() }
        return flows[flowID]
    }

    @discardableResult
    func remove(flowID: UInt64) -> FlowContext? {
        lock.lock()
        defer { lock.unlock() }
        return flows.removeValue(forKey: flowID)
    }

    func removeAll() -> [FlowContext] {
        lock.lock()
        defer { lock.unlock() }
        let contexts = Array(flows.values)
        flows.removeAll()
        return contexts
    }

    func activeSigningIdentifiers() -> [String] {
        lock.lock()
        defer { lock.unlock() }
        let identifiers = flows.values.map(\.signingIdentifier)
        return Array(Set(identifiers)).sorted()
    }

    var count: Int {
        lock.lock()
        defer { lock.unlock() }
        return flows.count
    }
}
