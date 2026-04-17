import Darwin
import Foundation
import Network

public enum BridgeProtocolError: Error, CustomStringConvertible {
    case invalidMagic
    case unsupportedMessageType(UInt8)
    case unsupportedAddressFamily(UInt8)
    case truncated
    case unsupportedAddress(String)
    case invalidUTF8
    case payloadTooLarge(Int)

    public var description: String {
        switch self {
        case .invalidMagic:
            "Invalid SwiftTunnel bridge magic"
        case .unsupportedMessageType(let type):
            "Unsupported bridge message type: \(type)"
        case .unsupportedAddressFamily(let family):
            "Unsupported bridge address family: \(family)"
        case .truncated:
            "Truncated bridge message"
        case .unsupportedAddress(let address):
            "Unsupported bridge address: \(address)"
        case .invalidUTF8:
            "Invalid UTF-8 in bridge message"
        case .payloadTooLarge(let size):
            "Bridge payload too large: \(size) bytes"
        }
    }
}

public struct BridgeEndpoint: Equatable, Sendable {
    public var host: String
    public var port: UInt16

    public init(host: String, port: UInt16) {
        self.host = host
        self.port = port
    }

    public init?(host: String, portString: String) {
        guard let port = UInt16(portString) else {
            return nil
        }
        self.init(host: host, port: port)
    }

    public init?(flowEndpoint: Network.NWEndpoint) {
        guard case let .hostPort(host, port) = flowEndpoint else {
            return nil
        }

        switch host {
        case .ipv4(let address):
            self.init(host: address.debugDescription, port: port.rawValue)
        case .ipv6(let address):
            self.init(host: address.debugDescription, port: port.rawValue)
        case .name(let name, _):
            self.init(host: name, port: port.rawValue)
        default:
            return nil
        }
    }

    public var isIPv4: Bool {
        var address = in_addr()
        return host.withCString { inet_pton(AF_INET, $0, &address) } == 1
    }

    public var isIPv6: Bool {
        var address = in6_addr()
        return host.withCString { inet_pton(AF_INET6, $0, &address) } == 1
    }

    public func asFlowEndpoint() -> Network.NWEndpoint? {
        guard let port = Network.NWEndpoint.Port(rawValue: port) else {
            return nil
        }

        if let address = IPv4Address(host) {
            return .hostPort(host: .ipv4(address), port: port)
        }

        if let address = IPv6Address(host) {
            return .hostPort(host: .ipv6(address), port: port)
        }

        return nil
    }
}

public struct BridgeOpenFlow: Equatable, Sendable {
    public var flowID: UInt64
    public var localEndpoint: BridgeEndpoint
    public var remoteEndpoint: BridgeEndpoint
    public var signingIdentifier: String

    public init(
        flowID: UInt64,
        localEndpoint: BridgeEndpoint,
        remoteEndpoint: BridgeEndpoint,
        signingIdentifier: String
    ) {
        self.flowID = flowID
        self.localEndpoint = localEndpoint
        self.remoteEndpoint = remoteEndpoint
        self.signingIdentifier = signingIdentifier
    }
}

public struct BridgeDatagram: Equatable, Sendable {
    public var flowID: UInt64
    public var remoteEndpoint: BridgeEndpoint
    public var payload: Data

    public init(flowID: UInt64, remoteEndpoint: BridgeEndpoint, payload: Data) {
        self.flowID = flowID
        self.remoteEndpoint = remoteEndpoint
        self.payload = payload
    }
}

public enum BridgeMessage: Equatable, Sendable {
    case openFlow(BridgeOpenFlow)
    case clientDatagram(BridgeDatagram)
    case closeFlow(flowID: UInt64)
    case serverDatagram(BridgeDatagram)
}

private enum BridgeMessageType: UInt8 {
    case openFlow = 0x01
    case clientDatagram = 0x02
    case closeFlow = 0x03
    case serverDatagram = 0x04
}

private let bridgeMagic: [UInt8] = [0x53, 0x54, 0x42, 0x31] // STB1

private struct DataCursor {
    let data: Data
    var offset: Int = 0

    mutating func readByte() throws -> UInt8 {
        guard offset < data.count else {
            throw BridgeProtocolError.truncated
        }
        let value = data[offset]
        offset += 1
        return value
    }

    mutating func readUInt16() throws -> UInt16 {
        let upper = try UInt16(readByte())
        let lower = try UInt16(readByte())
        return (upper << 8) | lower
    }

    mutating func readUInt64() throws -> UInt64 {
        var value: UInt64 = 0
        for _ in 0..<8 {
            value = (value << 8) | UInt64(try readByte())
        }
        return value
    }

    mutating func readData(length: Int) throws -> Data {
        guard offset + length <= data.count else {
            throw BridgeProtocolError.truncated
        }
        let slice = data[offset..<(offset + length)]
        offset += length
        return Data(slice)
    }
}

public enum BridgeCodec {
    public static func encode(_ message: BridgeMessage) throws -> Data {
        var data = Data(bridgeMagic)

        switch message {
        case .openFlow(let openFlow):
            data.append(BridgeMessageType.openFlow.rawValue)
            appendUInt64(openFlow.flowID, into: &data)
            try appendEndpoint(openFlow.localEndpoint, into: &data)
            try appendEndpoint(openFlow.remoteEndpoint, into: &data)
            try appendOptionalString(openFlow.signingIdentifier, into: &data)
            try appendOptionalString(nil, into: &data)
        case .clientDatagram(let datagram):
            data.append(BridgeMessageType.clientDatagram.rawValue)
            appendUInt64(datagram.flowID, into: &data)
            try appendEndpoint(datagram.remoteEndpoint, into: &data)
            try appendPayload(datagram.payload, into: &data)
        case .closeFlow(let flowID):
            data.append(BridgeMessageType.closeFlow.rawValue)
            appendUInt64(flowID, into: &data)
        case .serverDatagram(let datagram):
            data.append(BridgeMessageType.serverDatagram.rawValue)
            appendUInt64(datagram.flowID, into: &data)
            try appendEndpoint(datagram.remoteEndpoint, into: &data)
            try appendPayload(datagram.payload, into: &data)
        }

        return data
    }

    public static func decode(_ data: Data) throws -> BridgeMessage {
        var cursor = DataCursor(data: data)
        let magic = try cursor.readData(length: bridgeMagic.count)
        guard Array(magic) == bridgeMagic else {
            throw BridgeProtocolError.invalidMagic
        }

        let rawType = try cursor.readByte()
        guard let type = BridgeMessageType(rawValue: rawType) else {
            throw BridgeProtocolError.unsupportedMessageType(rawType)
        }

        switch type {
        case .openFlow:
            let flowID = try cursor.readUInt64()
            let localEndpoint = try decodeEndpoint(from: &cursor)
            let remoteEndpoint = try decodeEndpoint(from: &cursor)
            let signingIdentifier = try decodeOptionalString(from: &cursor) ?? ""
            if cursor.offset < cursor.data.count {
                _ = try decodeOptionalString(from: &cursor)
            }
            return .openFlow(
                BridgeOpenFlow(
                    flowID: flowID,
                    localEndpoint: localEndpoint,
                    remoteEndpoint: remoteEndpoint,
                    signingIdentifier: signingIdentifier
                )
            )
        case .clientDatagram:
            let flowID = try cursor.readUInt64()
            let remoteEndpoint = try decodeEndpoint(from: &cursor)
            let payload = try decodePayload(from: &cursor)
            return .clientDatagram(
                BridgeDatagram(
                    flowID: flowID,
                    remoteEndpoint: remoteEndpoint,
                    payload: payload
                )
            )
        case .closeFlow:
            return .closeFlow(flowID: try cursor.readUInt64())
        case .serverDatagram:
            let flowID = try cursor.readUInt64()
            let remoteEndpoint = try decodeEndpoint(from: &cursor)
            let payload = try decodePayload(from: &cursor)
            return .serverDatagram(
                BridgeDatagram(
                    flowID: flowID,
                    remoteEndpoint: remoteEndpoint,
                    payload: payload
                )
            )
        }
    }

    private static func appendUInt16(_ value: UInt16, into data: inout Data) {
        data.append(UInt8((value >> 8) & 0xFF))
        data.append(UInt8(value & 0xFF))
    }

    private static func appendUInt64(_ value: UInt64, into data: inout Data) {
        for shift in stride(from: 56, through: 0, by: -8) {
            data.append(UInt8((value >> UInt64(shift)) & 0xFF))
        }
    }

    private static func appendEndpoint(_ endpoint: BridgeEndpoint, into data: inout Data) throws {
        guard endpoint.isIPv4 else {
            throw BridgeProtocolError.unsupportedAddress(endpoint.host)
        }

        var rawAddress = in_addr()
        let parsed = endpoint.host.withCString { inet_pton(AF_INET, $0, &rawAddress) }
        guard parsed == 1 else {
            throw BridgeProtocolError.unsupportedAddress(endpoint.host)
        }

        let octets = withUnsafeBytes(of: &rawAddress) { Array($0.prefix(4)) }
        data.append(0x04)
        appendUInt16(endpoint.port, into: &data)
        data.append(contentsOf: octets)
    }

    private static func decodeEndpoint(from cursor: inout DataCursor) throws -> BridgeEndpoint {
        let family = try cursor.readByte()
        let port = try cursor.readUInt16()
        guard family == 0x04 else {
            throw BridgeProtocolError.unsupportedAddressFamily(family)
        }

        let address = try cursor.readData(length: 4)
        let octets = Array(address)
        let host = "\(octets[0]).\(octets[1]).\(octets[2]).\(octets[3])"
        return BridgeEndpoint(host: host, port: port)
    }

    private static func appendOptionalString(_ value: String?, into data: inout Data) throws {
        guard let value, !value.isEmpty else {
            appendUInt16(0, into: &data)
            return
        }

        let utf8 = Data(value.utf8)
        guard utf8.count <= Int(UInt16.max) else {
            throw BridgeProtocolError.payloadTooLarge(utf8.count)
        }
        appendUInt16(UInt16(utf8.count), into: &data)
        data.append(utf8)
    }

    private static func decodeOptionalString(from cursor: inout DataCursor) throws -> String? {
        let length = Int(try cursor.readUInt16())
        guard length > 0 else {
            return nil
        }
        let data = try cursor.readData(length: length)
        guard let string = String(data: data, encoding: .utf8) else {
            throw BridgeProtocolError.invalidUTF8
        }
        return string
    }

    private static func appendPayload(_ payload: Data, into data: inout Data) throws {
        guard payload.count <= Int(UInt16.max) else {
            throw BridgeProtocolError.payloadTooLarge(payload.count)
        }
        appendUInt16(UInt16(payload.count), into: &data)
        data.append(payload)
    }

    private static func decodePayload(from cursor: inout DataCursor) throws -> Data {
        let length = Int(try cursor.readUInt16())
        return try cursor.readData(length: length)
    }
}
