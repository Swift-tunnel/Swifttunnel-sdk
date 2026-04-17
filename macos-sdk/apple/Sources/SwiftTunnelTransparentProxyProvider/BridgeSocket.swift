import Darwin
import Foundation
import SwiftTunnelMacOSShared

enum BridgeSocketError: Error, CustomStringConvertible {
    case socketCreationFailed(Int32)
    case bindFailed(Int32)
    case connectFailed(Int32)
    case sendFailed(Int32)
    case decodeFailed(String)
    case invalidBridgeHost(String)

    var description: String {
        switch self {
        case .socketCreationFailed(let code):
            "Failed to create bridge UDP socket (\(code))"
        case .bindFailed(let code):
            "Failed to bind bridge UDP socket (\(code))"
        case .connectFailed(let code):
            "Failed to connect bridge UDP socket (\(code))"
        case .sendFailed(let code):
            "Failed to send bridge datagram (\(code))"
        case .decodeFailed(let message):
            "Failed to decode bridge datagram: \(message)"
        case .invalidBridgeHost(let host):
            "Bridge host must be an IPv4 address, got '\(host)'"
        }
    }
}

final class BridgeSocket {
    private let queue = DispatchQueue(label: "net.swifttunnel.macos.bridge-socket")
    private var readSource: DispatchSourceRead?
    private(set) var configuration: ProviderConfiguration
    private(set) var fileDescriptor: Int32
    private let onMessage: (BridgeMessage) -> Void

    init(configuration: ProviderConfiguration, onMessage: @escaping (BridgeMessage) -> Void) throws {
        self.configuration = configuration
        self.onMessage = onMessage

        let fileDescriptor = Darwin.socket(AF_INET, Int32(SOCK_DGRAM), IPPROTO_UDP)
        guard fileDescriptor >= 0 else {
            throw BridgeSocketError.socketCreationFailed(errno)
        }

        self.fileDescriptor = fileDescriptor
        try bindLocalLoopback()
        try connectToBridge()
        try configureNonBlocking()
        installReadSource()
    }

    deinit {
        close()
    }

    func send(_ message: BridgeMessage) throws {
        let encoded = try BridgeCodec.encode(message)
        let result = encoded.withUnsafeBytes { buffer in
            Darwin.send(fileDescriptor, buffer.baseAddress, buffer.count, 0)
        }

        guard result >= 0 else {
            throw BridgeSocketError.sendFailed(errno)
        }
    }

    func close() {
        readSource?.cancel()
        readSource = nil

        if fileDescriptor >= 0 {
            Darwin.close(fileDescriptor)
            fileDescriptor = -1
        }
    }

    private func bindLocalLoopback() throws {
        var bindAddress = sockaddr_in()
        bindAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        bindAddress.sin_family = sa_family_t(AF_INET)
        bindAddress.sin_port = in_port_t(0).bigEndian
        bindAddress.sin_addr = in_addr(s_addr: inet_addr("127.0.0.1"))

        let result = withUnsafePointer(to: &bindAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.bind(fileDescriptor, sockaddrPointer, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }

        guard result == 0 else {
            throw BridgeSocketError.bindFailed(errno)
        }
    }

    private func connectToBridge() throws {
        var bridgeAddress = sockaddr_in()
        bridgeAddress.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        bridgeAddress.sin_family = sa_family_t(AF_INET)
        bridgeAddress.sin_port = in_port_t(UInt16(configuration.bridgePort).bigEndian)

        let parsed = configuration.bridgeHost.withCString {
            inet_pton(AF_INET, $0, &bridgeAddress.sin_addr)
        }
        guard parsed == 1 else {
            throw BridgeSocketError.invalidBridgeHost(configuration.bridgeHost)
        }

        let result = withUnsafePointer(to: &bridgeAddress) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { sockaddrPointer in
                Darwin.connect(
                    fileDescriptor,
                    sockaddrPointer,
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }

        guard result == 0 else {
            throw BridgeSocketError.connectFailed(errno)
        }
    }

    private func configureNonBlocking() throws {
        let flags = fcntl(fileDescriptor, F_GETFL, 0)
        guard flags >= 0 else {
            throw BridgeSocketError.connectFailed(errno)
        }
        guard fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK) == 0 else {
            throw BridgeSocketError.connectFailed(errno)
        }
    }

    private func installReadSource() {
        let source = DispatchSource.makeReadSource(fileDescriptor: fileDescriptor, queue: queue)
        source.setEventHandler { [weak self] in
            self?.readAvailableMessages()
        }
        source.setCancelHandler { [fd = fileDescriptor] in
            if fd >= 0 {
                Darwin.shutdown(fd, SHUT_RDWR)
            }
        }
        source.resume()
        readSource = source
    }

    private func readAvailableMessages() {
        var buffer = [UInt8](repeating: 0, count: Int(UInt16.max) + 32)

        while true {
            let count = buffer.withUnsafeMutableBytes { bytes in
                Darwin.recv(fileDescriptor, bytes.baseAddress, bytes.count, 0)
            }

            if count == 0 {
                return
            }

            if count < 0 {
                if errno == EWOULDBLOCK || errno == EAGAIN {
                    return
                }
                return
            }

            let data = Data(buffer.prefix(count))
            do {
                let message = try BridgeCodec.decode(data)
                onMessage(message)
            } catch {
                NSLog("SwiftTunnel bridge decode failed: \(error)")
            }
        }
    }
}
