import Foundation

// start URandom.swift
// Origin: https://github.com/vapor/crypto/blob/master/Sources/Random/URandom.swift

#if os(Linux) || os(FreeBSD)
import Glibc
#else
import Darwin
#endif

/// URandom represents a file connection to /dev/urandom on Unix systems.
/// /dev/urandom is a cryptographically secure random generator provided by the OS.
public final class URandom {
    public enum Error: Swift.Error {
        case open(Int32)
        case read(Int32)
    }

    private let file: UnsafeMutablePointer<FILE>

    /// Initialize URandom
    public init(path: String) throws {
        guard let file = fopen(path, "rb") else {
            // The Random protocol doesn't allow init to fail, so we have to
            // check whether /dev/urandom was successfully opened here
            throw Error.open(errno)
        }
        self.file = file
    }

    deinit {
        fclose(file)
    }

    private func read(numBytes: Int) throws -> [Int8] {

        // Initialize an empty array with space for numBytes bytes
        var bytes = [Int8](repeating: 0, count: numBytes)
        guard fread(&bytes, 1, numBytes, file) == numBytes else {
            // If the requested number of random bytes couldn't be read,
            // we need to throw an error
            throw Error.read(errno)
        }

        return bytes
    }

    /// Get a random array of Bytes
    public func bytes(count: Int) throws -> [UInt8] {
        return try read(numBytes: count).map({ UInt8(bitPattern: $0) })
    }

    public func string(count: Int) throws -> String {
        let bytes = try self.bytes(count: count)

        var string = ""
        while (string.count < count) {
            string += bytes
                .compactMap({ String(bytes: [$0], encoding: .utf8) })
                .reduce("",+)
        }
        return string
    }
}

extension URandom {
    public convenience init() throws {
        try self.init(path: "/dev/urandom")
    }
}

// end URandom.swift
