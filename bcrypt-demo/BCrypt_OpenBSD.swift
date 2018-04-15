import Foundation
import bcrypt_openbsd

public struct BCrypt_BSD {
    let cost: UInt
    let algorithm: Algorithm

    enum BCryptError: Error {
         case invalidOptions
    }

    init(cost: UInt = 12) throws {
        guard cost >= 4 && cost <= 31 else {
            throw BCryptError.invalidOptions
        }

        self.cost = cost
        self.algorithm = ._2b
    }

    enum Algorithm: String, RawRepresentable {
        /// older version
        case _2a = "$2a$"
        /// format specific to the crypt_blowfish BCrypt implementation, identical to `2b` in all but name.
        case _2y = "$2y$"
        /// latest revision of the official BCrypt algorithm, current default
        case _2b = "$2b$"

        var revisionCount: Int {
            return 4
        }

        /// Salt's length
        var saltCount: Int {
            return 29
        }

        /// Checksum's length
        var checksumCount: Int {
            return 31
        }
    }

    /// Generates string (29 chars total) containing the algorithm information + the cost + base-64 encoded 22 character salt
    ///
    ///     E.g:  $2b$05$J/dtt5ybYUTCJ/dtt5ybYO
    ///           $AA$ => Algorithm
    ///              $CC$ => Cost
    ///                  SSSSSSSSSSSSSSSSSSSSSS => Salt
    ///
    /// Allowed charset for the salt: [./A-Za-z0-9]
    private func generateSalt() -> String? {
        guard let salt = try? URandom().string(count: 16)
            else { return nil }

        let encodedSaltBytes = UnsafeMutablePointer<Int8>.allocate(capacity: 25)
        encode_base64(encodedSaltBytes, salt, salt.count)

        let encodedSalt = String(cString: encodedSaltBytes)

        return
            self.algorithm.rawValue +
            (self.cost < 10 ? "0\(self.cost)" : "\(self.cost)" ) +
            "$" +
            encodedSalt
    }

    func encrypt(message: String) -> String? {
        guard let salt = generateSalt()
            else { return nil }

        return encrypt(message: message, salt: salt)
    }


    /// Returns the hash representation of the given message
    ///
    /// - Note: 2y isn't supported by OpenBSD's Bcrypt. 2b is used in it's place
    ///
    /// - Parameters:
    ///   - message: Message to hash
    ///   - salt: Salt to append to the hashed message
    /// - Returns: Hashed message
    private func encrypt(message: String, salt: String) -> String? {

        let originalAlgorithm = String( salt.prefix(algorithm.revisionCount) )

        let normalizedSalt: String
        if originalAlgorithm == Algorithm._2y.rawValue {
            normalizedSalt = Algorithm._2b.rawValue + salt.dropFirst(algorithm.revisionCount)
        } else {
            normalizedSalt = salt
        }

        let hashedBytes = UnsafeMutablePointer<Int8>.allocate(capacity: 1000)
        defer { hashedBytes.deallocate() }
        let hashingResult = bcrypt_hashpass(
            message,
            normalizedSalt,
            hashedBytes,
            128
        )

        if hashingResult == 0 {
            return nil
        } else {
            return originalAlgorithm + String(cString: hashedBytes).dropFirst(algorithm.revisionCount)
        }
    }

    func validate(message: String, hashed: String) -> Bool {

        guard let hashVersion = Algorithm(rawValue: String(hashed.prefix(4)))
            else { return false }

        let hashSalt = String(hashed.prefix(hashVersion.saltCount))
        guard !hashSalt.isEmpty, hashSalt.count == hashVersion.saltCount
            else { return false }

        let hashChecksum = String(hashed.suffix(hashVersion.checksumCount))
        guard !hashChecksum.isEmpty, hashChecksum.count == hashVersion.checksumCount
            else { return false }

        guard let messageHash = encrypt(message: message, salt: hashSalt)
            else { return false }

        return timingsafe_bcmp(messageHash, hashed, messageHash.count) == 0

        let messageHashChecksum = String(messageHash.suffix(hashVersion.checksumCount))
        guard !messageHashChecksum.isEmpty
            else { return false }

        return messageHashChecksum == hashChecksum
    }
}
