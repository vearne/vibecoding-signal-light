import Foundation
import CommonCrypto

public enum CursorSafeStorageError: Error, LocalizedError, Equatable {
    case emptyToken
    case unsupportedEnvelope
    case invalidCiphertext
    case decryptionFailed

    public var errorDescription: String? {
        switch self {
        case .emptyToken:
            return "Cursor 登录 token 为空"
        case .unsupportedEnvelope:
            return "Cursor 登录凭证使用了暂不支持的加密格式"
        case .invalidCiphertext:
            return "Cursor 登录凭证密文损坏"
        case .decryptionFailed:
            return "无法解密 Cursor 登录凭证"
        }
    }
}

public enum CursorSafeStorage {
    public static let prefix = "cursor-safe-storage:v1:"

    public static func resolveAccessToken(
        _ stored: String,
        passwordProvider: () throws -> String
    ) throws -> String {
        let trimmed = stored.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else {
            throw CursorSafeStorageError.emptyToken
        }

        guard trimmed.hasPrefix(prefix) else {
            return trimmed
        }

        let password = try passwordProvider()
        return try decrypt(storedValue: trimmed, password: password)
    }

    public static func decrypt(storedValue: String, password: String) throws -> String {
        let trimmed = storedValue.trimmingCharacters(in: .whitespacesAndNewlines)
        guard trimmed.hasPrefix(prefix) else {
            throw CursorSafeStorageError.unsupportedEnvelope
        }

        let encoded = String(trimmed.dropFirst(prefix.count))
        guard let blob = Data(base64Encoded: encoded), blob.count > 3 else {
            throw CursorSafeStorageError.invalidCiphertext
        }

        let version = String(data: blob.prefix(3), encoding: .utf8)
        guard version == "v10" else {
            throw CursorSafeStorageError.unsupportedEnvelope
        }

        let ciphertext = blob.dropFirst(3)
        guard let plaintext = decryptChromiumV10(ciphertext: Data(ciphertext), password: password) else {
            throw CursorSafeStorageError.decryptionFailed
        }

        let token = plaintext.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !token.isEmpty else {
            throw CursorSafeStorageError.decryptionFailed
        }
        return token
    }

    private static func decryptChromiumV10(ciphertext: Data, password: String) -> String? {
        guard let key = deriveKey(password: password) else {
            return nil
        }

        let iv = Data(repeating: UInt8(ascii: " "), count: kCCBlockSizeAES128)
        var decrypted = Data(count: ciphertext.count + kCCBlockSizeAES128)
        let outputCapacity = decrypted.count
        var decryptedLength: Int = 0

        let status = decrypted.withUnsafeMutableBytes { decryptedBytes in
            ciphertext.withUnsafeBytes { cipherBytes in
                key.withUnsafeBytes { keyBytes in
                    iv.withUnsafeBytes { ivBytes in
                        CCCrypt(
                            CCOperation(kCCDecrypt),
                            CCAlgorithm(kCCAlgorithmAES),
                            CCOptions(kCCOptionPKCS7Padding),
                            keyBytes.baseAddress,
                            kCCKeySizeAES128,
                            ivBytes.baseAddress,
                            cipherBytes.baseAddress,
                            ciphertext.count,
                            decryptedBytes.baseAddress,
                            outputCapacity,
                            &decryptedLength
                        )
                    }
                }
            }
        }

        guard status == kCCSuccess else {
            return nil
        }

        decrypted.count = decryptedLength
        return String(data: decrypted, encoding: .utf8)
    }

    private static func deriveKey(password: String) -> Data? {
        let passwordData = Data(password.utf8)
        let salt = Data("saltysalt".utf8)
        var derived = Data(count: kCCKeySizeAES128)
        let status = derived.withUnsafeMutableBytes { derivedBytes in
            passwordData.withUnsafeBytes { passwordBytes in
                salt.withUnsafeBytes { saltBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        passwordData.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA1),
                        1003,
                        derivedBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        kCCKeySizeAES128
                    )
                }
            }
        }
        return status == kCCSuccess ? derived : nil
    }
}
