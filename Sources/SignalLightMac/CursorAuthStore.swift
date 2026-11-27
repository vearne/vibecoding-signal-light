import Foundation
import Security
import SignalLightShared
import SQLite3

struct CursorAuthCredentials: Equatable {
    var accessToken: String
    var email: String?
    var planType: String?
}

enum CursorAuthStoreError: Error, LocalizedError, Equatable {
    case databaseUnreadable
    case missingAccessToken
    case keychainUnavailable
    case safeStorage(CursorSafeStorageError)

    var errorDescription: String? {
        switch self {
        case .databaseUnreadable:
            return "无法读取 Cursor 本地登录数据库"
        case .missingAccessToken:
            return "未找到 Cursor 登录信息"
        case .keychainUnavailable:
            return "无法从钥匙串读取 Cursor Safe Storage 密钥，请授权后重试"
        case .safeStorage(let error):
            return error.localizedDescription
        }
    }
}

enum CursorAuthStore {
    static let defaultDatabaseURL = FileManager.default.homeDirectoryForCurrentUser
        .appendingPathComponent("Library/Application Support/Cursor/User/globalStorage/state.vscdb", isDirectory: false)

    static let safeStorageService = "Cursor Safe Storage"
    static let safeStorageAccount = "Cursor Key"
    static let safeStorageAccountFallback = "Cursor"

    static func loadCredentials(databaseURL: URL = defaultDatabaseURL) -> CursorAuthCredentials? {
        try? loadCredentialsOrThrow(databaseURL: databaseURL)
    }

    static func loadCredentialsOrThrow(databaseURL: URL = defaultDatabaseURL) throws -> CursorAuthCredentials {
        guard FileManager.default.isReadableFile(atPath: databaseURL.path) else {
            throw CursorAuthStoreError.databaseUnreadable
        }

        var database: OpaquePointer?
        let flags = SQLITE_OPEN_READONLY | SQLITE_OPEN_NOMUTEX
        guard sqlite3_open_v2(databaseURL.path, &database, flags, nil) == SQLITE_OK,
              let database
        else {
            throw CursorAuthStoreError.databaseUnreadable
        }
        defer {
            sqlite3_close(database)
        }

        guard let storedToken = queryValue(key: "cursorAuth/accessToken", database: database),
              !storedToken.isEmpty
        else {
            throw CursorAuthStoreError.missingAccessToken
        }

        let accessToken: String
        do {
            accessToken = try CursorSafeStorage.resolveAccessToken(storedToken) {
                try loadSafeStoragePassword()
            }
        } catch let error as CursorSafeStorageError {
            throw CursorAuthStoreError.safeStorage(error)
        } catch let error as CursorAuthStoreError {
            throw error
        } catch {
            throw CursorAuthStoreError.safeStorage(.decryptionFailed)
        }

        return CursorAuthCredentials(
            accessToken: accessToken,
            email: queryValue(key: "cursorAuth/cachedEmail", database: database),
            planType: queryValue(key: "cursorAuth/stripeMembershipType", database: database)
        )
    }

    private static func loadSafeStoragePassword() throws -> String {
        if let password = readKeychainPassword(service: safeStorageService, account: safeStorageAccount) {
            return password
        }
        if let password = readKeychainPassword(service: safeStorageService, account: safeStorageAccountFallback) {
            return password
        }
        throw CursorAuthStoreError.keychainUnavailable
    }

    private static func readKeychainPassword(service: String, account: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess,
              let data = item as? Data,
              let password = String(data: data, encoding: .utf8)?
                .trimmingCharacters(in: .whitespacesAndNewlines),
              !password.isEmpty
        else {
            return nil
        }
        return password
    }

    private static func queryValue(key: String, database: OpaquePointer) -> String? {
        let sql = "SELECT value FROM ItemTable WHERE key = ?1 LIMIT 1;"
        var statement: OpaquePointer?
        guard sqlite3_prepare_v2(database, sql, -1, &statement, nil) == SQLITE_OK,
              let statement
        else {
            return nil
        }
        defer {
            sqlite3_finalize(statement)
        }

        sqlite3_bind_text(statement, 1, key, -1, unsafeBitCast(-1, to: sqlite3_destructor_type.self))
        guard sqlite3_step(statement) == SQLITE_ROW,
              let cString = sqlite3_column_text(statement, 0)
        else {
            return nil
        }

        let value = String(cString: cString).trimmingCharacters(in: .whitespacesAndNewlines)
        return value.isEmpty ? nil : value
    }
}
