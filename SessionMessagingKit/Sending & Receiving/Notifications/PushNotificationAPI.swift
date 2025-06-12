// Copyright © 2022 Rangeproof Pty Ltd. All rights reserved.

import Foundation
import GRDB
import Combine
import CryptoKit // CryptoKitをインポート
import SessionSnodeKit
import SessionUtilitiesKit

// エラーの定義
enum PushAPIError: Error, LocalizedError {
    case invalidJSON
    case requestFailed(String)
    case cryptoError(String)
    case invalidServerPublicKey
    case networkError(statusCode: Int, data: Data?)

    var errorDescription: String? {
        switch self {
        case .invalidJSON: return "Failed to encode the request body into JSON."
        case .requestFailed(let message): return message
        case .cryptoError(let message): return "Cryptography operation failed: \(message)"
        case .invalidServerPublicKey: return "The server public key is invalid."
        case .networkError(let statusCode, _): return "Network request failed with status code: \(statusCode)."
        }
    }
}

// MARK: - KeychainStorage

public extension KeychainStorage.DataKey { static let pushNotificationEncryptionKey: Self = "PNEncryptionKeyKey" }


private extension Log.Category {
    static let cat: Log.Category = .create("PushNotificationAPI", defaultLevel: .info)
}

// 暗号化されたリクエストボディの構造
struct EncryptedRequestBody: Codable {
    let ephemeralPublicKey: String // Base64 encoded client's temporary public key
    let sealedBox: String          // Base64 encoded (ciphertext + nonce + tag)
}

@objc(LKPushNotificationAPI)
public final class PushNotificationAPI : NSObject {
    // (RequestBodyのstruct定義は変更なし)
    struct RegistrationRequestBody: Codable {
        let token: String
        let pubKey: String?
        let closedGroupPublicKey: Set<String>?
    }
    
    struct NotifyRequestBody: Codable {
        enum CodingKeys: String, CodingKey {
            case data
            case sendTo = "send_to"
        }
        
        let data: String
        let sendTo: String
    }
    
    struct ClosedGroupRequestBody: Codable {
        let closedGroupPublicKey: String
        let pubKey: String
    }
    private var cancellables = Set<AnyCancellable>()
    internal static let encryptionKeyLength: Int = 32
    public static let maxRetryCount: Int = 4
    public static let tokenExpirationInterval: TimeInterval = (12 * 60 * 60)
    // MARK: - Settings
    public static let server = "http://172.105.193.245:5000"
    // サーバーのx25519公開鍵
    public static let serverPublicKey = "2323316383d95591b44964435b93042c73fb1a85053a4dfe04606b682d6afc61"

    @objc public enum ClosedGroupOperation : Int {
        case subscribe, unsubscribe
        
        public var endpoint: String {
            switch self {
                case .subscribe: return "subscribe_closed_group"
                case .unsubscribe: return "unsubscribe_closed_group"
            }
        }
    }
    // MARK: - Prepared Requests
    
    public static func preparedSubscribe(
        _ db: Database,
        token: Data,
        sessionIds: [SessionId],
        using dependencies: Dependencies
    ) throws -> AnyPublisher<SubscribeResponse, Error> {
        guard dependencies[defaults: .standard, key: .isUsingFullAPNs] else {
            throw NetworkError.invalidPreparedRequest
        }
        
        
        
            let userSessionId: SessionId = dependencies[cache: .general].sessionId
            let hexEncodedToken: String = token.toHexString()
            
            
            // データベースからのデータ読み取りは同期的に行い、必要なIDを取得
            let groupThreadIds: Set<String> = try dependencies[singleton: .storage].read { db in
                // ClosedGroupからグループのthreadIdを抽出
                return try ClosedGroup.fetchThreadIdsBySessionIdPrefix(db, sessionIdPrefix: .group)
            } ?? [] // エラーハンドリングとしてnilの場合に空のSetを返すなど
            

            let sessionIdsForRequest: [String] = groupThreadIds.map { idString in
                // SessionId.init(.group, hex: idString) を使用してSessionIdを作成し、hexStringを取得
                return SessionId(.group, hex: idString).hexString
            }
            
            
            let requestBody = RegistrationRequestBody(token: token.toHexString(), pubKey: userSessionId.hexString, closedGroupPublicKey: groupThreadIds)
            let url = URL(string: "\(server)/subscribe_closed_group")!
            
            return PushNotificationAPI.sendEncryptedRequestCombine(url: url, body: requestBody)
                .tryMap { data in
                    dependencies[defaults: .standard, key: .deviceToken] = nil
                    // 成功レスポンスのボディを返す
                    do{
                        var result:PushNotificationAPI.SubscribeResponse = try JSONDecoder().decode(PushNotificationAPI.SubscribeResponse.self, from: data.0)
                        return result
                    }
                    catch
                    {
                        throw PushAPIError.networkError(statusCode: (error as? URLError)?.errorCode ?? -999, data: nil)
                    }
                    
                }
                .mapError { error -> PushAPIError in
                    // URLSessionのエラーや、tryMapでスローされたエラーをPushAPIErrorに変換
                    if let apiError = error as? PushAPIError {
                        return apiError
                    } else {
                        return PushAPIError.networkError(statusCode: (error as? URLError)?.errorCode ?? -999, data: nil) // より詳細なエラーハンドリングが必要な場合もあります
                    }
                }
                .eraseToAnyPublisher()
    }
    public static func preparedUnsubscribe(
        _ db: Database,
        token: Data,
        sessionIds: [SessionId],
        using dependencies: Dependencies
    ) throws -> AnyPublisher<UnsubscribeResponse, Error> {
        let userSessionId: SessionId = dependencies[cache: .general].sessionId
        let hexEncodedToken: String = token.toHexString()
        
        
        // データベースからのデータ読み取りは同期的に行い、必要なIDを取得
        let groupThreadIds: Set<String> = try dependencies[singleton: .storage].read { db in
            // ClosedGroupからグループのthreadIdを抽出
            return try ClosedGroup.fetchThreadIdsBySessionIdPrefix(db, sessionIdPrefix: .group)
        } ?? [] // エラーハンドリングとしてnilの場合に空のSetを返すなど
        

        let sessionIdsForRequest: [String] = groupThreadIds.map { idString in
            // SessionId.init(.group, hex: idString) を使用してSessionIdを作成し、hexStringを取得
            return SessionId(.group, hex: idString).hexString
        }
        
        
        let requestBody = RegistrationRequestBody(token: token.toHexString(), pubKey: userSessionId.hexString, closedGroupPublicKey: groupThreadIds)
        let url = URL(string: "\(server)/unsubscribe_closed_group")!
        
        return PushNotificationAPI.sendEncryptedRequestCombine(url: url, body: requestBody)
            .tryMap { data in
                dependencies[defaults: .standard, key: .deviceToken] = nil
                // 成功レスポンスのボディを返す
                do{
                    var result:PushNotificationAPI.UnsubscribeResponse = try JSONDecoder().decode(PushNotificationAPI.UnsubscribeResponse.self, from: data.0)
                    return result
                }
                catch
                {
                    throw PushAPIError.networkError(statusCode: (error as? URLError)?.errorCode ?? -999, data: nil)
                }
                
            }
            .mapError { error -> PushAPIError in
                // URLSessionのエラーや、tryMapでスローされたエラーをPushAPIErrorに変換
                if let apiError = error as? PushAPIError {
                    return apiError
                } else {
                    return PushAPIError.networkError(statusCode: (error as? URLError)?.errorCode ?? -999, data: nil) // より詳細なエラーハンドリングが必要な場合もあります
                }
            }
            .eraseToAnyPublisher()
    }
    // MARK: - Initialization
    private override init() { }
    // 型を消去したAnyPublisherを公開
    // MARK: - Registration
    public static func unsubscribeAll(token: Data,using dependencies: Dependencies) -> AnyPublisher<Void, Error> {
        let hexEncodedToken: String = token.toHexString()
        let requestBody = RegistrationRequestBody(token: token.toHexString(), pubKey: nil, closedGroupPublicKey: nil)
        let url = URL(string: "\(server)/unregister")!
        
        return PushNotificationAPI.sendEncryptedRequestCombine(url: url, body: requestBody)
            .tryMap { data in
                dependencies[defaults: .standard, key: .deviceToken] = nil
                // 成功レスポンスのボディを返す
                return
            }
            .mapError { error -> PushAPIError in
                // URLSessionのエラーや、tryMapでスローされたエラーをPushAPIErrorに変換
                if let apiError = error as? PushAPIError {
                    return apiError
                } else {
                    return PushAPIError.networkError(statusCode: (error as? URLError)?.errorCode ?? -999, data: nil) // より詳細なエラーハンドリングが必要な場合もあります
                }
            }
            .eraseToAnyPublisher()
        //レスポンスが200-299であることは前提にしていい
    }
    public static func subscribeAll(
        token: Data,
        isForcedUpdate: Bool,
        using dependencies: Dependencies
    ) -> AnyPublisher<Void, Error> {
        let hexEncodedToken: String = token.toHexString()
        let oldToken: String? = dependencies[defaults: .standard, key: .deviceToken]
        let lastUploadTime: Double = dependencies[defaults: .standard, key: .lastDeviceTokenUpload]
        let now: TimeInterval = dependencies.dateNow.timeIntervalSince1970
        let userSessionId: SessionId = dependencies[cache: .general].sessionId
        guard isForcedUpdate || hexEncodedToken != oldToken || now - lastUploadTime > tokenExpirationInterval else {
            Log.info(.cat, "Device token hasn't changed or expired; no need to re-upload.")
            return Just(())
                .setFailureType(to: Error.self)
                .eraseToAnyPublisher()
        }
        let url = URL(string: "\(server)/subscribe_closed_group")!
        // データベースからのデータ読み取りは同期的に行い、必要なIDを取得
        let groupThreadIds: Set<String> = try dependencies[singleton: .storage].read { db in
            // ClosedGroupからグループのthreadIdを抽出
            return try ClosedGroup.fetchThreadIdsBySessionIdPrefix(db, sessionIdPrefix: .group)
        } ?? [] // エラーハンドリングとしてnilの場合に空のSetを返すなど
        

        let sessionIdsForRequest: [String] = groupThreadIds.map { idString in
            // SessionId.init(.group, hex: idString) を使用してSessionIdを作成し、hexStringを取得
            return SessionId(.group, hex: idString).hexString
        }
        
        // ユーザー自身のSessionIdも追加する場合（既存のコードの例に倣って）
        let allSessionIds = [userSessionId.hexString] + sessionIdsForRequest
        
        
        let requestBody = RegistrationRequestBody(token: token.toHexString(), pubKey: userSessionId.hexString, closedGroupPublicKey: groupThreadIds)
            
        return PushNotificationAPI.sendEncryptedRequestCombine(url: url, body: requestBody)
            .tryMap { data, response in
                // 成功レスポンスのボディを返す
                dependencies[defaults: .standard, key: .deviceToken] = hexEncodedToken
                dependencies[defaults: .standard, key: .lastDeviceTokenUpload] = now
                dependencies[defaults: .standard, key: .isUsingFullAPNs] = true
                return
            }
            .mapError { error -> PushAPIError in
                // URLSessionのエラーや、tryMapでスローされたエラーをPushAPIErrorに変換
                if let apiError = error as? PushAPIError {
                    return apiError
                } else {
                    return PushAPIError.networkError(statusCode: (error as? URLError)?.errorCode ?? -999, data: nil) // より詳細なエラーハンドリングが必要な場合もあります
                }
            }
            .eraseToAnyPublisher()
        }
    // MARK: - Notify
    
    public static func notify(
        recipient: String,
        with message: String,
        maxRetryCount: UInt? = nil,
        queue: DispatchQueue = DispatchQueue.global()
    ) async {
        let requestBody: NotifyRequestBody = NotifyRequestBody(data: message, sendTo: recipient)
        
        guard let body: Data = try? JSONEncoder().encode(requestBody) else {
            return
        }
        
        //let url = URL(string: "\(server)/notify")!
        let url = URL(string: "\(server)/notify")!
        let retryCount: UInt = 1
        do
        {
            try await PushNotificationAPI.sendEncryptedRequest<NotifyRequestBody>(url:url, body:requestBody, maxRetryCount: retryCount)
        }
        catch
        {
            return
        }
        
        return
    }
}


// MARK: - Private Helpers
public extension PushNotificationAPI {
    /// 暗号化されたリクエストをURLSessionで送信するメインのヘルパー関数
    static func sendEncryptedRequest<T: Codable>(url: URL, body: T, maxRetryCount: UInt = UInt(PushNotificationAPI.maxRetryCount)) async throws -> (Data, HTTPURLResponse){
        // 平文のJSONデータを生成
        let plaintextData = try JSONEncoder().encode(body)
        
        // リトライ処理
        return try await attempt(maxRetryCount: maxRetryCount) {
            // 1. ボディを暗号化
            let encryptedBody = try encryptBody(plaintext: plaintextData)

            // 2. URLRequestを作成
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = encryptedBody

            // 3. URLSessionでリクエストを送信
            let (data, response) = try await URLSession.shared.data(for: request)

            guard let httpResponse = response as? HTTPURLResponse else {
                throw PushAPIError.networkError(statusCode: -1, data: nil)
            }
            
            // ステータスコード2xx以外はエラー
            guard (200...299).contains(httpResponse.statusCode) else {
                throw PushAPIError.networkError(statusCode: httpResponse.statusCode, data: data)
            }

            // サーバーからのレスポンスをデコード（必要に応じて）
            // ここでは成功レスポンスのボディは問わないが、エラーメッセージ等が含まれる場合はデコード処理を追加
            // 例: let serverResponse = try JSONDecoder().decode(ServerResponse.self, from: data)
            return (data, httpResponse)
        }
    }


    static func sendEncryptedRequestCombine<T: Codable>(url: URL, body: T, maxRetryCount: Int = Int(PushNotificationAPI.maxRetryCount)) -> AnyPublisher<(Data, HTTPURLResponse), Error> {
        do {
            // 平文のJSONデータを生成
            let plaintextData = try JSONEncoder().encode(body)
            
            // ボディを暗号化
            let encryptedBody = try encryptBody(plaintext: plaintextData) // encryptBodyは既存のものとします

            // URLRequestを作成
            var request = URLRequest(url: url)
            request.httpMethod = "POST"
            request.setValue("application/json", forHTTPHeaderField: "Content-Type")
            request.httpBody = encryptedBody

            return URLSession.shared.dataTaskPublisher(for: request)
                .tryMap { data, response in
                    guard let httpResponse = response as? HTTPURLResponse else {
                        throw PushAPIError.networkError(statusCode: -1, data: nil)
                    }
                    
                    // ステータスコード2xx以外はエラー
                    guard (200...299).contains(httpResponse.statusCode) else {
                        throw PushAPIError.networkError(statusCode: httpResponse.statusCode, data: data)
                    }
                    
                    // 成功レスポンスのボディを返す
                    return (data, httpResponse)
                }
                .mapError { error -> PushAPIError in
                    // URLSessionのエラーや、tryMapでスローされたエラーをPushAPIErrorに変換
                    if let apiError = error as? PushAPIError {
                        return apiError
                    } else {
                        return PushAPIError.networkError(statusCode: (error as? URLError)?.errorCode ?? -999, data: nil) // より詳細なエラーハンドリングが必要な場合もあります
                    }
                }
                .retry(maxRetryCount) // リトライ処理
                .eraseToAnyPublisher() // 型をAnyPublisherに消去
        } catch {
            // JSONエンコードや暗号化でエラーが発生した場合
            return Fail(error: PushAPIError.networkError(statusCode: -1, data: nil)) // より具体的なエラーを返すことも可能
                .eraseToAnyPublisher()
        }
    }
    
    
    /// CryptoKitを使ってリクエストボディを暗号化する
    static func encryptBody(plaintext: Data) throws -> Data {
        // サーバーの公開鍵をDataに変換
        guard let serverPublicKeyData = Data(hexString: serverPublicKey) else {
            throw PushAPIError.cryptoError("Invalid server public key hex string.")
        }
        let serverKey = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: serverPublicKeyData)

        // クライアントの一時的なキーペアを生成
        let clientPrivateKey = Curve25519.KeyAgreement.PrivateKey()
        let clientPublicKeyData = clientPrivateKey.publicKey.rawRepresentation

        // 共通鍵を生成
        let sharedSecret = try clientPrivateKey.sharedSecretFromKeyAgreement(with: serverKey)

        // 共通鍵から対称キーを導出 (HKDF)
        let symmetricKey = sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: Data(), // Saltは空または共有された値
            sharedInfo: Data(), // Shared Infoも同様
            outputByteCount: 32
        )

        // ChaChaPolyで平文を暗号化
        let sealedBox = try ChaChaPoly.seal(plaintext, using: symmetricKey)
        
        // 送信用のリクエストボディを作成
        let encryptedRequest = EncryptedRequestBody(
            ephemeralPublicKey: clientPublicKeyData.base64EncodedString(),
            sealedBox: sealedBox.combined.base64EncodedString()
        )

        return try JSONEncoder().encode(encryptedRequest)
    }
    
    
    static func processNotification(
        notificationContent: UNNotificationContent,
        using dependencies: Dependencies
    ) -> (data: Data?, metadata: NotificationMetadata, result: ProcessResult) {
        // Make sure the notification is from the updated push server
        guard notificationContent.userInfo["spns"] != nil else {
            return (nil, .invalid, .legacyFailure)
        }
        
        guard let base64EncodedEncString: String = notificationContent.userInfo["enc_payload"] as? String else {
            return (nil, .invalid, .failureNoContent)
        }
        
        // Decrypt and decode the payload
        guard
            let encryptedData: Data = Data(base64Encoded: base64EncodedEncString),
            let notificationsEncryptionKey: Data = try? getOrGenerateEncryptionKey(using: dependencies),
            let decryptedData: Data = dependencies[singleton: .crypto].generate(
                .plaintextWithPushNotificationPayload(
                    payload: encryptedData,
                    encKey: notificationsEncryptionKey
                )
            ),
            let notification: BencodeResponse<NotificationMetadata> = try? BencodeDecoder(using: dependencies)
                .decode(BencodeResponse<NotificationMetadata>.self, from: decryptedData)
        else {
            Log.error(.cat, "Failed to decrypt or decode notification")
            return (nil, .invalid, .failure)
        }
        
        // If the metadata says that the message was too large then we should show the generic
        // notification (this is a valid case)
        guard !notification.info.dataTooLong else { return (nil, notification.info, .successTooLong) }
        
        // Check that the body we were given is valid and not empty
        guard
            let notificationData: Data = notification.data,
            notification.info.dataLength == notificationData.count,
            !notificationData.isEmpty
        else {
            Log.error(.cat, "Get notification data failed")
            return (nil, notification.info, .failureNoContent)
        }
        
        // Success, we have the notification content
        return (notificationData, notification.info, .success)
    }
    
    // MARK: - Security
    
    @discardableResult private static func getOrGenerateEncryptionKey(using dependencies: Dependencies) throws -> Data {
        do {
            try dependencies[singleton: .keychain].migrateLegacyKeyIfNeeded(
                legacyKey: "PNEncryptionKeyKey",
                legacyService: "PNKeyChainService",
                toKey: .pushNotificationEncryptionKey
            )
            var encryptionKey: Data = try dependencies[singleton: .keychain].data(forKey: .pushNotificationEncryptionKey)
            defer { encryptionKey.resetBytes(in: 0..<encryptionKey.count) }
            
            guard encryptionKey.count == encryptionKeyLength else { throw StorageError.invalidKeySpec }
            
            return encryptionKey
        }
        catch {
            switch (error, (error as? KeychainStorageError)?.code) {
                case (StorageError.invalidKeySpec, _), (_, errSecItemNotFound):
                    // No keySpec was found so we need to generate a new one
                    do {
                        var keySpec: Data = try dependencies[singleton: .crypto]
                            .tryGenerate(.randomBytes(encryptionKeyLength))
                        defer { keySpec.resetBytes(in: 0..<keySpec.count) } // Reset content immediately after use
                        
                        try dependencies[singleton: .keychain].set(data: keySpec, forKey: .pushNotificationEncryptionKey)
                        return keySpec
                    }
                    catch {
                        Log.error(.cat, "Setting keychain value failed with error: \(error.localizedDescription)")
                        throw StorageError.keySpecCreationFailed
                    }
                    
                default:
                    // Because we use kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly, the keychain will be inaccessible
                    // after device restart until device is unlocked for the first time. If the app receives a push
                    // notification, we won't be able to access the keychain to process that notification, so we should
                    // just terminate by throwing an uncaught exception
                    if dependencies[singleton: .appContext].isMainApp || dependencies[singleton: .appContext].isInBackground {
                        let appState: UIApplication.State = dependencies[singleton: .appContext].reportedApplicationState
                        Log.error(.cat, "CipherKeySpec inaccessible. New install or no unlock since device restart?, ApplicationState: \(appState.name)")
                        throw StorageError.keySpecInaccessible
                    }
                    
                    Log.error(.cat, "CipherKeySpec inaccessible; not main app.")
                    throw StorageError.keySpecInaccessible
            }
        }
    }
    /// 非同期処理を指定回数リトライするヘルパー関数
    static func attempt<T>(maxRetryCount: UInt, operation: @escaping () async throws -> T) async throws -> T {
        for _ in 0..<maxRetryCount - 1 {
            if let result = try? await operation() {
                return result
            }
            // 必要に応じてリトライ前に待機時間を設けることも可能
            // try await Task.sleep(for: .seconds(1))
        }
        // 最後の試行
        return try await operation()
    }
}

// 16進数文字列をDataに変換するためのヘルパー
extension Data {
    init?(hexString: String) {
        let len = hexString.count / 2
        var data = Data(capacity: len)
        var i = hexString.startIndex
        for _ in 0..<len {
            let j = hexString.index(i, offsetBy: 2)
            let bytes = hexString[i..<j]
            if var num = UInt8(bytes, radix: 16) {
                data.append(&num, count: 1)
            } else {
                return nil
            }
            i = j
        }
        self = data
    }
}
