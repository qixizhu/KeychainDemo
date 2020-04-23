//
//  UserKeychainHelper.swift
//  KeychainHelper
//
//  Created by 韩企 on 2020/4/23.
//  Copyright © 2020 七夕猪. All rights reserved.
//

import UIKit

/**
 官方文档
 Keychain Servers:https://developer.apple.com/documentation/security/keychain_services
 Using the Keychain to Manage User Secrets: https://developer.apple.com/documentation/security/keychain_services/keychain_items/using_the_keychain_to_manage_user_secrets
 Adding a Password to the Keychain:https://developer.apple.com/documentation/security/keychain_services/keychain_items/adding_a_password_to_the_keychain
 Searching for Keychain Items:https://developer.apple.com/documentation/security/keychain_services/keychain_items/searching_for_keychain_items
 Updating and Deleting Keychain Items:https://developer.apple.com/documentation/security/keychain_services/keychain_items/updating_and_deleting_keychain_items
 */

class UserKeychainHelper {
    
    static let shared = UserKeychainHelper()
    private init() {}
    
    // 自定义的存储 IDFV 时的标签。用于查找时，缩小查找范围。
    private let idFVLabel = "IDFV"
    // 自定义的存储用户名和密码的标签
    private let passwordLabel = "Username&Password"
    
    /// 检查 Keychain 中是否存在IDFV，如果不存在则获取并存储。
    func checkAndSaveIDFV() {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: idFVLabel,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        
        switch status {
        case errSecItemNotFound:    // 没有找到
            addIDFV()
        case errSecSuccess:    // 找到
            break
        default: break
        }
    }
    
    /// 存储 IDFV 字符串到 Keychain 中
    ///
    /// - Returns: true or false
    @discardableResult
    private func addIDFV() -> Bool {
        // 获取 IDFV，这里使用 identifierForVendor
        // 如果使用 ASIdentifierManager 的 advertisingIdentifier，则在用户设备开启了限制广告跟踪时，获取不到。
        // 且官方建议用于广告相关的业务时使用ASIdentifierManager 的 advertisingIdentifier。
        guard let idFAString = UIDevice.current.identifierForVendor?.uuidString else { return false }
        guard let idFAData = idFAString.data(using: .utf8) else { return false }
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: idFVLabel,
                                    kSecValueData as String: idFAData]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            return false
        }
        return true
    }
    
    /// 获取存储在Keychain中的IDFV
    ///
    /// - Returns: string optional.
    func getIDFVString() -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: idFVLabel,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        /// Is success
        guard status == errSecSuccess else { return nil }
        
        guard let existingItem = item as? [String : Any],
            let idFAData = existingItem[kSecValueData as String] as? Data,
            let idFAString = String(data: idFAData, encoding: String.Encoding.utf8)
        else {
            return nil
        }
        return idFAString
    }
    
    /// 删除Keychain中所有的IDFV
    ///
    /// - Returns: true or false.
    @discardableResult
    func deleteAllIDFV() -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrLabel as String: idFVLabel]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { return false }
        return true
    }
    
    // MARK: - 用户名和密码
    
    /// 保存用户名和密码。先查找，如果没找到就直接保存；如果找到了就更新。
    ///
    /// - Parameter credentials: username and password data struct
    /// - Returns: Whether or not save success.
    @discardableResult
    func save(credentials: Credentials) -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: passwordLabel,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        /// Is empty
        guard status != errSecItemNotFound else {
            return addSecItem(credentials: credentials)
        }
        guard status == errSecSuccess else { return false }
        
        guard let existingItem = item as? [String : Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8),
            let account = existingItem[kSecAttrAccount as String] as? String
        else {
            deleteAll()
            return addSecItem(credentials: credentials)
        }
        
        guard (account != credentials.username) || (password != credentials.password) else {
            return true
        }
        
        return updateSecItem(credentials: credentials)
    }
    
    /// 获取存储在Keychain中的用户名和密码
    ///
    /// - Returns: username and password struct.
    func getCredentials() -> Credentials? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: passwordLabel,
                                    kSecMatchLimit as String: kSecMatchLimitOne,
                                    kSecReturnAttributes as String: true,
                                    kSecReturnData as String: true]
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        /// Is success
        guard status == errSecSuccess else { return nil }
        
        guard let existingItem = item as? [String : Any],
            let passwordData = existingItem[kSecValueData as String] as? Data,
            let password = String(data: passwordData, encoding: String.Encoding.utf8),
            let account = existingItem[kSecAttrAccount as String] as? String
        else {
            return nil
        }
        let credentials = Credentials(username: account, password: password)
        return credentials
    }
    
    /// 保存用户名和密码到Keychain中
    /// - Parameter credentials: 用户名和密码
    /// - Returns: true or false
    private func addSecItem(credentials: Credentials) -> Bool {
        let account = credentials.username
        let password = credentials.password.data(using: String.Encoding.utf8)!
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrLabel as String: passwordLabel,
                                    kSecAttrAccount as String: account,
                                    kSecValueData as String: password]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            return false
        }
        return true
    }
    
    /// 更新Keychain中的用户名和密码
    /// - Parameter credentials: 用户名和密码
    /// - Returns: true or false
    private func updateSecItem(credentials: Credentials) -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrLabel as String: passwordLabel]
        let account = credentials.username
        let password = credentials.password.data(using: String.Encoding.utf8)!
        let attributes: [String: Any] = [kSecAttrAccount as String: account,
                                         kSecValueData as String: password]
        let status = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        guard status == errSecSuccess else { return false }
        return true
    }
    
    /// 删除Keychain中保存的用户名和密码
    ///
    /// - Returns: true or false.
    @discardableResult
    func deleteAll() -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrLabel as String: passwordLabel]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { return false }
        return true
    }
}

struct Credentials {
    var username: String
    var password: String
}
