//
//  Keychain.swift
//  onelabhwBlog
//
//  Created by Arnur Sakenov on 15.04.2023.
//


import Security
import Foundation

class KeychainService {
    class func saveToken(token: String, account: String) -> Bool {
        
        guard let data = token.data(using: .utf8) else {
           
            return false
        }
        
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: account,
                                    kSecValueData as String: data]
        let status = SecItemAdd(query as CFDictionary, nil)
        
        return status == errSecSuccess
    }
class func loadToken(account: String) -> String? {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: account,
                                    kSecReturnData as String: kCFBooleanTrue!,
                                    kSecMatchLimit as String: kSecMatchLimitOne]
        var dataTypeRef: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &dataTypeRef)
        
        if status == errSecSuccess {
            if let retrievedData = dataTypeRef as? Data,
               let token = String(data: retrievedData, encoding: .utf8) {
                return token
            }
        }
        
        return nil
    }
class func deleteToken(account: String) -> Bool {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
                                    kSecAttrAccount as String: account]
        let status = SecItemDelete(query as CFDictionary)
        
        return status == errSecSuccess
    }
}
