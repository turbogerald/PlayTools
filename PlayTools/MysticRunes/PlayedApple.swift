//
//  PlayWeRuinedIt.swift
//  PlayTools
//
//  Created by Venti on 16/01/2023.
//

import Foundation
import Security

// Implementation for PlayKeychain
// World's Most Advanced Keychain Replacement Solution:tm:
// This is a joke, don't take it seriously

public class PlayKeychain: NSObject {
    static let shared = PlayKeychain()
    static let playChainDB = PlayKeychainDB.shared

    @objc public static func debugLogger(_ logContent: String) {
        if PlaySettings.shared.settingsData.playChainDebugging {
            NSLog("PC-DEBUG: \(logContent)")
        }
    }

    static func flag(_ dictionary: NSDictionary, _ key: CFString) -> Bool {
        let value = dictionary[key as String]
        if let value = value as? Bool {
            return value
        }
        if let value = value as? NSNumber {
            return value.boolValue
        }
        return false
    }
    // Emulates SecItemAdd, SecItemUpdate, SecItemDelete and SecItemCopyMatching
    // Store the entire dictionary as a plist
    // SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result)
    @objc static public func add(_ attributes: NSDictionary,
                                 result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        if let ref = attributes[kSecValueRef as String], CFGetTypeID(ref as CFTypeRef) == SecIdentityGetTypeID() {
            return addIdentity(attributes, identity: ref as! SecIdentity, // swiftlint:disable:this force_cast
                               result: result)
        }
        let attributes = withPasswordDefaults(normalizedReference(attributes))
        guard let keychainDict = playChainDB.insert(attributes) else {
            debugLogger("Failed to write keychain file")
            return errSecIO
        }
        debugLogger("Wrote keychain item to db")

        let wantsReturn =
            flag(attributes, kSecReturnAttributes) ||
            flag(attributes, kSecReturnData) ||
            flag(attributes, kSecReturnRef) ||
            flag(attributes, kSecReturnPersistentRef)

        guard wantsReturn, result != nil else {
            return errSecSuccess
        }

        return addResult(attributes, keychainDict: keychainDict, result: result)
    }

    private static func addResult(_ attributes: NSDictionary,
                                  keychainDict: NSMutableDictionary,
                                  result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        // Place v_Data in the result
        guard let vData = attributes["v_Data"] as? CFTypeRef else {
            return errSecSuccess
        }

        if attributes["r_Attributes"] as? Int == 1 {
            // Create a dummy dictionary and return it
            let dummyDict = keychainDict
            if attributes["r_Data"] as? Int != 1 {
                dummyDict.removeObject(forKey: kSecValueData)
                dummyDict.removeObject(forKey: kSecValueRef)
                dummyDict.removeObject(forKey: kSecValuePersistentRef)
            }
            result?.pointee = Unmanaged.passRetained(dummyDict)
            return errSecSuccess
        }

        if flag(attributes, kSecReturnData) &&
            !flag(attributes, kSecReturnRef) &&
            !flag(attributes, kSecReturnPersistentRef) {
            result?.pointee = Unmanaged.passRetained(vData)
            return errSecSuccess
        }

        if attributes["class"] as? String == "cert" {
            guard let certificateData = vData as? Data,
                  let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
                return errSecBadReq
            }
            result?.pointee = Unmanaged.passRetained(certificate)
            return errSecSuccess
        }

        if attributes["class"] as? String == "keys" {
            if let keyDataValue = vData as? Data {
                // kSecAttrKeyType is stored as `type` in the dictionary
                // kSecAttrKeyClass is stored as `kcls` in the dictionary
                let keyAttributesDictionary = [
                    kSecAttrKeyType: attributes["type"] as? String
                        ?? (attributes[kSecAttrKeyType as String] as? String),
                    kSecAttrKeyClass: attributes["kcls"] as? String
                        ?? (attributes[kSecAttrKeyType as String] as? String)
                ]
                if let key = SecKeyCreateWithData(
                    keyDataValue as CFData,
                    keyAttributesDictionary as CFDictionary,
                    nil
                ) {
                    result?.pointee = Unmanaged.passRetained(key)
                    return errSecSuccess
                }
            }
            return errSecBadReq
        }
        result?.pointee = Unmanaged.passRetained(vData)
        return errSecSuccess
    }

    // SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate)
    @objc static public func update(_ query: NSDictionary, attributesToUpdate: NSDictionary) -> OSStatus {
        let query = storageQuery(query)
        let attributesToUpdate = normalizedReference(attributesToUpdate)
        guard let keychainDict = playChainDB.query(query)?.first else {
            debugLogger("Keychain item not found in db")
            return errSecItemNotFound
        }
        debugLogger("Select keychain item from db")
        // Reconstruct the dictionary (subscripting won't work as assignment is not allowed)
        let newKeychainDict = NSMutableDictionary()
        for (key, value) in keychainDict {
            newKeychainDict.setValue(value, forKey: key as! String) // swiftlint:disable:this force_cast
        }
        // Update the dictionary
        for (key, value) in attributesToUpdate {
            newKeychainDict.setValue(value, forKey: key as! String) // swiftlint:disable:this force_cast
        }
        guard playChainDB.update(newKeychainDict) else {
            debugLogger("Failed to update keychain item to db")
            return errSecIO
        }

        return errSecSuccess
    }

    // SecItemDelete(CFDictionaryRef query)
    @objc static public func delete(_ query: NSDictionary) -> OSStatus {
        let query = storageQuery(query)
        guard playChainDB.query(query)?.first != nil else {
            debugLogger("Failed to find keychain item")
            return errSecItemNotFound
        }
        guard playChainDB.delete(query) else {
            debugLogger("Failed to delete keychain item")
            return errSecIO
        }
        debugLogger("Deleted keychain item in db")
        return errSecSuccess
    }

    @objc static public func keyCreateRandomKey(_ parameters: NSDictionary,
                                                error: UnsafeMutablePointer<Unmanaged<CFError>?>?)
    -> Unmanaged<SecKey>? {
        let request = inMemoryKeyParameters(parameters)
        guard let key = SecKeyCreateRandomKey(request.parameters as CFDictionary, error) else {
            debugLogger("Failed to create random key")
            return nil
        }
        if request.isPermanent && !storeKey(key, parameters: parameters, keyAttributes: kSecPrivateKeyAttrs) {
            debugLogger("Failed to write keychain file")
            error?.pointee = Unmanaged.passRetained(CFErrorCreate(nil, kCFErrorDomainOSStatus, CFIndex(errSecIO), nil))
            return nil
        }
        return Unmanaged.passRetained(key)
    }

    @objc static public func keyGeneratePair(_ parameters: NSDictionary,
                                             publicKey: UnsafeMutablePointer<Unmanaged<SecKey>?>?,
                                             privateKey: UnsafeMutablePointer<Unmanaged<SecKey>?>?) -> OSStatus {
        let request = inMemoryKeyParameters(parameters)
        var newPublicKey: SecKey?
        var newPrivateKey: SecKey?
        let status = SecKeyGeneratePair(request.parameters as CFDictionary, &newPublicKey, &newPrivateKey)
        guard status == errSecSuccess, let newPublicKey = newPublicKey, let newPrivateKey = newPrivateKey else {
            debugLogger("Failed to generate key pair.")
            return status == errSecSuccess ? errSecMissingEntitlement : status
        }
        if request.isPermanent {
            guard storeKey(newPublicKey, parameters: parameters, keyAttributes: kSecPublicKeyAttrs),
                  storeKey(newPrivateKey, parameters: parameters, keyAttributes: kSecPrivateKeyAttrs) else {
                debugLogger("Failed to write key pair to keychain db")
                return errSecIO
            }
        }
        publicKey?.pointee = Unmanaged.passRetained(newPublicKey)
        privateKey?.pointee = Unmanaged.passRetained(newPrivateKey)
        return errSecSuccess
    }

    // Persistent keys are generated in memory and stored in PlayChain afterwards.
    // PlayChain keeps the key's bytes, which a Secure Enclave key never exposes,
    // so a persistent Secure Enclave key is generated as a software key.
    private static func inMemoryKeyParameters(_ parameters: NSDictionary)
    -> (parameters: [String: Any], isPermanent: Bool) {
        var request = parameters as? [String: Any] ?? [:]
        var isPermanent = flag(parameters, kSecAttrIsPermanent)
        request.removeValue(forKey: kSecAttrIsPermanent as String)
        for keyAttributes in [kSecPrivateKeyAttrs as String, kSecPublicKeyAttrs as String] {
            guard var attributes = request[keyAttributes] as? [String: Any] else { continue }
            isPermanent = isPermanent || flag(attributes as NSDictionary, kSecAttrIsPermanent)
            attributes[kSecAttrIsPermanent as String] = false
            request[keyAttributes] = attributes
        }
        if isPermanent && request[kSecAttrTokenID as String] as? String == kSecAttrTokenIDSecureEnclave as String {
            request.removeValue(forKey: kSecAttrTokenID as String)
            if var attributes = request[kSecPrivateKeyAttrs as String] as? [String: Any] {
                attributes.removeValue(forKey: kSecAttrAccessControl as String)
                request[kSecPrivateKeyAttrs as String] = attributes
            }
        }
        return (request, isPermanent)
    }

    // Stores a generated key like SecItemAdd would, with the attributes apps look it up by.
    private static func storeKey(_ key: SecKey, parameters: NSDictionary, keyAttributes: CFString) -> Bool {
        let attributes = parameters[keyAttributes as String] as? [String: Any] ?? [:]
        let item = NSMutableDictionary()
        item[kSecValueRef as String] = key
        for attribute in [kSecAttrApplicationTag, kSecAttrApplicationLabel, kSecAttrLabel] {
            item[attribute as String] = attributes[attribute as String] ?? parameters[attribute as String]
        }
        item[kSecAttrKeyType as String] = parameters[kSecAttrKeyType as String]
        item[kSecAttrKeySizeInBits as String] = parameters[kSecAttrKeySizeInBits as String]
        let keyItem = normalizedReference(item)
        guard keyItem[kSecValueData as String] != nil else {
            debugLogger("Key cannot be exported for storage")
            return false
        }
        return playChainDB.insert(keyItem) != nil
    }
}

extension PlayKeychain {
    // SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result)
    @objc static public func copyMatching(_ query: NSDictionary,
                                          result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        if isCertificateOrIdentity(query) {
            return copyCertificateMatching(query, result: result)
        }
        return copyItemMatching(query, result: result)
    }

    private static func copyItemMatching(_ query: NSDictionary,
                                         result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        guard let keychainDicts = playChainDB.query(query),
              let keychainDict = keychainDicts.first else {
            debugLogger("Keychain item not found in db")
            return errSecItemNotFound
        }

        let wantsAttributes = flag(query, kSecReturnAttributes)
        let wantsData = flag(query, kSecReturnData)
        let wantsRef = flag(query, kSecReturnRef)
        let wantsPersistentRef = flag(query, kSecReturnPersistentRef)

        if query[kSecMatchLimit as String] as? String == kSecMatchLimitAll as String {
            return copyAllMatches(keychainDicts, query: query, result: result)
        }
        // Check the `r_Attributes` key. If it is set to 1 in the query
        let classType = query[kSecClass as String] as? String ?? ""

        if wantsAttributes {
            // Create a dummy dictionary and return it
            let dummyDict = keychainDict
            if !wantsData {
                dummyDict.removeObject(forKey: kSecValueData)
                dummyDict.removeObject(forKey: kSecValueRef)
                dummyDict.removeObject(forKey: kSecValuePersistentRef)
            }
            result?.pointee = Unmanaged.passRetained(dummyDict)
            return errSecSuccess
        }

        // kSecReturnData asks for the stored bytes, even for kSecClassKey.
        if wantsData && !wantsRef && !wantsPersistentRef {
            guard let vData = keychainDict[kSecValueData] else {
                return errSecItemNotFound
            }
            result?.pointee = Unmanaged.passRetained(vData as CFTypeRef)
            return errSecSuccess
        }

        // A query without return flags is an existence check.
        if !wantsAttributes && !wantsData && !wantsRef && !wantsPersistentRef {
            return errSecSuccess
        }

        if wantsRef {
            return copyReference(keychainDict, result: result)
        }

        // Return v_Data if it exists
        if let vData = keychainDict[kSecValueData] {
            debugLogger("Read keychain file from db")
            // Check the class type, if it is a key we need to return the data
            // as SecKeyRef, otherwise we can return it as a CFTypeRef
            if classType == "keys" {
                return copyKey(keychainDict, keyData: vData, result: result)
            }
            result?.pointee = Unmanaged.passRetained(vData as CFTypeRef)
            return errSecSuccess
        }

        return errSecItemNotFound
    }

    // kSecAttrKeyType is stored as `type` and kSecAttrKeyClass as `kcls` in the dictionary
    private static func copyKey(_ keychainDict: NSMutableDictionary, keyData: Any,
                                result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        guard let keyType = keychainDict[kSecAttrKeyType] as? String,
              let keyClass = keychainDict[kSecAttrKeyClass] as? String,
              let keyData = keyData as? Data else {
            debugLogger("Stored key cannot be rebuilt")
            return errSecDecode
        }
        let keyAttributes = [kSecAttrKeyType: keyType, kSecAttrKeyClass: keyClass] as CFDictionary
        guard let key = SecKeyCreateWithData(keyData as CFData, keyAttributes, nil) else {
            debugLogger("Stored key cannot be rebuilt")
            return errSecDecode
        }
        result?.pointee = Unmanaged.passRetained(key)
        return errSecSuccess
    }

    private static func copyAllMatches(_ keychainDicts: [NSMutableDictionary], query: NSDictionary,
                                       result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        let wantsData = flag(query, kSecReturnData)
        let wantsAttributes = flag(query, kSecReturnAttributes)
        let wantsRef = flag(query, kSecReturnRef)
        let wantsPersistentRef = flag(query, kSecReturnPersistentRef)
        if wantsData && !wantsAttributes && !wantsRef && !wantsPersistentRef {
            let values = keychainDicts.compactMap({ $0[kSecValueData] })
            guard values.count == keychainDicts.count else {
                return errSecItemNotFound
            }
            result?.pointee = Unmanaged.passRetained(values as CFTypeRef)
            return errSecSuccess
        }

        result?.pointee = Unmanaged.passRetained(keychainDicts.map({
            if !wantsData {
                $0.removeObject(forKey: kSecValueData)
            }
            $0.removeObject(forKey: kSecValueRef)
            $0.removeObject(forKey: kSecValuePersistentRef)
            return $0
        }) as CFTypeRef)
        return errSecSuccess
    }

    private static func copyReference(_ keychainDict: NSMutableDictionary,
                                      result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        // Return the data on v_PersistentRef or v_Data if they exist
        var key: CFTypeRef?
        if let vData = keychainDict[kSecValueData] {
            NSLog("found v_Data")
            debugLogger("Read keychain item from db")
            key = vData as CFTypeRef
        }
        if let vPersistentRef = keychainDict[kSecValuePersistentRef] {
            NSLog("found persistent ref")
            debugLogger("Read keychain item from db")
            key = vPersistentRef as CFTypeRef
        }

        if key == nil {
            debugLogger("Keychain item not found in db")
            return errSecItemNotFound
        }

        let dummyKeyAttrs = [
            kSecAttrKeyType: keychainDict[kSecAttrKeyType] ?? kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: keychainDict[kSecAttrKeyClass] ?? kSecAttrKeyClassPublic
        ] as CFDictionary

        guard let keyData = key as? Data,
              let secKey = SecKeyCreateWithData(keyData as CFData, dummyKeyAttrs, nil) else {
            debugLogger("Stored key cannot be rebuilt")
            return errSecDecode
        }
        result?.pointee = Unmanaged.passRetained(secKey)
        return errSecSuccess
    }
}
