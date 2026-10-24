//
//  PlayedAppleCertificates.swift
//  PlayTools
//

import Foundation
import Security

// Object references (kSecValueRef), certificates and identities for PlayKeychain.
// PlayChain persists raw bytes, so keys and certificates are stored as their external
// representation, and identities are assembled on lookup from a stored certificate
// plus the PlayChain private key it certifies.

// SecIdentityCreate is not in the public headers, but Security.framework has exported it for years.
private typealias SecIdentityCreateFunction = @convention(c) (CFAllocator?, SecCertificate, SecKey)
    -> Unmanaged<SecIdentity>?
private let secIdentityCreate: SecIdentityCreateFunction? = {
    guard let symbol = dlsym(UnsafeMutableRawPointer(bitPattern: -2), "SecIdentityCreate") else { // RTLD_DEFAULT
        return nil
    }
    return unsafeBitCast(symbol, to: SecIdentityCreateFunction.self)
}()

extension PlayKeychain {
    // The real keychain infers the class from kSecValueRef and stores the referenced object.
    // Store the object's bytes instead so PlayChain can keep and rebuild it.
    static func normalizedReference(_ attributes: NSDictionary) -> NSDictionary {
        guard let value = attributes[kSecValueRef as String] else { return attributes }
        let item = NSMutableDictionary(dictionary: attributes)
        let ref = value as CFTypeRef
        if CFGetTypeID(ref) == SecKeyGetTypeID() {
            let key = ref as! SecKey // swiftlint:disable:this force_cast
            let keyAttributes = SecKeyCopyAttributes(key) as? [String: Any] ?? [:]
            item[kSecClass as String] = kSecClassKey
            item[kSecAttrKeyClass as String] = keyClass(of: key)
            item[kSecAttrKeyType as String] = attributes[kSecAttrKeyType as String]
                ?? keyAttributes[kSecAttrKeyType as String]
            item[kSecAttrKeySizeInBits as String] = attributes[kSecAttrKeySizeInBits as String]
                ?? keyAttributes[kSecAttrKeySizeInBits as String]
            item[kSecValueData as String] = SecKeyCopyExternalRepresentation(key, nil)
        } else if CFGetTypeID(ref) == SecCertificateGetTypeID() {
            item[kSecClass as String] = kSecClassCertificate
            let certificate = ref as! SecCertificate // swiftlint:disable:this force_cast
            item[kSecValueData as String] = SecCertificateCopyData(certificate)
        }
        item.removeObject(forKey: kSecValueRef as String)
        return item
    }

    // Like the real keychain, a password item without account or service is stored with "",
    // so a later query for an empty service still finds it.
    static func withPasswordDefaults(_ attributes: NSDictionary) -> NSDictionary {
        let itemClass = attributes[kSecClass as String] as? String
        var defaults: [CFString] = []
        if itemClass == kSecClassGenericPassword as String {
            defaults = [kSecAttrAccount, kSecAttrService]
        } else if itemClass == kSecClassInternetPassword as String {
            defaults = [kSecAttrAccount]
        }
        let missing = defaults.filter { attributes[$0 as String] == nil }
        guard !missing.isEmpty else { return attributes }
        let item = NSMutableDictionary(dictionary: attributes)
        missing.forEach { item[$0 as String] = "" }
        return item
    }

    // A public key's public key is itself; a private key yields a different object.
    static func keyClass(of key: SecKey) -> CFString {
        guard let publicKey = SecKeyCopyPublicKey(key), CFEqual(publicKey, key) else {
            return kSecAttrKeyClassPrivate
        }
        return kSecAttrKeyClassPublic
    }

    // Identities are stored as their certificate, so identity queries address the certificate table.
    static func storageQuery(_ query: NSDictionary) -> NSDictionary {
        guard query[kSecClass as String] as? String == kSecClassIdentity as String else { return query }
        let certificateQuery = NSMutableDictionary(dictionary: query)
        certificateQuery[kSecClass as String] = kSecClassCertificate
        return certificateQuery
    }

    static func isCertificateOrIdentity(_ attributes: NSDictionary) -> Bool {
        let itemClass = attributes[kSecClass as String] as? String
        return itemClass == kSecClassCertificate as String || itemClass == kSecClassIdentity as String
    }

    // Adding an identity stores its certificate and its private key.
    static func addIdentity(_ attributes: NSDictionary, identity: SecIdentity,
                            result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        var certificate: SecCertificate?
        var privateKey: SecKey?
        guard SecIdentityCopyCertificate(identity, &certificate) == errSecSuccess,
              SecIdentityCopyPrivateKey(identity, &privateKey) == errSecSuccess,
              let certificate = certificate, let privateKey = privateKey else {
            return errSecParam
        }
        let certificateItem = NSMutableDictionary(dictionary: attributes)
        certificateItem[kSecValueRef as String] = certificate
        let keyItem: NSDictionary = [kSecValueRef as String: privateKey]
        guard playChainDB.insert(normalizedReference(certificateItem)) != nil,
              playChainDB.insert(normalizedReference(keyItem)) != nil else {
            debugLogger("Failed to write identity to db")
            return errSecIO
        }
        if flag(attributes, kSecReturnRef) {
            result?.pointee = Unmanaged.passRetained(identity)
        }
        return errSecSuccess
    }

    // SecItemCopyMatching for kSecClassCertificate and kSecClassIdentity.
    static func copyCertificateMatching(_ query: NSDictionary,
                                        result: UnsafeMutablePointer<Unmanaged<CFTypeRef>?>?) -> OSStatus {
        let isIdentity = query[kSecClass as String] as? String == kSecClassIdentity as String
        let certificateQuery = NSMutableDictionary(dictionary: storageQuery(query))
        certificateQuery.removeObject(forKey: kSecMatchLimit as String) // identities are filtered below
        let matches: [(item: NSMutableDictionary, ref: CFTypeRef)] = (playChainDB.query(certificateQuery) ?? [])
            .compactMap { item in
                guard let data = item[kSecValueData] as? Data,
                      let certificate = SecCertificateCreateWithData(nil, data as CFData) else { return nil }
                guard isIdentity else { return (item, certificate) }
                guard let identity = identity(for: certificate) else { return nil }
                return (item, identity)
            }
        guard let firstMatch = matches.first else {
            debugLogger("Keychain item not found in db")
            return errSecItemNotFound
        }

        if query[kSecMatchLimit as String] as? String == kSecMatchLimitAll as String {
            let values = matches.compactMap { returnValue(query, item: $0.item, ref: $0.ref) }
            if !values.isEmpty {
                result?.pointee = Unmanaged.passRetained(values as CFArray)
            }
            return errSecSuccess
        }
        // Without return flags this is an existence check.
        if let value = returnValue(query, item: firstMatch.item, ref: firstMatch.ref) {
            result?.pointee = Unmanaged.passRetained(value)
        }
        return errSecSuccess
    }

    private static func returnValue(_ query: NSDictionary, item: NSMutableDictionary, ref: CFTypeRef) -> CFTypeRef? {
        let wantsData = flag(query, kSecReturnData)
        let wantsRef = flag(query, kSecReturnRef)
        if flag(query, kSecReturnAttributes) || (wantsData && wantsRef) {
            let attributes = NSMutableDictionary(dictionary: item)
            attributes[kSecClass as String] = query[kSecClass as String]
            if !wantsData {
                attributes.removeObject(forKey: kSecValueData as String)
            }
            if wantsRef {
                attributes[kSecValueRef as String] = ref
            }
            return attributes
        }
        if wantsRef {
            return ref
        }
        if wantsData {
            return item[kSecValueData].map { $0 as CFTypeRef }
        }
        return nil
    }

    // Pairs a certificate with the PlayChain private key whose public key it certifies.
    private static func identity(for certificate: SecCertificate) -> SecIdentity? {
        guard let secIdentityCreate = secIdentityCreate,
              let certificateKey = SecCertificateCopyKey(certificate),
              let certificateKeyData = SecKeyCopyExternalRepresentation(certificateKey, nil) as Data? else {
            return nil
        }
        let privateKeyQuery: NSDictionary = [kSecClass as String: kSecClassKey,
                                             kSecAttrKeyClass as String: kSecAttrKeyClassPrivate]
        for item in playChainDB.query(privateKeyQuery) ?? [] {
            guard let keyData = item[kSecValueData] as? Data,
                  let keyType = item[kSecAttrKeyType] as? String else { continue }
            let keyAttributes = [kSecAttrKeyType: keyType, kSecAttrKeyClass: kSecAttrKeyClassPrivate] as CFDictionary
            guard let privateKey = SecKeyCreateWithData(keyData as CFData, keyAttributes, nil),
                  let publicKey = SecKeyCopyPublicKey(privateKey),
                  SecKeyCopyExternalRepresentation(publicKey, nil) as Data? == certificateKeyData else { continue }
            return secIdentityCreate(nil, certificate, privateKey)?.takeRetainedValue()
        }
        return nil
    }
}
