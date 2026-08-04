import Foundation
import Security

// P12 密码只从进程环境读取，避免出现在 security 命令参数和进程列表中。
func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data("\(message)\n".utf8))
    exit(1)
}

let environment = ProcessInfo.processInfo.environment
guard let encoded = environment["LINKLAKE_MACOS_SIGNING_CERT_P12_B64"], !encoded.isEmpty else {
    fail("LINKLAKE_MACOS_SIGNING_CERT_P12_B64 is required")
}
guard let password = environment["LINKLAKE_MACOS_SIGNING_CERT_PASSWORD"], !password.isEmpty else {
    fail("LINKLAKE_MACOS_SIGNING_CERT_PASSWORD is required")
}
guard let data = Data(base64Encoded: encoded, options: []),
      !data.isEmpty,
      data.count <= 4 * 1024 * 1024 else {
    fail("The macOS signing certificate archive is not valid base64 or has an invalid size")
}

let options = [kSecImportExportPassphrase as String: password] as CFDictionary
var importedItems: CFArray?
let status = SecPKCS12Import(data as CFData, options, &importedItems)
guard status == errSecSuccess else {
    fail("SecPKCS12Import failed with status \(status)")
}
guard let items = importedItems, CFArrayGetCount(items) > 0 else {
    fail("The macOS signing certificate archive did not contain an identity")
}

print("Imported \(CFArrayGetCount(items)) signing identity item(s) into the temporary keychain.")
