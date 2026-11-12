// Uses the Swift bindings against a running service, as the Mac app will (scripts/swift-bindings.sh).
// Arguments: the openvault directory, its recovery phrase, and the version the library should be.
import Foundation

let arguments = CommandLine.arguments
let (home, phrase, expected) = (arguments[1], arguments[2], arguments[3])

func check(_ condition: Bool, _ what: String) {
    if !condition {
        FileHandle.standardError.write(Data("ffi smoke test failed: \(what)\n".utf8))
        exit(1)
    }
}

final class Listener: WatchListener, @unchecked Sendable {
    let changed = DispatchSemaphore(value: 0)
    let ended = DispatchSemaphore(value: 0)

    func onEvent(event: WatchEvent) {
        if event.entries && event.collections == ["smoke"] {
            changed.signal()
        }
    }

    func onEnd(error: String?) {
        check(error == nil, "the watch ended with \(error ?? "")")
        ended.signal()
    }
}

check(version() == expected, "version \(version()), not \(expected)")
let found = try deviceHome(home: home)
check(found.vault && found.keys == .software, "home \(found)")
let client = try Client(home: home)
check(client.isRunning(), "the service isn't running")
let vault = try client.vault()
check(vault.recovery.count == 9 && !vault.admin, "vault \(vault)")

do {
    try client.createCollection(name: "smoke", recoveryPhrase: nil)
    check(false, "a collection was created without a signature")
} catch OpenVaultError.RecoveryPhraseNeeded {
    try client.createCollection(name: "smoke", recoveryPhrase: phrase)
}

let listener = Listener()
let watch = try client.watch(listener: listener)
try client.set(collection: "smoke", entries: [
    NewEntry(name: "prod/TOKEN", kind: .secret, value: Data("abc".utf8)),
    NewEntry(name: "prod/REGION", kind: .variable, value: Data("eu west".utf8)),
])
check(listener.changed.wait(timeout: .now() + 10) == .success, "no event for the write")

let entries = try client.entries(collection: "smoke")
check(entries.map(\.name) == ["prod/REGION", "prod/TOKEN"], "entries \(entries.map(\.name))")
check(entries[0].value == Data("eu west".utf8), "a variable's value")
check(entries[1].value == nil, "a list held a secret's value")
check(entries.allSatisfy { $0.setBy == vault.device }, "who set them")
let token = try client.get(collection: "smoke", name: "prod/TOKEN")
check(token?.value == Data("abc".utf8) && token?.kind == .secret, "the secret's value")

let collections = try client.collections()
check(collections.count == 1 && collections[0].secrets == 1 && collections[0].variables == 1,
      "collections \(collections)")
check(collections[0].devices.map(\.scope) == [.write], "scopes \(collections[0].devices)")
let log = try client.log(from: 0, max: 16)
check(log.first?.change == .genesis && log.allSatisfy { $0.signer == .recoveryKey },
      "log \(log)")
check(try client.peers().isEmpty, "peers")
check(try client.devices().count == 1, "devices")

// Files: written from a path, listed with their size, written out again, and left alone when a
// save holds what the current version does.
let scratch = FileManager.default.temporaryDirectory.appending(path: "ffi-smoke-\(UUID().uuidString)")
try FileManager.default.createDirectory(at: scratch, withIntermediateDirectories: true)
defer { try? FileManager.default.removeItem(at: scratch) }
let original = scratch.appending(path: "notes.bin")
let bytes = Data((0..<(100 << 10)).map { UInt8($0 % 251) })
try bytes.write(to: original)
check(try client.writeFile(collection: "smoke", name: "docs/notes.bin", path: original.path), "a file wasn't written")
check(!(try client.writeFile(collection: "smoke", name: "docs/notes.bin", path: original.path)),
      "the same contents were written again")
let file = try client.entries(collection: "smoke").first { $0.name == "docs/notes.bin" }
check(file?.kind == .file && file?.size == UInt64(bytes.count) && file?.missing == 0 && file?.value == nil,
      "the file as listed: \(String(describing: file?.size))")
check(try client.fetch(collection: "smoke", name: "docs/notes.bin") == 0, "its chunks are here")
let copy = scratch.appending(path: "copy.bin")
try client.exportFile(collection: "smoke", name: "docs/notes.bin", path: copy.path)
check(try Data(contentsOf: copy) == bytes, "the copy's bytes")
let mode = try FileManager.default.attributesOfItem(atPath: copy.path)[.posixPermissions] as? Int
check(mode == 0o600, "the copy's mode \(String(describing: mode))")
check(try client.get(collection: "smoke", name: "docs/notes.bin") == nil, "get gave a file's manifest")
do {
    _ = try client.writeFile(collection: "smoke", name: "prod/TOKEN", path: original.path)
    check(false, "a file took a secret's name")
} catch OpenVaultError.Failed {}
check(try client.collections()[0].files == 1, "the collection's file count")
check(try client.placement(collection: "smoke", set: .onDemand) == .onDemand, "on demand")
check(try client.placement(collection: "smoke", set: .keep) == .keep, "keep")
_ = diskNotEncrypted()

watch.stop()
check(listener.ended.wait(timeout: .now() + 10) == .success, "the watch didn't end")
print("openvault-ffi \(version()) works from Swift: \(entries.count) entries, a file, \(log.count) log entries")
