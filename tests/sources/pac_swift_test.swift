import Foundation
import Darwin

protocol Plugin: AnyObject {
    var name: String { get }
    func initialize(config: [String: Any]) -> Bool
    func process(input: Any) -> Any
    func cleanup()
}

class PluginManager {
    var plugins: [String: Plugin] = [:]
    var callbacks: [String: (Any) -> Void] = [:]

    func register(_ plugin: Plugin) {
        plugins[plugin.name] = plugin
    }

    func addCallback(name: String, handler: @escaping (Any) -> Void) {
        callbacks[name] = handler
    }

    func dispatch(pluginName: String, input: Any) -> Any? {
        guard let p = plugins[pluginName] else { return nil }
        let result = p.process(input: input)
        if let cb = callbacks[pluginName] {
            cb(result)
        }
        return result
    }
}

class DataProcessor: Plugin {
    let name = "data"
    private var config: [String: Any] = [:]
    var onComplete: ((Bool, Any?) -> Void)?

    func initialize(config: [String: Any]) -> Bool {
        self.config = config
        return true
    }

    func process(input: Any) -> Any {
        if let str = input as? String {
            return str.uppercased()
        }
        return input
    }

    func cleanup() {
        config = [:]
        onComplete = nil
    }
}

class NetworkSimulator: Plugin {
    let name = "network"
    private var dlHandle: UnsafeMutableRawPointer?

    func initialize(config: [String: Any]) -> Bool {
        dlHandle = dlopen("/usr/lib/libSystem.B.dylib", RTLD_LAZY)
        return dlHandle != nil
    }

    func process(input: Any) -> Any {
        guard let handle = dlHandle,
              let sym = dlsym(handle, "getenv") else {
            return "no_handle"
        }
        typealias GetenvFn = @convention(c) (UnsafePointer<CChar>) -> UnsafeMutablePointer<CChar>?
        let getenvFn = unsafeBitCast(sym, to: GetenvFn.self)
        if let result = getenvFn("HOME") {
            return String(cString: result)
        }
        return "unknown"
    }

    func cleanup() {
        if let handle = dlHandle {
            dlclose(handle)
            dlHandle = nil
        }
    }
}

func testClosuresAndCapture() {
    var captured = 0
    let closures: [() -> Int] = (0..<5).map { i in
        return {
            captured += i
            return captured
        }
    }
    for c in closures {
        print("Closure result: \(c())")
    }
}

func testErrorHandling() {
    enum MyError: Error {
        case invalidInput
        case timeout
    }

    func riskyOperation(_ value: Int) throws -> String {
        guard value > 0 else { throw MyError.invalidInput }
        guard value < 100 else { throw MyError.timeout }
        return "OK: \(value)"
    }

    do {
        let result = try riskyOperation(42)
        print("Success: \(result)")
    } catch {
        print("Error: \(error)")
    }
}

func testProtocolWitness() {
    let plugins: [Plugin] = [
        DataProcessor(),
        NetworkSimulator()
    ]
    for p in plugins {
        _ = p.initialize(config: ["mode": "test"])
        let result = p.process(input: "hello")
        print("\(p.name): \(result)")
        p.cleanup()
    }
}

func testFunctionPointers() {
    typealias MathOp = (Double, Double) -> Double
    let operations: [String: MathOp] = [
        "add": { $0 + $1 },
        "mul": { $0 * $1 },
    ]
    for (name, op) in operations {
        print("\(name)(3,4) = \(op(3, 4))")
    }
}

func testSpawnInSwift() {
    var pid: pid_t = 0
    let argv: [UnsafeMutablePointer<CChar>?] = [
        strdup("/bin/echo"),
        strdup("Swift spawned process"),
        nil
    ]
    let result = posix_spawn(&pid, "/bin/echo", nil, nil, argv, nil)
    if result == 0 {
        var status: Int32 = 0
        waitpid(pid, &status, 0)
    }
    for a in argv { free(a) }
}

func testSignalRecovery() {
    signal(SIGINT, SIG_IGN)
    print("Signal handler installed")
}

// Top-level entry
let manager = PluginManager()
let dataPlugin = DataProcessor()
let netPlugin = NetworkSimulator()

manager.register(dataPlugin)
manager.register(netPlugin)

dataPlugin.onComplete = { success, value in
    print("Complete: \(success) \(value ?? "nil")")
}

manager.addCallback(name: "data") { result in
    print("Manager callback: \(result)")
}

_ = dataPlugin.initialize(config: ["verbose": true])
_ = netPlugin.initialize(config: [:])

_ = manager.dispatch(pluginName: "data", input: "test input")
_ = manager.dispatch(pluginName: "network", input: "query")

testClosuresAndCapture()
testErrorHandling()
testProtocolWitness()
testSpawnInSwift()
testFunctionPointers()
testSignalRecovery()

dataPlugin.cleanup()
netPlugin.cleanup()
