import Cocoa
import FlutterMacOS
import LaunchAtLogin

class MainFlutterWindow: NSWindow {
  private var launchAtStartupChannel: FlutterMethodChannel?

  override func awakeFromNib() {
    let flutterViewController = FlutterViewController()
    let windowFrame = self.frame
    self.contentViewController = flutterViewController
    self.setFrame(windowFrame, display: true)

    // launch_at_startup 的 macOS 实现需要由宿主提供平台通道。
    LaunchAtLogin.migrateIfNeeded()
    let channel = FlutterMethodChannel(
      name: "launch_at_startup",
      binaryMessenger: flutterViewController.engine.binaryMessenger
    )
    channel.setMethodCallHandler { call, result in
      switch call.method {
      case "launchAtStartupIsEnabled":
        result(LaunchAtLogin.isEnabled)
      case "launchAtStartupSetEnabled":
        guard
          let arguments = call.arguments as? [String: Any],
          let enabled = arguments["setEnabledValue"] as? Bool
        else {
          result(
            FlutterError(
              code: "invalid_arguments",
              message: "setEnabledValue must be a boolean",
              details: nil
            )
          )
          return
        }
        LaunchAtLogin.isEnabled = enabled
        result(nil)
      default:
        result(FlutterMethodNotImplemented)
      }
    }
    launchAtStartupChannel = channel

    RegisterGeneratedPlugins(registry: flutterViewController)

    super.awakeFromNib()
  }
}
