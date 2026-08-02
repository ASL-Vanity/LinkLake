import 'dart:convert';
import 'dart:io';

typedef ProcessRunner = Future<ProcessResult> Function(
  String executable,
  List<String> arguments,
);

/// Stable process/JSON boundary between the Flutter UI and the Rust updater.
///
/// UI code should call this class and then exit after [apply] reports
/// `requires_manager_exit=true`. The detached Rust helper owns installation and
/// rollback, so Flutter never replaces files that it currently has open.
class ManagerUpdateProtocol {
  ManagerUpdateProtocol({
    required this.clientExecutable,
    required this.installDirectory,
    required this.currentReleaseVersion,
    this.stateDirectory,
    int? managerProcessId,
    ProcessRunner? processRunner,
  })  : managerProcessId = managerProcessId ?? pid,
        _run = processRunner ?? Process.run;

  final String clientExecutable;
  final String installDirectory;
  final String currentReleaseVersion;
  final String? stateDirectory;
  final int managerProcessId;
  final ProcessRunner _run;

  Future<Map<String, Object?>> download({
    String repository = 'ASL-Vanity/LinkLake',
    String channel = 'auto',
    bool developmentSignature = false,
  }) => _invoke([
    'manager-update',
    'download',
    '--repository',
    repository,
    '--channel',
    channel,
    '--current-version',
    currentReleaseVersion,
    if (stateDirectory != null) ...['--state-dir', stateDirectory!],
    if (developmentSignature) '--development-signature',
  ]);

  Future<Map<String, Object?>> apply() => _invoke([
    'manager-update',
    'apply',
    '--install-dir',
    installDirectory,
    '--manager-pid',
    managerProcessId.toString(),
    '--yes',
    if (stateDirectory != null) ...['--state-dir', stateDirectory!],
  ]);

  Future<Map<String, Object?>> status() => _invoke([
    'manager-update',
    'status',
    if (stateDirectory != null) ...['--state-dir', stateDirectory!],
  ]);

  Future<Map<String, Object?>> rollback() => _invoke([
    'manager-update',
    'rollback',
    '--install-dir',
    installDirectory,
    '--manager-pid',
    managerProcessId.toString(),
    '--yes',
    if (stateDirectory != null) ...['--state-dir', stateDirectory!],
  ]);

  Future<Map<String, Object?>> _invoke(List<String> arguments) async {
    final result = await _run(clientExecutable, arguments);
    if (result.exitCode != 0) {
      throw ManagerUpdateException(
        result.exitCode,
        result.stderr.toString().trim(),
      );
    }
    final value = jsonDecode(result.stdout.toString());
    if (value is! Map<String, dynamic>) {
      throw const FormatException('Updater returned a non-object JSON value.');
    }
    return value.cast<String, Object?>();
  }
}

class ManagerUpdateException implements Exception {
  const ManagerUpdateException(this.exitCode, this.message);

  final int exitCode;
  final String message;

  @override
  String toString() => 'Manager updater failed ($exitCode): $message';
}
