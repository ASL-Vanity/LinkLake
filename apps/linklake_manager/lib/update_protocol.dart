import 'dart:convert';
import 'dart:io';

typedef ProcessRunner =
    Future<ProcessResult> Function(String executable, List<String> arguments);

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
  }) : managerProcessId = managerProcessId ?? pid,
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
  ], ManagerUpdateResponseKind.staged);

  Future<Map<String, Object?>> apply() => _invoke([
    'manager-update',
    'apply',
    '--install-dir',
    installDirectory,
    '--manager-pid',
    managerProcessId.toString(),
    '--yes',
    if (stateDirectory != null) ...['--state-dir', stateDirectory!],
  ], ManagerUpdateResponseKind.schedule);

  Future<Map<String, Object?>> status() => _invoke([
    'manager-update',
    'status',
    if (stateDirectory != null) ...['--state-dir', stateDirectory!],
  ], ManagerUpdateResponseKind.status);

  Future<Map<String, Object?>> rollback() => _invoke([
    'manager-update',
    'rollback',
    '--install-dir',
    installDirectory,
    '--manager-pid',
    managerProcessId.toString(),
    '--yes',
    if (stateDirectory != null) ...['--state-dir', stateDirectory!],
  ], ManagerUpdateResponseKind.schedule);

  Future<Map<String, Object?>> _invoke(
    List<String> arguments,
    ManagerUpdateResponseKind kind,
  ) async {
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
    final response = value.cast<String, Object?>();
    validateManagerUpdateResponse(response, kind);
    return response;
  }
}

enum ManagerUpdateResponseKind { staged, schedule, status }

void validateManagerUpdateResponse(
  Map<String, Object?> value,
  ManagerUpdateResponseKind kind,
) {
  const stagedKeys = {
    'schema_version',
    'current_version',
    'version',
    'target',
    'archive_name',
    'archive_sha256',
    'signature_key_id',
    'staged_directory',
    'staged_manifest',
    'payload_sha256',
    'downloaded_unix_seconds',
  };
  const scheduleKeys = {
    'schema_version',
    'state',
    'operation',
    'from_version',
    'to_version',
    'status_file',
    'helper_process_id',
    'requires_manager_exit',
    'manager_process_id',
    'manager_process_identity',
    'exit_timeout_seconds',
    'exit_deadline_unix_seconds',
  };
  const statusKeys = {
    'schema_version',
    'state',
    'operation',
    'from_version',
    'to_version',
    'message',
    'error',
    'backup',
    'requires_manager_exit',
    'manager_process_id',
    'manager_process_identity',
    'exit_deadline_unix_seconds',
    'updated_unix_seconds',
  };
  final expectedKeys = switch (kind) {
    ManagerUpdateResponseKind.staged => stagedKeys,
    ManagerUpdateResponseKind.schedule => scheduleKeys,
    ManagerUpdateResponseKind.status => statusKeys,
  };
  if (value.keys.toSet().difference(expectedKeys).isNotEmpty ||
      expectedKeys.difference(value.keys.toSet()).isNotEmpty) {
    throw const FormatException(
      'Updater response does not match Manager update schema v2.',
    );
  }
  _expect(value['schema_version'] == 2, 'schema_version must be 2');
  switch (kind) {
    case ManagerUpdateResponseKind.staged:
      for (final key in [
        'current_version',
        'version',
        'target',
        'archive_name',
        'signature_key_id',
        'staged_directory',
        'staged_manifest',
      ]) {
        _expect(_nonEmptyString(value[key]), '$key must be a string');
      }
      for (final key in ['archive_sha256', 'payload_sha256']) {
        _expect(
          value[key] is String &&
              RegExp(r'^[0-9a-f]{64}$').hasMatch(value[key]! as String),
          '$key must be a lowercase SHA-256 value',
        );
      }
      _expect(
        value['downloaded_unix_seconds'] is int &&
            (value['downloaded_unix_seconds']! as int) > 0,
        'downloaded_unix_seconds must be positive',
      );
    case ManagerUpdateResponseKind.schedule:
      _expect(value['state'] == 'scheduled', 'state must be scheduled');
      _expect(
        value['operation'] == 'apply' || value['operation'] == 'rollback',
        'operation must be apply or rollback',
      );
      for (final key in [
        'from_version',
        'to_version',
        'status_file',
        'manager_process_identity',
      ]) {
        _expect(_nonEmptyString(value[key]), '$key must be a string');
      }
      for (final key in [
        'helper_process_id',
        'manager_process_id',
        'exit_timeout_seconds',
        'exit_deadline_unix_seconds',
      ]) {
        _expect(value[key] is int && (value[key]! as int) > 0, '$key invalid');
      }
      _expect(
        value['requires_manager_exit'] == true,
        'scheduled update must require Manager exit',
      );
    case ManagerUpdateResponseKind.status:
      const states = {
        'idle',
        'scheduled',
        'waiting_for_exit',
        'installing',
        'succeeded',
        'rolled_back',
        'failed',
      };
      _expect(states.contains(value['state']), 'invalid Manager update state');
      _expect(
        value['operation'] == null ||
            value['operation'] == 'apply' ||
            value['operation'] == 'rollback',
        'invalid Manager update operation',
      );
      for (final key in ['from_version', 'to_version', 'error', 'backup']) {
        _expect(value[key] == null || value[key] is String, '$key invalid');
      }
      _expect(value['message'] is String, 'message must be a string');
      _expect(
        value['requires_manager_exit'] is bool,
        'requires_manager_exit must be a boolean',
      );
      _expect(
        value['manager_process_id'] == null ||
            (value['manager_process_id'] is int &&
                (value['manager_process_id']! as int) > 0),
        'manager_process_id invalid',
      );
      _expect(
        value['manager_process_identity'] == null ||
            _nonEmptyString(value['manager_process_identity']),
        'manager_process_identity invalid',
      );
      _expect(
        value['exit_deadline_unix_seconds'] == null ||
            (value['exit_deadline_unix_seconds'] is int &&
                (value['exit_deadline_unix_seconds']! as int) > 0),
        'exit_deadline_unix_seconds invalid',
      );
      _expect(
        value['updated_unix_seconds'] is int &&
            (value['updated_unix_seconds']! as int) > 0,
        'updated_unix_seconds invalid',
      );
  }
}

bool _nonEmptyString(Object? value) =>
    value is String && value.trim().isNotEmpty;

void _expect(bool condition, String message) {
  if (!condition) throw FormatException(message);
}

class ManagerUpdateException implements Exception {
  const ManagerUpdateException(this.exitCode, this.message);

  final int exitCode;
  final String message;

  @override
  String toString() => 'Manager updater failed ($exitCode): $message';
}
