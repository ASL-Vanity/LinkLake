import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/update_protocol.dart';

const stagedResponse = <String, Object?>{
  'schema_version': 2,
  'current_version': '0.8.0-rc.1',
  'version': '0.8.0',
  'target': 'windows-x86_64',
  'archive_name': 'linklake-manager-0.8.0-windows-x86_64.zip',
  'archive_sha256':
      'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
  'signature_key_id': 'release-2026',
  'staged_directory': r'C:\state\staging\manager',
  'staged_manifest': r'C:\state\staging\manager-staged.json',
  'payload_sha256':
      'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb',
  'downloaded_unix_seconds': 1785700000,
};

const scheduleResponse = <String, Object?>{
  'schema_version': 2,
  'state': 'scheduled',
  'operation': 'apply',
  'from_version': '0.8.0-rc.1',
  'to_version': '0.8.0',
  'status_file': r'C:\state\manager-status.json',
  'helper_process_id': 777,
  'requires_manager_exit': true,
  'manager_process_id': 4242,
  'manager_process_identity': '4242:1785700000',
  'exit_timeout_seconds': 60,
  'exit_deadline_unix_seconds': 1785700060,
};

void main() {
  test('download uses the stable Rust CLI and parses JSON', () async {
    late List<String> captured;
    final protocol = ManagerUpdateProtocol(
      clientExecutable: 'linklake-client',
      installDirectory: r'C:\Program Files\LinkLake Manager',
      currentReleaseVersion: '0.8.0-rc.1',
      stateDirectory: r'C:\state',
      managerProcessId: 4242,
      processRunner: (executable, arguments) async {
        expect(executable, 'linklake-client');
        captured = arguments;
        return ProcessResult(1, 0, jsonEncode(stagedResponse), '');
      },
    );

    final result = await protocol.download(developmentSignature: true);
    expect(result['version'], '0.8.0');
    expect(
      captured,
      containsAllInOrder([
        'manager-update',
        'download',
        '--current-version',
        '0.8.0-rc.1',
        '--state-dir',
        r'C:\state',
        '--development-signature',
      ]),
    );
  });

  test('apply sends the Manager exit-handshake process ID', () async {
    late List<String> captured;
    final protocol = ManagerUpdateProtocol(
      clientExecutable: 'linklake-client',
      installDirectory: r'C:\Program Files\LinkLake Manager',
      currentReleaseVersion: '0.8.0-rc.1',
      managerProcessId: 4242,
      processRunner: (_, arguments) async {
        captured = arguments;
        return ProcessResult(1, 0, jsonEncode(scheduleResponse), '');
      },
    );

    final result = await protocol.apply();
    expect(result['requires_manager_exit'], true);
    expect(
      captured,
      containsAllInOrder([
        'manager-update',
        'apply',
        '--install-dir',
        r'C:\Program Files\LinkLake Manager',
        '--manager-pid',
        '4242',
        '--yes',
      ]),
    );
  });

  test(
    'non-zero updater exit is surfaced without interpreting stdout',
    () async {
      final protocol = ManagerUpdateProtocol(
        clientExecutable: 'linklake-client',
        installDirectory: '/opt/linklake-manager',
        currentReleaseVersion: '0.8.0-rc.1',
        processRunner: (_, arguments) async =>
            ProcessResult(1, 7, '', 'denied'),
      );
      expect(protocol.status, throwsA(isA<ManagerUpdateException>()));
    },
  );

  test('schema v2 rejects missing process identity and status path', () {
    final invalid = Map<String, Object?>.from(scheduleResponse)
      ..remove('manager_process_identity');
    expect(
      () => validateManagerUpdateResponse(
        invalid,
        ManagerUpdateResponseKind.schedule,
      ),
      throwsA(isA<FormatException>()),
    );
  });
}
