import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/update_protocol.dart';

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
        return ProcessResult(1, 0, '{"version":"0.8.0"}', '');
      },
    );

    final result = await protocol.download(developmentSignature: true);
    expect(result['version'], '0.8.0');
    expect(captured, containsAllInOrder([
      'manager-update',
      'download',
      '--current-version',
      '0.8.0-rc.1',
      '--state-dir',
      r'C:\state',
      '--development-signature',
    ]));
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
        return ProcessResult(1, 0, '{"requires_manager_exit":true}', '');
      },
    );

    final result = await protocol.apply();
    expect(result['requires_manager_exit'], true);
    expect(captured, containsAllInOrder([
      'manager-update',
      'apply',
      '--install-dir',
      r'C:\Program Files\LinkLake Manager',
      '--manager-pid',
      '4242',
      '--yes',
    ]));
  });

  test('non-zero updater exit is surfaced without interpreting stdout', () async {
    final protocol = ManagerUpdateProtocol(
      clientExecutable: 'linklake-client',
      installDirectory: '/opt/linklake-manager',
      currentReleaseVersion: '0.8.0-rc.1',
      processRunner: (_, __) async => ProcessResult(1, 7, '', 'denied'),
    );
    expect(protocol.status, throwsA(isA<ManagerUpdateException>()));
  });
}
