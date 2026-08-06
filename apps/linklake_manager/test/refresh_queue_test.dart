import 'dart:async';

import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/refresh_queue.dart';

void main() {
  test(
    'overlapping mutation refresh waits for one newer coalesced snapshot',
    () async {
      final gates = <Completer<void>>[];
      final silentModes = <bool>[];
      final queue = RefreshQueue((silent) async {
        silentModes.add(silent);
        final gate = Completer<void>();
        gates.add(gate);
        await gate.future;
      });
      addTearDown(queue.dispose);

      final initial = queue.request(silent: true);
      expect(gates, hasLength(1));

      var mutationRefreshCompleted = false;
      final mutationRefresh = queue.request(silent: true).then((_) {
        mutationRefreshCompleted = true;
      });
      final coalescedRefresh = queue.request(silent: false);
      expect(gates, hasLength(1));

      gates.first.complete();
      await initial;
      await Future<void>.delayed(Duration.zero);
      expect(gates, hasLength(2));
      expect(mutationRefreshCompleted, isFalse);
      expect(silentModes, [true, false]);

      gates.last.complete();
      await Future.wait([mutationRefresh, coalescedRefresh]);
      expect(mutationRefreshCompleted, isTrue);
      expect(gates, hasLength(2));
    },
  );

  test(
    'dispose completes waiters without starting a queued callback',
    () async {
      final gate = Completer<void>();
      var callbacks = 0;
      final queue = RefreshQueue((_) async {
        callbacks++;
        await gate.future;
      });

      final active = queue.request();
      final queued = queue.request();
      queue.dispose();
      await Future.wait([active, queued]);
      expect(callbacks, 1);

      gate.complete();
      await Future<void>.delayed(Duration.zero);
      expect(callbacks, 1);
    },
  );
}
