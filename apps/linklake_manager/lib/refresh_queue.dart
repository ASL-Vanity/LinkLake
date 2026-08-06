import 'dart:async';

typedef RefreshOperation = Future<void> Function(bool silent);

/// 将刷新请求合并为顺序快照，并保证刷新期间提交的新请求至少等待下一轮快照。
class RefreshQueue {
  RefreshQueue(this._operation);

  final RefreshOperation _operation;
  final Map<int, bool> _silentByGeneration = {};
  final List<_RefreshWaiter> _waiters = [];

  int _requestedGeneration = 0;
  int _activeGeneration = 0;
  int _completedGeneration = 0;
  bool _running = false;
  bool _disposed = false;

  Future<void> request({bool silent = false}) {
    if (_disposed) return Future<void>.value();

    final targetGeneration = _activeGeneration > _completedGeneration
        ? _activeGeneration + 1
        : _completedGeneration + 1;
    if (_requestedGeneration < targetGeneration) {
      _requestedGeneration = targetGeneration;
    }
    _silentByGeneration[targetGeneration] =
        (_silentByGeneration[targetGeneration] ?? true) && silent;

    final completer = Completer<void>();
    _waiters.add(_RefreshWaiter(targetGeneration, completer));
    if (!_running) {
      _running = true;
      unawaited(_run());
    }
    return completer.future;
  }

  void dispose() {
    if (_disposed) return;
    _disposed = true;
    for (final waiter in _waiters) {
      if (!waiter.completer.isCompleted) waiter.completer.complete();
    }
    _waiters.clear();
    _silentByGeneration.clear();
  }

  Future<void> _run() async {
    try {
      while (!_disposed && _completedGeneration < _requestedGeneration) {
        final generation = _completedGeneration + 1;
        _activeGeneration = generation;
        final silent = _silentByGeneration.remove(generation) ?? true;
        Object? failure;
        StackTrace? failureStack;
        try {
          await _operation(silent);
        } catch (error, stackTrace) {
          failure = error;
          failureStack = stackTrace;
        }
        _completedGeneration = generation;
        _completeGeneration(generation, failure, failureStack);
      }
    } finally {
      _activeGeneration = _completedGeneration;
      _running = false;
    }
  }

  void _completeGeneration(
    int generation,
    Object? failure,
    StackTrace? failureStack,
  ) {
    final completed = _waiters
        .where((waiter) => waiter.generation <= generation)
        .toList(growable: false);
    _waiters.removeWhere((waiter) => waiter.generation <= generation);
    for (final waiter in completed) {
      if (waiter.completer.isCompleted) continue;
      if (failure == null) {
        waiter.completer.complete();
      } else {
        waiter.completer.completeError(failure, failureStack);
      }
    }
  }
}

class _RefreshWaiter {
  const _RefreshWaiter(this.generation, this.completer);

  final int generation;
  final Completer<void> completer;
}
