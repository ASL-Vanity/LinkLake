import 'dart:math' as math;

import 'package:flutter/material.dart';

import 'api_client.dart';

enum MetricsRange {
  oneHour('1h'),
  twelveHours('12h'),
  oneDay('1d'),
  sevenDays('7d'),
  thirtyDays('30d');

  const MetricsRange(this.key);

  final String key;
}

class MetricsHistoryPoint {
  const MetricsHistoryPoint({
    required this.timestampUnixSeconds,
    required this.inboundBps,
    required this.outboundBps,
    required this.activeConnections,
    required this.activeSessions,
    required this.requestsPerSecond,
    required this.errorsPerSecond,
  });

  factory MetricsHistoryPoint.fromJson(Map<String, dynamic> value) =>
      MetricsHistoryPoint(
        timestampUnixSeconds:
            (value['timestamp_unix_seconds'] as num?)?.toInt() ?? 0,
        inboundBps: (value['inbound_bps'] as num?)?.toDouble() ?? 0,
        outboundBps: (value['outbound_bps'] as num?)?.toDouble() ?? 0,
        activeConnections: (value['active_connections'] as num?)?.toInt() ?? 0,
        activeSessions: (value['active_sessions'] as num?)?.toInt() ?? 0,
        requestsPerSecond:
            (value['requests_per_second'] as num?)?.toDouble() ?? 0,
        errorsPerSecond: (value['errors_per_second'] as num?)?.toDouble() ?? 0,
      );

  final int timestampUnixSeconds;
  final double inboundBps;
  final double outboundBps;
  final int activeConnections;
  final int activeSessions;
  final double requestsPerSecond;
  final double errorsPerSecond;

  int get activeTotal => activeConnections + activeSessions;
}

class MetricsHistorySeries {
  const MetricsHistorySeries({
    required this.protocol,
    required this.range,
    required this.points,
    required this.sampleIntervalSeconds,
    required this.stepSeconds,
  });

  factory MetricsHistorySeries.fromJson(
    Map<String, dynamic> value,
  ) => MetricsHistorySeries(
    protocol: value['protocol']?.toString() ?? 'total',
    range: value['range']?.toString() ?? '1h',
    points: (value['points'] as List? ?? const [])
        .whereType<Map>()
        .map(
          (point) =>
              MetricsHistoryPoint.fromJson(Map<String, dynamic>.from(point)),
        )
        .toList(growable: false),
    sampleIntervalSeconds:
        (value['sample_interval_seconds'] as num?)?.toInt() ?? 0,
    stepSeconds: (value['step_seconds'] as num?)?.toInt() ?? 0,
  );

  final String protocol;
  final String range;
  final List<MetricsHistoryPoint> points;
  final int sampleIntervalSeconds;
  final int stepSeconds;
}

String metricsHistoryPath({
  required String protocol,
  required MetricsRange range,
}) => Uri(
  path: '/api/v1/metrics/history',
  queryParameters: {'range': range.key, 'protocol': protocol},
).toString();

String policyMetricsHistoryPath({
  required String kind,
  required String policyId,
  required MetricsRange range,
}) => Uri(
  path: '/api/v1/metrics/policies/$kind/$policyId/history',
  queryParameters: {'range': range.key},
).toString();

String historyProtocolForPolicyKey(String key) => switch (key) {
  'tcp' => 'tcp',
  'udp' => 'udp',
  'http' || 'sni' => 'web',
  'secret' => 'secret',
  'socks5' || 'proxy' => 'proxy',
  _ => 'total',
};

class MetricsHistoryPanel extends StatefulWidget {
  const MetricsHistoryPanel({
    super.key,
    required this.api,
    required this.protocol,
    required this.chinese,
    required this.title,
    required this.subtitle,
    this.compact = false,
    this.initiallyExpanded = true,
    this.policyKind,
    this.policyId,
  });

  final LinkLakeApi api;
  final String protocol;
  final bool chinese;
  final String title;
  final String subtitle;
  final bool compact;
  final bool initiallyExpanded;
  final String? policyKind;
  final String? policyId;

  @override
  State<MetricsHistoryPanel> createState() => _MetricsHistoryPanelState();
}

class _MetricsHistoryPanelState extends State<MetricsHistoryPanel> {
  MetricsRange _range = MetricsRange.oneHour;
  MetricsHistorySeries? _series;
  String? _error;
  bool _loading = false;
  late bool _expanded;
  int _generation = 0;
  final Map<String, (DateTime, MetricsHistorySeries)> _cache = {};

  String t(String chinese, String english) =>
      widget.chinese ? chinese : english;

  @override
  void initState() {
    super.initState();
    _expanded = widget.initiallyExpanded;
    _load(_range);
  }

  @override
  void didUpdateWidget(covariant MetricsHistoryPanel oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (oldWidget.api != widget.api ||
        oldWidget.protocol != widget.protocol ||
        oldWidget.policyKind != widget.policyKind ||
        oldWidget.policyId != widget.policyId) {
      _cache.clear();
      _series = null;
      _load(_range);
    }
  }

  Future<void> _load(MetricsRange range) async {
    final generation = ++_generation;
    final path = widget.policyKind != null && widget.policyId != null
        ? policyMetricsHistoryPath(
            kind: widget.policyKind!,
            policyId: widget.policyId!,
            range: range,
          )
        : metricsHistoryPath(protocol: widget.protocol, range: range);
    final cached = _cache[path];
    if (cached != null &&
        DateTime.now().difference(cached.$1) < const Duration(seconds: 30)) {
      if (!mounted || generation != _generation) return;
      setState(() {
        _range = range;
        _series = cached.$2;
        _loading = false;
        _error = null;
      });
      return;
    }
    if (mounted) {
      setState(() {
        _range = range;
        _loading = true;
        _error = null;
      });
    }
    try {
      final value = await widget.api.getObject(path);
      final series = MetricsHistorySeries.fromJson(value);
      if (!mounted || generation != _generation) return;
      _cache[path] = (DateTime.now(), series);
      setState(() {
        _series = series;
        _loading = false;
      });
    } catch (error) {
      if (!mounted || generation != _generation) return;
      setState(() {
        _loading = false;
        _error = error.toString();
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    final series = _series;
    if (!_expanded) {
      return Card(
        child: ListTile(
          title: Text(
            widget.title,
            style: const TextStyle(fontWeight: FontWeight.w700),
          ),
          subtitle: Text(widget.subtitle),
          trailing: IconButton(
            key: Key('expand-metrics-${widget.protocol}'),
            tooltip: t('展开图表', 'Expand chart'),
            onPressed: () => setState(() => _expanded = true),
            icon: const Icon(Icons.expand_more),
          ),
        ),
      );
    }
    return Card(
      child: Padding(
        padding: EdgeInsets.all(widget.compact ? 14 : 18),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Wrap(
              spacing: 12,
              runSpacing: 10,
              crossAxisAlignment: WrapCrossAlignment.center,
              children: [
                SizedBox(
                  width: widget.compact ? 330 : 430,
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(
                        widget.title,
                        style: Theme.of(context).textTheme.titleMedium
                            ?.copyWith(fontWeight: FontWeight.w700),
                      ),
                      Text(
                        widget.subtitle,
                        style: Theme.of(context).textTheme.bodySmall?.copyWith(
                          color: Theme.of(context).colorScheme.onSurfaceVariant,
                        ),
                      ),
                    ],
                  ),
                ),
                for (final range in MetricsRange.values)
                  ChoiceChip(
                    key: Key('metrics-range-${widget.protocol}-${range.key}'),
                    label: Text(range.key),
                    selected: _range == range,
                    onSelected: _loading && _range == range
                        ? null
                        : (_) => _load(range),
                    visualDensity: VisualDensity.compact,
                  ),
                if (!widget.initiallyExpanded)
                  IconButton(
                    tooltip: t('收起图表', 'Collapse chart'),
                    onPressed: () => setState(() => _expanded = false),
                    icon: const Icon(Icons.expand_less),
                  ),
              ],
            ),
            const SizedBox(height: 12),
            if (_loading) const LinearProgressIndicator(minHeight: 2),
            if (_error != null) ...[
              const SizedBox(height: 8),
              Row(
                children: [
                  Expanded(
                    child: Text(
                      _error!,
                      style: TextStyle(
                        color: Theme.of(context).colorScheme.error,
                      ),
                    ),
                  ),
                  TextButton(
                    onPressed: () => _load(_range),
                    child: Text(t('重试', 'Retry')),
                  ),
                ],
              ),
            ],
            SizedBox(
              height: widget.compact ? 205 : 260,
              child: series == null || series.points.isEmpty
                  ? Center(
                      child: Text(
                        _loading
                            ? t('正在加载历史指标…', 'Loading history…')
                            : t('该时间范围暂无数据', 'No data for this range'),
                      ),
                    )
                  : MetricsLineChart(
                      key: Key('metrics-chart-${widget.protocol}'),
                      points: series.points,
                      chinese: widget.chinese,
                    ),
            ),
            if (series != null && series.points.isNotEmpty)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text(
                  '${t('样本', 'Samples')}: ${series.points.length} · '
                  '${t('步长', 'Step')}: ${series.stepSeconds}s',
                  style: Theme.of(context).textTheme.labelSmall?.copyWith(
                    color: Theme.of(context).colorScheme.onSurfaceVariant,
                  ),
                ),
              ),
          ],
        ),
      ),
    );
  }
}

class MetricsLineChart extends StatelessWidget {
  const MetricsLineChart({
    super.key,
    required this.points,
    required this.chinese,
  });

  final List<MetricsHistoryPoint> points;
  final bool chinese;

  @override
  Widget build(BuildContext context) {
    final latest = points.last;
    return Semantics(
      label: chinese ? '流量与连接历史趋势图' : 'Traffic and connection history chart',
      value:
          '${_formatRate(latest.inboundBps)} / ${_formatRate(latest.outboundBps)}, '
          '${latest.activeTotal} ${chinese ? '活动会话' : 'active sessions'}',
      child: Column(
        children: [
          Wrap(
            spacing: 14,
            runSpacing: 4,
            children: [
              _Legend(
                color: Theme.of(context).colorScheme.primary,
                label: chinese ? '入站' : 'Inbound',
                value: _formatRate(latest.inboundBps),
              ),
              _Legend(
                color: Theme.of(context).colorScheme.tertiary,
                label: chinese ? '出站' : 'Outbound',
                value: _formatRate(latest.outboundBps),
              ),
              _Legend(
                color: Theme.of(context).colorScheme.secondary,
                label: chinese ? '活动连接' : 'Active',
                value: '${latest.activeTotal}',
              ),
            ],
          ),
          const SizedBox(height: 10),
          Expanded(
            child: RepaintBoundary(
              child: CustomPaint(
                painter: _MetricsLinePainter(
                  points: points,
                  inboundColor: Theme.of(context).colorScheme.primary,
                  outboundColor: Theme.of(context).colorScheme.tertiary,
                  activeColor: Theme.of(context).colorScheme.secondary,
                  gridColor: Theme.of(context).colorScheme.outlineVariant,
                ),
                size: Size.infinite,
              ),
            ),
          ),
        ],
      ),
    );
  }
}

class _Legend extends StatelessWidget {
  const _Legend({
    required this.color,
    required this.label,
    required this.value,
  });

  final Color color;
  final String label;
  final String value;

  @override
  Widget build(BuildContext context) => Row(
    mainAxisSize: MainAxisSize.min,
    children: [
      Container(
        width: 10,
        height: 10,
        decoration: BoxDecoration(color: color, shape: BoxShape.circle),
      ),
      const SizedBox(width: 5),
      Text('$label $value', style: Theme.of(context).textTheme.labelSmall),
    ],
  );
}

class _MetricsLinePainter extends CustomPainter {
  const _MetricsLinePainter({
    required this.points,
    required this.inboundColor,
    required this.outboundColor,
    required this.activeColor,
    required this.gridColor,
  });

  final List<MetricsHistoryPoint> points;
  final Color inboundColor;
  final Color outboundColor;
  final Color activeColor;
  final Color gridColor;

  @override
  void paint(Canvas canvas, Size size) {
    if (points.isEmpty || size.isEmpty) return;
    final chart = Rect.fromLTWH(2, 4, size.width - 4, size.height - 8);
    final grid = Paint()
      ..color = gridColor.withValues(alpha: 0.65)
      ..strokeWidth = 1;
    for (var index = 0; index <= 4; index++) {
      final y = chart.top + chart.height * index / 4;
      canvas.drawLine(Offset(chart.left, y), Offset(chart.right, y), grid);
    }
    final maxRate = points.fold<double>(1, (value, point) {
      return math.max(value, math.max(point.inboundBps, point.outboundBps));
    });
    final maxActive = points.fold<int>(1, (value, point) {
      return math.max(value, point.activeTotal);
    });
    _drawLine(
      canvas,
      chart,
      inboundColor,
      points.map((point) => point.inboundBps / maxRate).toList(),
    );
    _drawLine(
      canvas,
      chart,
      outboundColor,
      points.map((point) => point.outboundBps / maxRate).toList(),
    );
    _drawLine(
      canvas,
      chart,
      activeColor,
      points.map((point) => point.activeTotal / maxActive).toList(),
      dashed: true,
    );
  }

  void _drawLine(
    Canvas canvas,
    Rect chart,
    Color color,
    List<double> values, {
    bool dashed = false,
  }) {
    final path = Path();
    for (var index = 0; index < values.length; index++) {
      final x = values.length == 1
          ? chart.center.dx
          : chart.left + chart.width * index / (values.length - 1);
      final y = chart.bottom - chart.height * values[index].clamp(0, 1);
      if (index == 0) {
        path.moveTo(x, y);
      } else {
        path.lineTo(x, y);
      }
    }
    final paint = Paint()
      ..color = color
      ..strokeWidth = dashed ? 1.8 : 2.4
      ..strokeCap = StrokeCap.round
      ..strokeJoin = StrokeJoin.round
      ..style = PaintingStyle.stroke;
    canvas.drawPath(path, paint);
  }

  @override
  bool shouldRepaint(covariant _MetricsLinePainter oldDelegate) =>
      oldDelegate.points != points ||
      oldDelegate.inboundColor != inboundColor ||
      oldDelegate.outboundColor != outboundColor ||
      oldDelegate.activeColor != activeColor ||
      oldDelegate.gridColor != gridColor;
}

class ClientInsightSnapshot {
  const ClientInsightSnapshot({
    required this.total,
    required this.online,
    required this.offline,
    required this.disabled,
    required this.configurationIssues,
    required this.platforms,
    required this.configModes,
  });

  factory ClientInsightSnapshot.fromClients(
    List<dynamic> clients, {
    int? nowUnixSeconds,
  }) {
    final now = nowUnixSeconds ?? DateTime.now().millisecondsSinceEpoch ~/ 1000;
    final values = clients
        .whereType<Map>()
        .map((client) => Map<String, dynamic>.from(client))
        .toList(growable: false);
    var online = 0;
    var enabled = 0;
    var issues = 0;
    final platforms = <String, int>{};
    final modes = <String, int>{};
    for (final client in values) {
      final isEnabled = client['enabled'] != false;
      if (isEnabled) enabled++;
      final lastSeen = (client['last_seen_unix_seconds'] as num?)?.toInt() ?? 0;
      final isOnline =
          isEnabled &&
          (client['online'] == true ||
              (lastSeen > 0 && now - lastSeen.clamp(0, now) <= 120));
      if (isOnline) online++;
      final sync = client['config_sync_status']?.toString();
      if (sync == 'conflict' || sync == 'apply_failed') issues++;
      final platform = client['platform']?.toString().trim();
      final platformKey = platform == null || platform.isEmpty
          ? 'unknown'
          : platform;
      platforms.update(platformKey, (value) => value + 1, ifAbsent: () => 1);
      final mode = client['config_mode']?.toString() ?? 'local';
      modes.update(mode, (value) => value + 1, ifAbsent: () => 1);
    }
    return ClientInsightSnapshot(
      total: values.length,
      online: online,
      offline: math.max(0, enabled - online),
      disabled: math.max(0, values.length - enabled),
      configurationIssues: issues,
      platforms: platforms,
      configModes: modes,
    );
  }

  final int total;
  final int online;
  final int offline;
  final int disabled;
  final int configurationIssues;
  final Map<String, int> platforms;
  final Map<String, int> configModes;
}

class ClientInsightsPanel extends StatelessWidget {
  const ClientInsightsPanel({
    super.key,
    required this.clients,
    required this.chinese,
  });

  final List<dynamic> clients;
  final bool chinese;

  String t(String zh, String en) => chinese ? zh : en;

  @override
  Widget build(BuildContext context) {
    final snapshot = ClientInsightSnapshot.fromClients(clients);
    final status = <(String, int, Color)>[
      (t('在线', 'Online'), snapshot.online, const Color(0xFF22A06B)),
      (t('离线', 'Offline'), snapshot.offline, const Color(0xFFE09F3E)),
      (
        t('已停用', 'Disabled'),
        snapshot.disabled,
        Theme.of(context).colorScheme.outline,
      ),
    ];
    final platforms = snapshot.platforms.entries.toList()
      ..sort((left, right) => right.value.compareTo(left.value));
    final modes = snapshot.configModes.entries.toList()
      ..sort((left, right) => right.value.compareTo(left.value));
    return LayoutBuilder(
      builder: (context, constraints) {
        final cards = [
          _DistributionCard(
            title: t('客户端状态', 'Client status'),
            subtitle:
                '${snapshot.total} ${t('台客户端', 'clients')} · '
                '${snapshot.configurationIssues} ${t('个配置问题', 'configuration issues')}',
            values: status,
          ),
          _DistributionCard(
            title: t('平台与配置模式', 'Platform and configuration'),
            subtitle: t(
              '展示运行平台和服务端管理配置的分布',
              'Distribution of runtime platforms and managed configuration',
            ),
            values: [
              for (final entry in platforms.take(4))
                (entry.key, entry.value, Theme.of(context).colorScheme.primary),
              for (final entry in modes.take(3))
                (
                  _configModeLabel(entry.key),
                  entry.value,
                  Theme.of(context).colorScheme.tertiary,
                ),
            ],
          ),
        ];
        if (constraints.maxWidth < 760) {
          return Column(
            children: [cards.first, const SizedBox(height: 12), cards.last],
          );
        }
        return Row(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Expanded(child: cards.first),
            const SizedBox(width: 12),
            Expanded(child: cards.last),
          ],
        );
      },
    );
  }

  String _configModeLabel(String value) => switch (value) {
    'server_managed' => t('服务端管理', 'Server managed'),
    'report_only' => t('仅上报', 'Report only'),
    _ => t('本地配置', 'Local configuration'),
  };
}

class _DistributionCard extends StatelessWidget {
  const _DistributionCard({
    required this.title,
    required this.subtitle,
    required this.values,
  });

  final String title;
  final String subtitle;
  final List<(String, int, Color)> values;

  @override
  Widget build(BuildContext context) {
    final maxValue = values.fold<int>(
      1,
      (value, item) => math.max(value, item.$2),
    );
    return Card(
      child: Padding(
        padding: const EdgeInsets.all(16),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            Text(
              title,
              style: Theme.of(
                context,
              ).textTheme.titleMedium?.copyWith(fontWeight: FontWeight.w700),
            ),
            Text(
              subtitle,
              style: Theme.of(context).textTheme.bodySmall?.copyWith(
                color: Theme.of(context).colorScheme.onSurfaceVariant,
              ),
            ),
            const SizedBox(height: 14),
            for (final item in values) ...[
              Row(
                children: [
                  SizedBox(
                    width: 112,
                    child: Text(
                      item.$1,
                      maxLines: 1,
                      overflow: TextOverflow.ellipsis,
                      style: Theme.of(context).textTheme.labelMedium,
                    ),
                  ),
                  Expanded(
                    child: ClipRRect(
                      borderRadius: BorderRadius.circular(6),
                      child: LinearProgressIndicator(
                        minHeight: 11,
                        value: item.$2 / maxValue,
                        color: item.$3,
                        backgroundColor: item.$3.withValues(alpha: 0.12),
                      ),
                    ),
                  ),
                  SizedBox(
                    width: 38,
                    child: Text(
                      '${item.$2}',
                      textAlign: TextAlign.end,
                      style: Theme.of(context).textTheme.labelLarge,
                    ),
                  ),
                ],
              ),
              const SizedBox(height: 9),
            ],
          ],
        ),
      ),
    );
  }
}

String _formatRate(double value) {
  if (value >= 1024 * 1024 * 1024) {
    return '${(value / (1024 * 1024 * 1024)).toStringAsFixed(1)} GiB/s';
  }
  if (value >= 1024 * 1024) {
    return '${(value / (1024 * 1024)).toStringAsFixed(1)} MiB/s';
  }
  if (value >= 1024) return '${(value / 1024).toStringAsFixed(1)} KiB/s';
  return '${value.toStringAsFixed(value < 10 ? 1 : 0)} B/s';
}
