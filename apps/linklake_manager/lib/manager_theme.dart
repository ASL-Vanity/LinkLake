import 'package:flutter/material.dart';

enum ManagerThemeStyle {
  lake,
  paper,
  graphite;

  static ManagerThemeStyle parse(Object? value) => switch (value) {
    'paper' => ManagerThemeStyle.paper,
    'graphite' => ManagerThemeStyle.graphite,
    _ => ManagerThemeStyle.lake,
  };

  String label(bool chinese) => switch (this) {
    ManagerThemeStyle.lake => chinese ? '湖光' : 'Lake glass',
    ManagerThemeStyle.paper => chinese ? '米纸' : 'Warm paper',
    ManagerThemeStyle.graphite => chinese ? '石墨' : 'Graphite',
  };
}

ThemeData buildManagerTheme(ManagerThemeStyle style, Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final seed = switch (style) {
    ManagerThemeStyle.lake =>
      dark ? const Color(0xFF38BDF8) : const Color(0xFF087EA4),
    ManagerThemeStyle.paper =>
      dark ? const Color(0xFFE5A45B) : const Color(0xFF9A5A24),
    ManagerThemeStyle.graphite =>
      dark ? const Color(0xFFA7F3D0) : const Color(0xFF176B52),
  };
  final scheme = ColorScheme.fromSeed(seedColor: seed, brightness: brightness);
  final radius = switch (style) {
    ManagerThemeStyle.lake => 22.0,
    ManagerThemeStyle.paper => 10.0,
    ManagerThemeStyle.graphite => 3.0,
  };
  final scaffold = switch ((style, dark)) {
    (ManagerThemeStyle.lake, false) => const Color(0xFFEAF4F8),
    (ManagerThemeStyle.lake, true) => const Color(0xFF06131D),
    (ManagerThemeStyle.paper, false) => const Color(0xFFF4EFE4),
    (ManagerThemeStyle.paper, true) => const Color(0xFF1D1914),
    (ManagerThemeStyle.graphite, false) => const Color(0xFFE8ECEB),
    (ManagerThemeStyle.graphite, true) => const Color(0xFF101413),
  };
  final surface = switch ((style, dark)) {
    (ManagerThemeStyle.lake, false) => const Color(0xFFF8FCFD),
    (ManagerThemeStyle.lake, true) => const Color(0xFF0C202C),
    (ManagerThemeStyle.paper, false) => const Color(0xFFFFFBF2),
    (ManagerThemeStyle.paper, true) => const Color(0xFF29231C),
    (ManagerThemeStyle.graphite, false) => const Color(0xFFF7F9F8),
    (ManagerThemeStyle.graphite, true) => const Color(0xFF19201E),
  };
  final border = switch (style) {
    ManagerThemeStyle.lake => BorderSide(
      color: scheme.outlineVariant.withValues(alpha: dark ? 0.45 : 0.6),
    ),
    ManagerThemeStyle.paper => BorderSide(
      color: scheme.outlineVariant.withValues(alpha: 0.75),
    ),
    ManagerThemeStyle.graphite => BorderSide(
      color: scheme.outline.withValues(alpha: 0.8),
    ),
  };

  return ThemeData(
    brightness: brightness,
    colorScheme: scheme.copyWith(surface: surface),
    useMaterial3: true,
    scaffoldBackgroundColor: scaffold,
    cardTheme: CardThemeData(
      elevation: style == ManagerThemeStyle.paper ? 1 : 0,
      margin: EdgeInsets.zero,
      color: surface,
      shadowColor: dark ? Colors.black54 : const Color(0x332C241B),
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(radius),
        side: border,
      ),
    ),
    dialogTheme: DialogThemeData(
      backgroundColor: surface,
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(radius + 2),
        side: border,
      ),
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: style != ManagerThemeStyle.graphite,
      fillColor: scheme.surfaceContainerHighest.withValues(
        alpha: style == ManagerThemeStyle.lake ? 0.45 : 0.75,
      ),
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(radius.clamp(4, 14)),
      ),
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: style == ManagerThemeStyle.lake
          ? surface.withValues(alpha: 0.94)
          : surface,
      indicatorShape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(
          style == ManagerThemeStyle.graphite ? 2 : 14,
        ),
      ),
    ),
    appBarTheme: AppBarTheme(
      elevation: style == ManagerThemeStyle.paper ? 1 : 0,
      scrolledUnderElevation: style == ManagerThemeStyle.paper ? 2 : 0,
      backgroundColor: style == ManagerThemeStyle.lake
          ? surface.withValues(alpha: 0.96)
          : surface,
      surfaceTintColor: Colors.transparent,
    ),
    dividerTheme: DividerThemeData(color: border.color, thickness: 1),
    pageTransitionsTheme: const PageTransitionsTheme(
      builders: {
        TargetPlatform.windows: FadeForwardsPageTransitionsBuilder(),
        TargetPlatform.linux: FadeForwardsPageTransitionsBuilder(),
        TargetPlatform.macOS: FadeForwardsPageTransitionsBuilder(),
      },
    ),
  );
}

class ThemeStylePreview extends StatelessWidget {
  const ThemeStylePreview({
    super.key,
    required this.style,
    required this.selected,
    required this.chinese,
    required this.onTap,
  });

  final ManagerThemeStyle style;
  final bool selected;
  final bool chinese;
  final VoidCallback onTap;

  @override
  Widget build(BuildContext context) {
    final previewTheme = buildManagerTheme(style, Theme.of(context).brightness);
    return Expanded(
      child: Semantics(
        button: true,
        selected: selected,
        label: style.label(chinese),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(14),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 180),
            padding: const EdgeInsets.all(10),
            decoration: BoxDecoration(
              color: previewTheme.scaffoldBackgroundColor,
              borderRadius: BorderRadius.circular(14),
              border: Border.all(
                width: selected ? 2 : 1,
                color: selected
                    ? Theme.of(context).colorScheme.primary
                    : Theme.of(context).colorScheme.outlineVariant,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  height: 32,
                  decoration: BoxDecoration(
                    color: previewTheme.colorScheme.surface,
                    borderRadius: BorderRadius.circular(
                      style == ManagerThemeStyle.graphite
                          ? 2
                          : style == ManagerThemeStyle.paper
                          ? 7
                          : 12,
                    ),
                    border: Border.all(
                      color: previewTheme.colorScheme.outlineVariant,
                    ),
                  ),
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: Container(
                      width: 36,
                      height: 8,
                      margin: const EdgeInsets.only(left: 8),
                      decoration: BoxDecoration(
                        color: previewTheme.colorScheme.primary,
                        borderRadius: BorderRadius.circular(8),
                      ),
                    ),
                  ),
                ),
                const SizedBox(height: 7),
                Text(
                  style.label(chinese),
                  maxLines: 1,
                  overflow: TextOverflow.ellipsis,
                  style: Theme.of(context).textTheme.labelMedium,
                ),
              ],
            ),
          ),
        ),
      ),
    );
  }
}
