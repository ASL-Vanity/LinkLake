import 'package:flutter/material.dart';

enum ManagerThemeStyle {
  aurora,
  minimal,
  paper,
  neon,
  highContrast;

  static ManagerThemeStyle parse(Object? value) => switch (value) {
    'aurora' || 'lake' => ManagerThemeStyle.aurora,
    'minimal' => ManagerThemeStyle.minimal,
    'paper' => ManagerThemeStyle.paper,
    'neon' => ManagerThemeStyle.neon,
    'highContrast' ||
    'high_contrast' ||
    'graphite' => ManagerThemeStyle.highContrast,
    _ => ManagerThemeStyle.aurora,
  };

  String label(bool chinese) => switch (this) {
    ManagerThemeStyle.aurora => chinese ? '极光玻璃' : 'Aurora glass',
    ManagerThemeStyle.minimal => chinese ? '极简平面' : 'Minimal',
    ManagerThemeStyle.paper => chinese ? '温暖纸张' : 'Warm paper',
    ManagerThemeStyle.neon => chinese ? '霓虹终端' : 'Neon terminal',
    ManagerThemeStyle.highContrast => chinese ? '高对比' : 'High contrast',
  };
}

class ManagerMaterialTheme extends ThemeExtension<ManagerMaterialTheme> {
  const ManagerMaterialTheme({
    required this.style,
    required this.backgroundColors,
    required this.cardOpacity,
    required this.borderWidth,
  });

  final ManagerThemeStyle style;
  final List<Color> backgroundColors;
  final double cardOpacity;
  final double borderWidth;

  @override
  ManagerMaterialTheme copyWith({
    ManagerThemeStyle? style,
    List<Color>? backgroundColors,
    double? cardOpacity,
    double? borderWidth,
  }) => ManagerMaterialTheme(
    style: style ?? this.style,
    backgroundColors: backgroundColors ?? this.backgroundColors,
    cardOpacity: cardOpacity ?? this.cardOpacity,
    borderWidth: borderWidth ?? this.borderWidth,
  );

  @override
  ManagerMaterialTheme lerp(covariant ManagerMaterialTheme? other, double t) {
    if (other == null) return this;
    final length = backgroundColors.length < other.backgroundColors.length
        ? backgroundColors.length
        : other.backgroundColors.length;
    return ManagerMaterialTheme(
      style: t < 0.5 ? style : other.style,
      backgroundColors: [
        for (var index = 0; index < length; index++)
          Color.lerp(
                backgroundColors[index],
                other.backgroundColors[index],
                t,
              ) ??
              backgroundColors[index],
      ],
      cardOpacity: cardOpacity + (other.cardOpacity - cardOpacity) * t,
      borderWidth: borderWidth + (other.borderWidth - borderWidth) * t,
    );
  }
}

ThemeData buildManagerTheme(ManagerThemeStyle style, Brightness brightness) {
  final dark = brightness == Brightness.dark;
  final spec = _ThemeSpec.forStyle(style, dark: dark);
  final baseScheme = style == ManagerThemeStyle.highContrast
      ? _highContrastScheme(brightness)
      : ColorScheme.fromSeed(seedColor: spec.seed, brightness: brightness);
  final scheme = baseScheme.copyWith(
    surface: spec.surface,
    outline: style == ManagerThemeStyle.highContrast
        ? (dark ? Colors.white : Colors.black)
        : baseScheme.outline,
    outlineVariant: style == ManagerThemeStyle.highContrast
        ? (dark ? Colors.white : Colors.black)
        : baseScheme.outlineVariant,
  );
  final border = BorderSide(
    color: style == ManagerThemeStyle.highContrast
        ? scheme.outline
        : style == ManagerThemeStyle.neon
        ? scheme.primary.withValues(alpha: 0.9)
        : scheme.outlineVariant.withValues(alpha: spec.borderAlpha),
    width: spec.borderWidth,
  );
  final shape = RoundedRectangleBorder(
    borderRadius: BorderRadius.circular(spec.radius),
    side: border,
  );
  final textTheme = ThemeData(brightness: brightness).textTheme.apply(
    bodyColor: scheme.onSurface,
    displayColor: scheme.onSurface,
  );

  return ThemeData(
    brightness: brightness,
    colorScheme: scheme,
    useMaterial3: true,
    scaffoldBackgroundColor: spec.scaffold,
    visualDensity: style == ManagerThemeStyle.minimal
        ? VisualDensity.compact
        : VisualDensity.standard,
    textTheme: style == ManagerThemeStyle.highContrast
        ? textTheme.copyWith(
            titleLarge: textTheme.titleLarge?.copyWith(
              fontWeight: FontWeight.w800,
            ),
            titleMedium: textTheme.titleMedium?.copyWith(
              fontWeight: FontWeight.w700,
            ),
            labelLarge: textTheme.labelLarge?.copyWith(
              fontWeight: FontWeight.w700,
            ),
          )
        : textTheme,
    cardTheme: CardThemeData(
      elevation: spec.elevation,
      margin: EdgeInsets.zero,
      color: spec.surface.withValues(alpha: spec.cardOpacity),
      shadowColor: spec.shadow,
      shape: shape,
    ),
    dialogTheme: DialogThemeData(
      elevation: spec.elevation + 2,
      backgroundColor: spec.surface,
      shadowColor: spec.shadow,
      shape: shape,
    ),
    inputDecorationTheme: InputDecorationTheme(
      filled: spec.filledInputs,
      fillColor: spec.inputFill,
      border: OutlineInputBorder(
        borderRadius: BorderRadius.circular(spec.inputRadius),
        borderSide: border,
      ),
      enabledBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(spec.inputRadius),
        borderSide: border,
      ),
      focusedBorder: OutlineInputBorder(
        borderRadius: BorderRadius.circular(spec.inputRadius),
        borderSide: BorderSide(
          color: scheme.primary,
          width: style == ManagerThemeStyle.highContrast ? 3 : 2,
        ),
      ),
    ),
    chipTheme: ChipThemeData(
      shape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(spec.chipRadius),
        side: border,
      ),
      backgroundColor: spec.surface,
      selectedColor: scheme.primaryContainer,
      side: border,
    ),
    navigationRailTheme: NavigationRailThemeData(
      backgroundColor: spec.navigation,
      indicatorColor: style == ManagerThemeStyle.neon
          ? scheme.primary.withValues(alpha: 0.22)
          : scheme.secondaryContainer,
      indicatorShape: RoundedRectangleBorder(
        borderRadius: BorderRadius.circular(spec.navigationRadius),
        side: style == ManagerThemeStyle.highContrast
            ? border
            : BorderSide.none,
      ),
    ),
    appBarTheme: AppBarTheme(
      elevation: spec.appBarElevation,
      scrolledUnderElevation: spec.appBarElevation + 1,
      backgroundColor: spec.navigation,
      foregroundColor: scheme.onSurface,
      surfaceTintColor: Colors.transparent,
      shadowColor: spec.shadow,
    ),
    dividerTheme: DividerThemeData(
      color: border.color,
      thickness: style == ManagerThemeStyle.highContrast ? 2 : 1,
    ),
    tooltipTheme: TooltipThemeData(
      decoration: BoxDecoration(
        color: style == ManagerThemeStyle.highContrast
            ? scheme.onSurface
            : scheme.inverseSurface,
        borderRadius: BorderRadius.circular(spec.inputRadius),
        border: style == ManagerThemeStyle.highContrast
            ? Border.all(color: scheme.surface, width: 2)
            : null,
      ),
      textStyle: TextStyle(
        color: style == ManagerThemeStyle.highContrast
            ? scheme.surface
            : scheme.onInverseSurface,
      ),
    ),
    pageTransitionsTheme: PageTransitionsTheme(
      builders: {
        TargetPlatform.windows:
            style == ManagerThemeStyle.minimal ||
                style == ManagerThemeStyle.highContrast
            ? const _InstantPageTransitionsBuilder()
            : const FadeForwardsPageTransitionsBuilder(),
        TargetPlatform.linux:
            style == ManagerThemeStyle.minimal ||
                style == ManagerThemeStyle.highContrast
            ? const _InstantPageTransitionsBuilder()
            : const FadeForwardsPageTransitionsBuilder(),
        TargetPlatform.macOS:
            style == ManagerThemeStyle.minimal ||
                style == ManagerThemeStyle.highContrast
            ? const _InstantPageTransitionsBuilder()
            : const FadeForwardsPageTransitionsBuilder(),
      },
    ),
    extensions: [
      ManagerMaterialTheme(
        style: style,
        backgroundColors: spec.backgroundColors,
        cardOpacity: spec.cardOpacity,
        borderWidth: spec.borderWidth,
      ),
    ],
  );
}

class ThemeStylePreview extends StatelessWidget {
  const ThemeStylePreview({
    super.key,
    required this.style,
    required this.selected,
    required this.chinese,
    required this.onTap,
    this.width = 142,
  });

  final ManagerThemeStyle style;
  final bool selected;
  final bool chinese;
  final VoidCallback onTap;
  final double width;

  @override
  Widget build(BuildContext context) {
    final previewTheme = buildManagerTheme(style, Theme.of(context).brightness);
    final material = previewTheme.extension<ManagerMaterialTheme>()!;
    final cardShape = previewTheme.cardTheme.shape as RoundedRectangleBorder;
    return SizedBox(
      width: width,
      child: Semantics(
        button: true,
        selected: selected,
        label: style.label(chinese),
        child: InkWell(
          onTap: onTap,
          borderRadius: BorderRadius.circular(12),
          child: AnimatedContainer(
            duration: const Duration(milliseconds: 180),
            padding: const EdgeInsets.all(9),
            decoration: BoxDecoration(
              gradient: LinearGradient(colors: material.backgroundColors),
              borderRadius: BorderRadius.circular(12),
              border: Border.all(
                width: selected ? 2.5 : material.borderWidth,
                color: selected
                    ? Theme.of(context).colorScheme.primary
                    : previewTheme.colorScheme.outline,
              ),
            ),
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                Container(
                  height: 34,
                  decoration: ShapeDecoration(
                    color: previewTheme.cardTheme.color,
                    shape: cardShape,
                    shadows: previewTheme.cardTheme.elevation == 0
                        ? const []
                        : [
                            BoxShadow(
                              color:
                                  previewTheme.cardTheme.shadowColor ??
                                  Colors.black26,
                              blurRadius: 8,
                              offset: const Offset(0, 3),
                            ),
                          ],
                  ),
                  child: Align(
                    alignment: Alignment.centerLeft,
                    child: Container(
                      width: 38,
                      height: style == ManagerThemeStyle.highContrast ? 10 : 7,
                      margin: const EdgeInsets.only(left: 8),
                      color: style == ManagerThemeStyle.highContrast
                          ? previewTheme.colorScheme.primary
                          : null,
                      decoration: style == ManagerThemeStyle.highContrast
                          ? null
                          : BoxDecoration(
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

class _ThemeSpec {
  const _ThemeSpec({
    required this.seed,
    required this.scaffold,
    required this.surface,
    required this.navigation,
    required this.inputFill,
    required this.backgroundColors,
    required this.shadow,
    required this.radius,
    required this.inputRadius,
    required this.chipRadius,
    required this.navigationRadius,
    required this.borderWidth,
    required this.borderAlpha,
    required this.cardOpacity,
    required this.elevation,
    required this.appBarElevation,
    required this.filledInputs,
  });

  factory _ThemeSpec.forStyle(ManagerThemeStyle style, {required bool dark}) =>
      switch ((style, dark)) {
        (ManagerThemeStyle.aurora, false) => const _ThemeSpec(
          seed: Color(0xFF0D7EA6),
          scaffold: Color(0xFFE7F3F8),
          surface: Color(0xFFF8FCFD),
          navigation: Color(0xF2F8FCFD),
          inputFill: Color(0xA6DDEEF4),
          backgroundColors: [
            Color(0xFFD9F0FF),
            Color(0xFFE1FFF4),
            Color(0xFFF6F9FF),
          ],
          shadow: Color(0x33216A86),
          radius: 24,
          inputRadius: 14,
          chipRadius: 14,
          navigationRadius: 16,
          borderWidth: 1,
          borderAlpha: 0.55,
          cardOpacity: 0.9,
          elevation: 0,
          appBarElevation: 0,
          filledInputs: true,
        ),
        (ManagerThemeStyle.aurora, true) => const _ThemeSpec(
          seed: Color(0xFF38BDF8),
          scaffold: Color(0xFF06131D),
          surface: Color(0xFF0B202C),
          navigation: Color(0xF20B202C),
          inputFill: Color(0xB2193745),
          backgroundColors: [
            Color(0xFF071A2B),
            Color(0xFF082A29),
            Color(0xFF111827),
          ],
          shadow: Color(0x6614B8A6),
          radius: 24,
          inputRadius: 14,
          chipRadius: 14,
          navigationRadius: 16,
          borderWidth: 1,
          borderAlpha: 0.45,
          cardOpacity: 0.88,
          elevation: 0,
          appBarElevation: 0,
          filledInputs: true,
        ),
        (ManagerThemeStyle.minimal, false) => const _ThemeSpec(
          seed: Color(0xFF355E58),
          scaffold: Color(0xFFF3F5F4),
          surface: Color(0xFFFFFFFF),
          navigation: Color(0xFFFFFFFF),
          inputFill: Color(0xFFFFFFFF),
          backgroundColors: [Color(0xFFF3F5F4), Color(0xFFFFFFFF)],
          shadow: Color(0x00000000),
          radius: 4,
          inputRadius: 4,
          chipRadius: 4,
          navigationRadius: 4,
          borderWidth: 0.7,
          borderAlpha: 0.7,
          cardOpacity: 1,
          elevation: 0,
          appBarElevation: 0,
          filledInputs: false,
        ),
        (ManagerThemeStyle.minimal, true) => const _ThemeSpec(
          seed: Color(0xFF9DCFC4),
          scaffold: Color(0xFF151817),
          surface: Color(0xFF1C211F),
          navigation: Color(0xFF1C211F),
          inputFill: Color(0xFF1C211F),
          backgroundColors: [Color(0xFF151817), Color(0xFF1C211F)],
          shadow: Color(0x00000000),
          radius: 4,
          inputRadius: 4,
          chipRadius: 4,
          navigationRadius: 4,
          borderWidth: 0.7,
          borderAlpha: 0.75,
          cardOpacity: 1,
          elevation: 0,
          appBarElevation: 0,
          filledInputs: false,
        ),
        (ManagerThemeStyle.paper, false) => const _ThemeSpec(
          seed: Color(0xFF9A5A24),
          scaffold: Color(0xFFF1EADB),
          surface: Color(0xFFFFFBF2),
          navigation: Color(0xFFFFFBF2),
          inputFill: Color(0xFFF6EEDC),
          backgroundColors: [
            Color(0xFFF1E8D5),
            Color(0xFFF8F0DF),
            Color(0xFFFFFCF5),
          ],
          shadow: Color(0x4D6B4A2D),
          radius: 9,
          inputRadius: 7,
          chipRadius: 7,
          navigationRadius: 8,
          borderWidth: 1,
          borderAlpha: 0.8,
          cardOpacity: 1,
          elevation: 2,
          appBarElevation: 1,
          filledInputs: true,
        ),
        (ManagerThemeStyle.paper, true) => const _ThemeSpec(
          seed: Color(0xFFE7AE6A),
          scaffold: Color(0xFF1D1914),
          surface: Color(0xFF2B241C),
          navigation: Color(0xFF2B241C),
          inputFill: Color(0xFF352C22),
          backgroundColors: [
            Color(0xFF1D1914),
            Color(0xFF292117),
            Color(0xFF30261C),
          ],
          shadow: Color(0x99000000),
          radius: 9,
          inputRadius: 7,
          chipRadius: 7,
          navigationRadius: 8,
          borderWidth: 1,
          borderAlpha: 0.75,
          cardOpacity: 1,
          elevation: 2,
          appBarElevation: 1,
          filledInputs: true,
        ),
        (ManagerThemeStyle.neon, false) => const _ThemeSpec(
          seed: Color(0xFF6D28D9),
          scaffold: Color(0xFFEDE9FE),
          surface: Color(0xFFF9F7FF),
          navigation: Color(0xFFF5F3FF),
          inputFill: Color(0xFFEDE9FE),
          backgroundColors: [
            Color(0xFFE0E7FF),
            Color(0xFFF5E8FF),
            Color(0xFFE4FFF8),
          ],
          shadow: Color(0x666D28D9),
          radius: 16,
          inputRadius: 11,
          chipRadius: 20,
          navigationRadius: 20,
          borderWidth: 1.4,
          borderAlpha: 0.9,
          cardOpacity: 0.98,
          elevation: 3,
          appBarElevation: 2,
          filledInputs: true,
        ),
        (ManagerThemeStyle.neon, true) => const _ThemeSpec(
          seed: Color(0xFFB7FF3C),
          scaffold: Color(0xFF070611),
          surface: Color(0xFF121020),
          navigation: Color(0xFF0D0B19),
          inputFill: Color(0xFF1C1730),
          backgroundColors: [
            Color(0xFF080616),
            Color(0xFF17072A),
            Color(0xFF03221F),
          ],
          shadow: Color(0x998B5CF6),
          radius: 16,
          inputRadius: 11,
          chipRadius: 20,
          navigationRadius: 20,
          borderWidth: 1.4,
          borderAlpha: 0.95,
          cardOpacity: 0.96,
          elevation: 3,
          appBarElevation: 2,
          filledInputs: true,
        ),
        (ManagerThemeStyle.highContrast, false) => const _ThemeSpec(
          seed: Colors.black,
          scaffold: Colors.white,
          surface: Colors.white,
          navigation: Colors.white,
          inputFill: Colors.white,
          backgroundColors: [Colors.white, Color(0xFFE8E8E8)],
          shadow: Colors.black,
          radius: 0,
          inputRadius: 0,
          chipRadius: 0,
          navigationRadius: 0,
          borderWidth: 2.4,
          borderAlpha: 1,
          cardOpacity: 1,
          elevation: 0,
          appBarElevation: 0,
          filledInputs: false,
        ),
        (ManagerThemeStyle.highContrast, true) => const _ThemeSpec(
          seed: Color(0xFFFFFF00),
          scaffold: Colors.black,
          surface: Colors.black,
          navigation: Colors.black,
          inputFill: Colors.black,
          backgroundColors: [Colors.black, Color(0xFF191919)],
          shadow: Colors.white,
          radius: 0,
          inputRadius: 0,
          chipRadius: 0,
          navigationRadius: 0,
          borderWidth: 2.4,
          borderAlpha: 1,
          cardOpacity: 1,
          elevation: 0,
          appBarElevation: 0,
          filledInputs: false,
        ),
      };

  final Color seed;
  final Color scaffold;
  final Color surface;
  final Color navigation;
  final Color inputFill;
  final List<Color> backgroundColors;
  final Color shadow;
  final double radius;
  final double inputRadius;
  final double chipRadius;
  final double navigationRadius;
  final double borderWidth;
  final double borderAlpha;
  final double cardOpacity;
  final double elevation;
  final double appBarElevation;
  final bool filledInputs;
}

ColorScheme _highContrastScheme(Brightness brightness) {
  final dark = brightness == Brightness.dark;
  return ColorScheme(
    brightness: brightness,
    primary: dark ? const Color(0xFFFFFF00) : Colors.black,
    onPrimary: dark ? Colors.black : Colors.white,
    secondary: dark ? const Color(0xFF00FFFF) : const Color(0xFF003D5B),
    onSecondary: dark ? Colors.black : Colors.white,
    error: dark ? const Color(0xFFFF6B6B) : const Color(0xFF8B0000),
    onError: dark ? Colors.black : Colors.white,
    surface: dark ? Colors.black : Colors.white,
    onSurface: dark ? Colors.white : Colors.black,
  );
}

class _InstantPageTransitionsBuilder extends PageTransitionsBuilder {
  const _InstantPageTransitionsBuilder();

  @override
  Widget buildTransitions<T>(
    PageRoute<T> route,
    BuildContext context,
    Animation<double> animation,
    Animation<double> secondaryAnimation,
    Widget child,
  ) => child;
}
