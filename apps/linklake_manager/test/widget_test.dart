import 'package:flutter_test/flutter_test.dart';
import 'package:linklake_manager/main.dart';

void main() {
  testWidgets('shows the LinkLake login screen', (tester) async {
    await tester.pumpWidget(const LinkLakeManagerApp());

    expect(find.text('LinkLake'), findsOneWidget);
    expect(find.text('登录'), findsOneWidget);
  });
}
