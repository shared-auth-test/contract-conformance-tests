import 'package:flutter_test/flutter_test.dart';
import 'package:shared_auth_ui_smoke_flutter/main.dart';

void main() {
  testWidgets('renders signup and login controls', (tester) async {
    await tester.pumpWidget(const SharedAuthSmokeApp());
    expect(find.text('Shared Auth smoke'), findsOneWidget);
    expect(find.text('Email'), findsOneWidget);
    expect(find.text('Password'), findsOneWidget);
    expect(find.text('Sign up'), findsOneWidget);
    expect(find.text('Log in'), findsOneWidget);
  });
}
