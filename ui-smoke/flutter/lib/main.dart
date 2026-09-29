import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:http/http.dart' as http;

const baseUrl = String.fromEnvironment('SHARED_AUTH_BASE_URL', defaultValue: 'http://127.0.0.1:8120');

void main() => runApp(const SharedAuthSmokeApp());

class SharedAuthSmokeApp extends StatelessWidget {
  const SharedAuthSmokeApp({super.key});
  @override
  Widget build(BuildContext context) => const MaterialApp(home: AuthScreen());
}

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});
  @override
  State<AuthScreen> createState() => _AuthScreenState();
}

class _AuthScreenState extends State<AuthScreen> {
  final email = TextEditingController();
  final password = TextEditingController();
  String result = '';

  Future<void> submit(String path) async {
    setState(() => result = 'working…');
    try {
      final response = await http.post(
        Uri.parse(baseUrl + path),
        headers: const {'accept': 'application/json', 'content-type': 'application/json'},
        body: jsonEncode({'email': email.text, 'password': password.text}),
      );
      setState(() => result = response.statusCode.toString() + ' ' + response.body);
    } catch (error) {
      setState(() => result = error.toString());
    }
  }

  @override
  void dispose() { email.dispose(); password.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) => Scaffold(
    appBar: AppBar(title: const Text('Shared Auth smoke')),
    body: Padding(
      padding: const EdgeInsets.all(24),
      child: Column(children: [
        TextField(controller: email, decoration: const InputDecoration(labelText: 'Email')),
        TextField(controller: password, obscureText: true, decoration: const InputDecoration(labelText: 'Password')),
        Wrap(spacing: 12, children: [
          ElevatedButton(onPressed: () => submit('/auth/register'), child: const Text('Sign up')),
          ElevatedButton(onPressed: () => submit('/auth/login'), child: const Text('Log in')),
        ]),
        SelectableText(result),
      ]),
    ),
  );
}
