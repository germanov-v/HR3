import 'dart:async';
import 'package:flutter/material.dart';
import 'package:uni_links/uni_links.dart';
import 'package:url_launcher/url_launcher.dart';
import 'package:http/http.dart' as http;

void main() {
  runApp(const MyApp());
}

class MyApp extends StatefulWidget {
  const MyApp({super.key});

  @override
  State<MyApp> createState() => _MyAppState();
}

class _MyAppState extends State<MyApp> {
  String? _accessToken;
  StreamSubscription? _sub;

  @override
  void initState() {
    super.initState();
    _initUniLinks();
  }

  Future<void> _initUniLinks() async {
    // На случай, если приложение уже открыто с deeplink
    try {
      final initialLink = await getInitialLink();
      if (initialLink != null) _handleLink(initialLink);
    } catch (_) {}

    // Слушаем входящие ссылки
    _sub = linkStream.listen((String? link) {
      if (link != null) _handleLink(link);
    }, onError: (err) {
      debugPrint('Link error: $err');
    });
  }

  void _handleLink(String link) {
    final uri = Uri.parse(link);
    final token = uri.queryParameters['access_token'];
    if (token != null) {
      setState(() => _accessToken = token);
      debugPrint("Access token: $token");
    }
  }

  @override
  void dispose() {
    _sub?.cancel();
    super.dispose();
  }

  Future<void> _signInWithYandex() async {
    final returnUrl = Uri.encodeComponent("myapp://auth/callback");
    final authUrl = Uri.parse(
      "https://localhost:7105/oauth/yandex/start?returnUrl=$returnUrl",
    );
    if (!await launchUrl(authUrl, mode: LaunchMode.externalApplication)) {
      throw 'Could not launch $authUrl';
    }
  }

  Future<void> _callProtectedApi() async {
    if (_accessToken == null) return;
    final resp = await http.get(
      Uri.parse("https://auth.localtest.me:7105/me"),
      headers: {"Authorization": "Bearer $_accessToken"},
    );
    debugPrint("Protected API response: ${resp.body}");
  }

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      home: Scaffold(
        appBar: AppBar(title: const Text("Flutter Auth via Yandex")),
        body: Center(
          child: _accessToken == null
              ? ElevatedButton(
            onPressed: _signInWithYandex,
            child: const Text("Войти через Яндекс"),
          )
              : Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [
              Text("Token: $_accessToken"),
              const SizedBox(height: 20),
              ElevatedButton(
                onPressed: _callProtectedApi,
                child: const Text("Вызвать /me"),
              )
            ],
          ),
        ),
      ),
    );
  }
}
