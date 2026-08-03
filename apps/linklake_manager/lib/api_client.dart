import 'dart:convert';
import 'dart:io';

abstract interface class LinkLakeApi {
  Uri get baseUri;
  bool get authenticated;

  Future<Map<String, dynamic>> login(
    String username,
    String password, {
    String? totpCode,
  });

  Future<void> changePassword(String password);
  Future<void> logout();
  Future<Map<String, dynamic>> getObject(String path);
  Future<List<dynamic>> getList(String path);
  Future<Map<String, dynamic>> postObject(
    String path,
    Map<String, dynamic> body,
  );
  Future<Map<String, dynamic>> putObject(
    String path,
    Map<String, dynamic> body,
  );
  Future<void> post(String path, [Map<String, dynamic>? body]);
  Future<String> getText(String path);
  Future<void> delete(String path);
  void close();
}

/// LinkLake 管理 API 的桌面端会话客户端。
class LinkLakeApiClient implements LinkLakeApi {
  LinkLakeApiClient(String baseUrl)
    : baseUri = Uri.parse(baseUrl.replaceAll(RegExp(r'/+$'), ''));

  @override
  final Uri baseUri;
  final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 10)
    ..idleTimeout = const Duration(seconds: 30);
  String? _cookie;

  @override
  bool get authenticated => _cookie != null;

  @override
  Future<Map<String, dynamic>> login(
    String username,
    String password, {
    String? totpCode,
  }) async {
    final response = await _request(
      'POST',
      '/api/v1/auth/login',
      body: {
        'username': username,
        'password': password,
        'totp_code': totpCode?.trim().isEmpty == true ? null : totpCode,
      },
      includeCookie: false,
    );
    final cookie = response.headers.value(HttpHeaders.setCookieHeader);
    if (cookie == null || cookie.isEmpty) {
      throw const LinkLakeApiException(
        500,
        'server did not return a session',
        code: 'missing_session',
      );
    }
    _cookie = cookie.split(';').first;
    return _decodeObject(response.body);
  }

  @override
  Future<void> changePassword(String password) async {
    await _request(
      'POST',
      '/api/v1/auth/change-password',
      body: {'new_password': password},
    );
  }

  @override
  Future<void> logout() async {
    try {
      await _request('POST', '/api/v1/auth/logout');
    } finally {
      _cookie = null;
    }
  }

  @override
  Future<Map<String, dynamic>> getObject(String path) async {
    final response = await _request('GET', path);
    return _decodeObject(response.body);
  }

  @override
  Future<List<dynamic>> getList(String path) async {
    final response = await _request('GET', path);
    final decoded = response.body.isEmpty
        ? <dynamic>[]
        : jsonDecode(response.body);
    if (decoded is! List) {
      throw const LinkLakeApiException(
        500,
        'server returned an invalid list',
        code: 'invalid_response',
      );
    }
    return decoded;
  }

  @override
  Future<Map<String, dynamic>> postObject(
    String path,
    Map<String, dynamic> body,
  ) async {
    final response = await _request('POST', path, body: body);
    if (response.body.isEmpty) return <String, dynamic>{};
    return _decodeObject(response.body);
  }

  @override
  Future<Map<String, dynamic>> putObject(
    String path,
    Map<String, dynamic> body,
  ) async {
    final response = await _request('PUT', path, body: body);
    if (response.body.isEmpty) return <String, dynamic>{};
    return _decodeObject(response.body);
  }

  @override
  Future<void> post(String path, [Map<String, dynamic>? body]) async {
    await _request('POST', path, body: body);
  }

  @override
  Future<String> getText(String path) async {
    final response = await _request('GET', path);
    return response.body;
  }

  @override
  Future<void> delete(String path) async {
    await _request('DELETE', path);
  }

  Future<_ApiResponse> _request(
    String method,
    String path, {
    Map<String, dynamic>? body,
    bool includeCookie = true,
  }) async {
    final request = await _client.openUrl(method, baseUri.resolve(path));
    request.headers.set(HttpHeaders.acceptHeader, 'application/json');
    if (!const ['GET', 'HEAD', 'OPTIONS'].contains(method.toUpperCase())) {
      request.headers.set('X-LinkLake-CSRF', '1');
    }
    if (includeCookie && _cookie != null) {
      request.headers.set(HttpHeaders.cookieHeader, _cookie!);
    }
    if (body != null) {
      request.headers.contentType = ContentType.json;
      request.write(jsonEncode(body));
    }
    final response = await request.close().timeout(const Duration(seconds: 20));
    final text = await utf8.decoder.bind(response).join();
    if (response.statusCode < 200 || response.statusCode >= 300) {
      var message = text;
      String? code;
      try {
        final decoded = jsonDecode(text);
        if (decoded is Map && decoded['error'] != null) {
          message = decoded['error'].toString();
          code = decoded['code']?.toString();
        }
      } catch (_) {}
      throw LinkLakeApiException(response.statusCode, message, code: code);
    }
    return _ApiResponse(response.headers, text);
  }

  Map<String, dynamic> _decodeObject(String value) {
    final decoded = value.isEmpty ? <String, dynamic>{} : jsonDecode(value);
    if (decoded is! Map<String, dynamic>) {
      throw const LinkLakeApiException(
        500,
        'server returned an invalid object',
        code: 'invalid_response',
      );
    }
    return decoded;
  }

  @override
  void close() => _client.close(force: true);
}

class LinkLakeApiException implements Exception {
  const LinkLakeApiException(this.statusCode, this.message, {this.code});

  final int statusCode;
  final String message;
  final String? code;

  @override
  String toString() => 'HTTP $statusCode: $message';
}

class _ApiResponse {
  const _ApiResponse(this.headers, this.body);

  final HttpHeaders headers;
  final String body;
}
