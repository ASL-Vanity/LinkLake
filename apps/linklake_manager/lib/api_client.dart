import 'dart:convert';
import 'dart:io';

/// LinkLake 管理 API 的桌面端会话客户端。
class LinkLakeApiClient {
  LinkLakeApiClient(String baseUrl)
      : baseUri = Uri.parse(baseUrl.replaceAll(RegExp(r'/+$'), ''));

  final Uri baseUri;
  final HttpClient _client = HttpClient()
    ..connectionTimeout = const Duration(seconds: 10)
    ..idleTimeout = const Duration(seconds: 30);
  String? _cookie;

  bool get authenticated => _cookie != null;

  Future<Map<String, dynamic>> login(String username, String password) async {
    final response = await _request(
      'POST',
      '/api/v1/auth/login',
      body: {'username': username, 'password': password},
      includeCookie: false,
    );
    final cookie = response.headers.value(HttpHeaders.setCookieHeader);
    if (cookie == null || cookie.isEmpty) {
      throw const LinkLakeApiException(500, 'server did not return a session');
    }
    _cookie = cookie.split(';').first;
    return _decodeObject(response.body);
  }

  Future<void> changePassword(String password) async {
    await _request(
      'POST',
      '/api/v1/auth/change-password',
      body: {'new_password': password},
    );
  }

  Future<void> logout() async {
    try {
      await _request('POST', '/api/v1/auth/logout');
    } finally {
      _cookie = null;
    }
  }

  Future<Map<String, dynamic>> getObject(String path) async {
    final response = await _request('GET', path);
    return _decodeObject(response.body);
  }

  Future<List<dynamic>> getList(String path) async {
    final response = await _request('GET', path);
    final decoded = response.body.isEmpty ? <dynamic>[] : jsonDecode(response.body);
    if (decoded is! List) {
      throw const LinkLakeApiException(500, 'server returned an invalid list');
    }
    return decoded;
  }

  Future<Map<String, dynamic>> postObject(
    String path,
    Map<String, dynamic> body,
  ) async {
    final response = await _request('POST', path, body: body);
    if (response.body.isEmpty) return <String, dynamic>{};
    return _decodeObject(response.body);
  }

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
      try {
        final decoded = jsonDecode(text);
        if (decoded is Map && decoded['error'] != null) {
          message = decoded['error'].toString();
        }
      } catch (_) {}
      throw LinkLakeApiException(response.statusCode, message);
    }
    return _ApiResponse(response.headers, text);
  }

  Map<String, dynamic> _decodeObject(String value) {
    final decoded = value.isEmpty ? <String, dynamic>{} : jsonDecode(value);
    if (decoded is! Map<String, dynamic>) {
      throw const LinkLakeApiException(500, 'server returned an invalid object');
    }
    return decoded;
  }

  void close() => _client.close(force: true);
}

class LinkLakeApiException implements Exception {
  const LinkLakeApiException(this.statusCode, this.message);

  final int statusCode;
  final String message;

  @override
  String toString() => 'HTTP $statusCode: $message';
}

class _ApiResponse {
  const _ApiResponse(this.headers, this.body);

  final HttpHeaders headers;
  final String body;
}
