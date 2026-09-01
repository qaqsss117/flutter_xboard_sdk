part of 'encrypted_transport.dart';

class GatewayQueryParameter {
  const GatewayQueryParameter(this.name, this.value);

  final String name;
  final String value;
}

class GatewayRequestPayload {
  GatewayRequestPayload({
    required String method,
    required this.path,
    this.query = const [],
    this.headers = const {},
    List<int> body = const [],
    this.contentType,
  })  : method = method.toUpperCase(),
        body = Uint8List.fromList(body) {
    if (!RegExp(r'^[A-Z]+$').hasMatch(this.method)) {
      throw ArgumentError.value(method, 'method', 'Invalid HTTP method');
    }
    if (!path.startsWith('/') ||
        path.contains('://') ||
        path.contains('?') ||
        path.contains('#')) {
      throw ArgumentError.value(path, 'path', 'Expected an absolute-path reference');
    }
  }

  final String method;
  final String path;
  final List<GatewayQueryParameter> query;
  final Map<String, String> headers;
  final Uint8List body;
  final String? contentType;

  Map<String, Object?> toJson(String padding) => {
        'm': method,
        'p': path,
        'q': query.map((item) => [item.name, item.value]).toList(),
        'h': headers,
        'b': _base64UrlEncode(body),
        'ct': contentType,
        'z': padding,
      };

  static GatewayRequestPayload fromJson(Map<String, Object?> json) {
    _expectKeys(json, const {'m', 'p', 'q', 'h', 'b', 'ct', 'z'});
    _expectPadding(json['z']);

    final rawQuery = json['q'];
    if (rawQuery is! List) {
      throw GatewayProtocolException('Request query must be a list');
    }
    final query = rawQuery.map((item) {
      if (item is! List || item.length != 2 || item[0] is! String || item[1] is! String) {
        throw GatewayProtocolException('Invalid request query entry');
      }
      return GatewayQueryParameter(item[0] as String, item[1] as String);
    }).toList(growable: false);

    return GatewayRequestPayload(
      method: _expectString(json['m'], 'm'),
      path: _expectString(json['p'], 'p'),
      query: query,
      headers: _expectStringMap(json['h'], 'h'),
      body: _base64UrlDecode(_expectString(json['b'], 'b')),
      contentType: _expectNullableString(json['ct'], 'ct'),
    );
  }
}

class GatewayResponsePayload {
  GatewayResponsePayload({
    required this.statusCode,
    this.headers = const {},
    List<int> body = const [],
  }) : body = Uint8List.fromList(body) {
    if (statusCode < 100 || statusCode > 599) {
      throw ArgumentError.value(statusCode, 'statusCode', 'Invalid HTTP status');
    }
  }

  final int statusCode;
  final Map<String, String> headers;
  final Uint8List body;

  Map<String, Object?> toJson(String padding) => {
        's': statusCode,
        'h': headers,
        'b': _base64UrlEncode(body),
        'z': padding,
      };

  static GatewayResponsePayload fromJson(Map<String, Object?> json) {
    _expectKeys(json, const {'s', 'h', 'b', 'z'});
    _expectPadding(json['z']);
    final statusCode = json['s'];
    if (statusCode is! int) {
      throw GatewayProtocolException('Response status must be an integer');
    }
    return GatewayResponsePayload(
      statusCode: statusCode,
      headers: _expectStringMap(json['h'], 'h'),
      body: _base64UrlDecode(_expectString(json['b'], 'b')),
    );
  }
}

Map<String, String> _expectStringMap(Object? value, String field) {
  if (value is! Map) {
    throw GatewayProtocolException('$field must be an object');
  }
  final result = <String, String>{};
  for (final entry in value.entries) {
    if (entry.key is! String || entry.value is! String) {
      throw GatewayProtocolException('$field must contain only string values');
    }
    result[entry.key as String] = entry.value as String;
  }
  return result;
}

String _expectString(Object? value, String field) {
  if (value is! String) {
    throw GatewayProtocolException('$field must be a string');
  }
  return value;
}

String? _expectNullableString(Object? value, String field) {
  if (value != null && value is! String) {
    throw GatewayProtocolException('$field must be null or a string');
  }
  return value as String?;
}

void _expectPadding(Object? value) {
  final padding = _expectString(value, 'z');
  if (!RegExp(r'^[A-Za-z0-9_-]*$').hasMatch(padding)) {
    throw GatewayProtocolException('Invalid padding');
  }
}

void _expectKeys(Map<String, Object?> json, Set<String> expected) {
  if (json.length != expected.length || !json.keys.every(expected.contains)) {
    throw GatewayProtocolException('Encrypted payload has unexpected fields');
  }
}

String _base64UrlEncode(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');

Uint8List _base64UrlDecode(String value) {
  if (!RegExp(r'^[A-Za-z0-9_-]*$').hasMatch(value) || value.length % 4 == 1) {
    throw GatewayProtocolException('Invalid base64url value');
  }
  final padded = value.padRight(value.length + ((4 - value.length % 4) % 4), '=');
  try {
    return Uint8List.fromList(base64Url.decode(padded));
  } on FormatException {
    throw GatewayProtocolException('Invalid base64url value');
  }
}
