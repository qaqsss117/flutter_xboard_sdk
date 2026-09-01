import 'dart:async';
import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';
import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_xboard_sdk/src/core/auth/token_manager.dart';
import 'package:flutter_xboard_sdk/src/core/exceptions/xboard_exceptions.dart';
import 'package:flutter_xboard_sdk/src/core/http/http_config.dart';
import 'package:flutter_xboard_sdk/src/core/http/http_service.dart';
import 'package:flutter_xboard_sdk/src/core/security/encrypted_gateway_protocol.dart';

const _gatewayPath = '/abcdefghijklmnopqrstuvwxyz012345';

void main() {
  const keyId = 27;
  late KeyPair serverKeyPair;
  late EncryptedGatewayServer gatewayServer;
  late TokenManager tokenManager;
  late HttpService service;

  setUp(() async {
    serverKeyPair = await X25519().newKeyPairFromSeed(
      List<int>.generate(32, (index) => index + 70),
    );
    gatewayServer = EncryptedGatewayServer(serverKeyPairs: {keyId: serverKeyPair});
    final serverPublicKey = await serverKeyPair.extractPublicKey() as SimplePublicKey;
    tokenManager = TokenManager.memory();
    await tokenManager.saveToken('Bearer secret-token');
    service = await HttpService.create(
      'https://client.example',
      tokenManager: tokenManager,
      httpConfig: HttpConfig(
        userAgent: 'Sentinel/Test',
        encryptedGateway: EncryptedGatewayConfig(
          path: _gatewayPath,
          keyId: keyId,
          serverPublicKey: base64Url.encode(serverPublicKey.bytes).replaceAll('=', ''),
        ),
      ),
    );
  });

  tearDown(() {
    service.dispose();
    tokenManager.dispose();
  });

  test('sends only an encrypted POST and restores a successful response', () async {
    service.dio.httpClientAdapter = _GatewayAdapter(gatewayServer, (request) {
      expect(request.payload.method, 'GET');
      expect(request.payload.path, '/api/v1/user/info');
      expect(
        request.payload.query.map((entry) => '${entry.name}=${entry.value}'),
        ['scope=profile', 'scope=subscription'],
      );
      expect(request.payload.headers['authorization'], 'Bearer secret-token');
      return GatewayResponsePayload(
        statusCode: 200,
        headers: const {'content-type': 'application/json'},
        body: utf8.encode('{"status":"success","data":{"email":"user@example.com"}}'),
      );
    });

    final response = await service.getRequest(
      '/api/v1/user/info?scope=profile&scope=subscription',
    );

    expect(response['success'], isTrue);
    expect((response['data'] as Map<String, dynamic>)['email'], 'user@example.com');
  });

  test('restores an encrypted business error', () async {
    service.dio.httpClientAdapter = _GatewayAdapter(gatewayServer, (request) {
      return GatewayResponsePayload(
        statusCode: 403,
        headers: const {'content-type': 'application/json'},
        body: utf8.encode('{"message":"session expired"}'),
      );
    });

    await expectLater(
      service.getRequest('/api/v1/user/info'),
      throwsA(
        isA<ApiException>()
            .having((error) => error.code, 'code', 403)
            .having((error) => error.message, 'message', 'session expired'),
      ),
    );
  });

  test('restores an upstream 500 error', () async {
    service.dio.httpClientAdapter = _GatewayAdapter(gatewayServer, (request) {
      return GatewayResponsePayload(
        statusCode: 500,
        headers: const {'content-type': 'application/json'},
        body: utf8.encode('{"message":"internal error"}'),
      );
    });

    await expectLater(
      service.getRequest('/api/v1/user/info'),
      throwsA(
        isA<NetworkException>().having((error) => error.message, 'message', 'internal error'),
      ),
    );
  });

  test('round trips a response near the configured envelope size limit', () async {
    // 默认 maxEnvelopeSize 为 4MiB，构造一个接近但仍在限内的响应体
    // \u6ce8\u610f\u54cd\u5e94\u4f53\u5728\u4fe1\u5c01\u5185\u4f1a\u88ab base64url \u7f16\u7801\uff08\u81ea\u65e0\u586b\u5145\u65f6\u7ea6\u81a8\u80c0 4/3\uff09\uff0c
    // \u9009\u53d6\u80fd\u8ba9\u6700\u7ec8\u4fe1\u5c01\u63a5\u8fd1\u4f46\u4ecd\u5b89\u5168\u4f4e\u4e8e\u9ed8\u8ba4 4MiB \u4e0a\u9650\u7684\u539f\u59cb\u957f\u5ea6\u3002
    const dataLength = 2500000;
    final largeBody = utf8.encode('{"success":true,"data":"${'a' * dataLength}"}');

    service.dio.httpClientAdapter = _GatewayAdapter(gatewayServer, (request) {
      return GatewayResponsePayload(
        statusCode: 200,
        headers: const {'content-type': 'application/json'},
        body: largeBody,
      );
    });

    final response = await service.getRequest('/api/v1/user/info');
    expect((response['data'] as String).length, dataLength);
  });

  test('cancelling a request does not leave an encrypted request in flight', () async {
    service.dio.httpClientAdapter = _GatewayAdapter(
      gatewayServer,
      (request) => GatewayResponsePayload(statusCode: 200, body: utf8.encode('{}')),
      delay: const Duration(seconds: 5),
    );

    final cancelToken = CancelToken();
    final future = service.dio.get('/api/v1/user/info', cancelToken: cancelToken);
    cancelToken.cancel('client cancelled');

    await expectLater(
      future,
      throwsA(isA<DioException>().having((e) => e.type, 'type', DioExceptionType.cancel)),
    );
  });

  test('does not emit a plaintext request when the gateway client fails to initialize', () async {
    await expectLater(
      HttpService.create(
        'https://client.example',
        httpConfig: const HttpConfig(userAgent: 'Sentinel/Test'),
        requireEncryptedGateway: true,
      ),
      throwsA(isA<ConfigException>()),
    );
  });

  test('returns encrypted subscription bytes and allowed response headers', () async {
    service.dio.httpClientAdapter = _GatewayAdapter(gatewayServer, (request) {
      expect(request.payload.path, '/api/v1/client/subscribe');
      expect(request.payload.query.single.name, 'token');
      expect(request.payload.query.single.value, 'subscription-secret');
      return GatewayResponsePayload(
        statusCode: 200,
        headers: const {
          'content-type': 'text/yaml',
          'subscription-userinfo': 'upload=1; download=2; total=3',
        },
        body: utf8.encode('proxies: []\n'),
      );
    });

    final response = await service.getEncryptedRawRequest(
      '/api/v1/client/subscribe?token=subscription-secret',
    );

    expect(utf8.decode(response.body), 'proxies: []\n');
    expect(response.headers['subscription-userinfo'], 'upload=1; download=2; total=3');
  });
}

class _GatewayAdapter implements HttpClientAdapter {
  _GatewayAdapter(this.server, this.handle, {this.delay});

  final EncryptedGatewayServer server;
  final GatewayResponsePayload Function(GatewayDecryptedRequest request) handle;
  final Duration? delay;

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    expect(options.method, 'POST');
    expect(options.uri.toString(), 'https://client.example$_gatewayPath');
    expect(options.headers['authorization'], isNull);
    expect(options.headers['content-type'], 'application/octet-stream');
    if (delay != null) {
      final cancelled = Completer<void>();
      cancelFuture?.then((_) => cancelled.complete());
      await Future.any([Future.delayed(delay!), cancelled.future]);
      if (cancelled.isCompleted) {
        throw DioException(requestOptions: options, type: DioExceptionType.cancel);
      }
    }
    final requestBytes = BytesBuilder(copy: false);
    await for (final chunk in requestStream ?? const Stream<Uint8List>.empty()) {
      requestBytes.add(chunk);
    }
    final request = await server.decryptRequest(requestBytes.takeBytes());
    final encryptedResponse = await server.encryptResponse(
      request.context,
      handle(request),
    );
    return ResponseBody.fromBytes(
      encryptedResponse,
      200,
      headers: const {
        'content-type': ['application/octet-stream'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}