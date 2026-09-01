import 'dart:convert';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_xboard_sdk/src/core/security/encrypted_gateway_protocol.dart';

void main() {
  const keyId = 0x10203040;
  final timestamp = DateTime.utc(2026, 8, 31, 12, 34, 56);
  final clientSeed = List<int>.generate(32, (index) => index + 1);
  final serverSeed = List<int>.generate(32, (index) => index + 33);
  final requestId = List<int>.generate(16, (index) => 0x20 + index);
  final requestNonce = List<int>.generate(24, (index) => 0x40 + index);
  final responseNonce = List<int>.generate(24, (index) => 0x60 + index);

  late KeyPair clientKeyPair;
  late KeyPair serverKeyPair;
  late EncryptedGatewayClient client;
  late EncryptedGatewayServer server;

  setUp(() async {
    clientKeyPair = await X25519().newKeyPairFromSeed(clientSeed);
    serverKeyPair = await X25519().newKeyPairFromSeed(serverSeed);
    final serverPublicKey = await serverKeyPair.extractPublicKey() as SimplePublicKey;
    client = await EncryptedGatewayClient.create(
      keyRing: GatewayServerKeyRing(currentKeyId: keyId, currentPublicKey: serverPublicKey.bytes),
      clientKeyPair: clientKeyPair,
    );
    server = EncryptedGatewayServer(serverKeyPairs: {keyId: serverKeyPair});
  });

  test('round trips a padded request and response', () async {
    final encrypted = await client.encryptRequest(
      GatewayRequestPayload(
        method: 'post',
        path: '/api/v1/passport/auth/login',
        query: const [
          GatewayQueryParameter('source', 'windows'),
          GatewayQueryParameter('source', 'direct'),
        ],
        headers: const {
          'accept-language': 'zh-CN',
          'content-type': 'application/json',
        },
        body: utf8.encode('{"email":"user@example.com"}'),
        contentType: 'application/json',
      ),
      timestamp: timestamp,
      requestId: requestId,
      nonce: requestNonce,
      fixedPaddingByte: 0,
    );

    expect(encrypted.bytes, hasLength(1024));
    final decrypted = await server.decryptRequest(encrypted.bytes, now: timestamp);
    expect(decrypted.payload.method, 'POST');
    expect(decrypted.payload.path, '/api/v1/passport/auth/login');
    expect(decrypted.payload.query.map((item) => item.value), ['windows', 'direct']);
    expect(utf8.decode(decrypted.payload.body), '{"email":"user@example.com"}');

    final encryptedResponse = await server.encryptResponse(
      decrypted.context,
      GatewayResponsePayload(
        statusCode: 422,
        headers: const {'content-type': 'application/json'},
        body: utf8.encode('{"message":"invalid"}'),
      ),
      timestamp: timestamp,
      nonce: responseNonce,
      fixedPaddingByte: 1,
    );
    expect(encryptedResponse, hasLength(1024));

    final response = await client.decryptResponse(
      encryptedResponse,
      expectedRequestId: encrypted.requestId,
      now: timestamp,
    );
    expect(response.statusCode, 422);
    expect(response.headers['content-type'], 'application/json');
    expect(utf8.decode(response.body), '{"message":"invalid"}');
  });

  test('rejects authenticated header tampering', () async {
    final encrypted = await client.encryptRequest(
      GatewayRequestPayload(method: 'GET', path: '/api/v1/user/info'),
      timestamp: timestamp,
      requestId: requestId,
      nonce: requestNonce,
      fixedPaddingByte: 0,
    );
    encrypted.bytes[42] ^= 1;

    await expectLater(
      server.decryptRequest(encrypted.bytes, now: timestamp),
      throwsA(isA<GatewayProtocolException>()),
    );
  });

  test('rejects ciphertext tampering', () async {
    final encrypted = await client.encryptRequest(
      GatewayRequestPayload(method: 'GET', path: '/api/v1/user/info'),
      timestamp: timestamp,
      requestId: requestId,
      nonce: requestNonce,
      fixedPaddingByte: 0,
    );
    encrypted.bytes[100] ^= 1;

    await expectLater(
      server.decryptRequest(encrypted.bytes, now: timestamp),
      throwsA(isA<GatewayProtocolException>()),
    );
  });

  test('rejects stale envelopes before decryption', () async {
    final encrypted = await client.encryptRequest(
      GatewayRequestPayload(method: 'GET', path: '/api/v1/user/info'),
      timestamp: timestamp,
      requestId: requestId,
      nonce: requestNonce,
      fixedPaddingByte: 0,
    );

    await expectLater(
      server.decryptRequest(
        encrypted.bytes,
        now: timestamp.add(const Duration(minutes: 3)),
      ),
      throwsA(
        isA<GatewayProtocolException>().having(
          (error) => error.message,
          'message',
          contains('timestamp'),
        ),
      ),
    );
  });
}