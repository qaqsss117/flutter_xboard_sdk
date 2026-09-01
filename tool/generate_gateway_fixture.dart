import 'dart:convert';
import 'dart:io';

import 'package:cryptography/cryptography.dart';
import 'package:flutter_xboard_sdk/src/core/security/encrypted_gateway_protocol.dart';

Future<void> main() async {
  const keyId = 0x10203040;
  final timestamp = DateTime.utc(2026, 8, 31, 12, 34, 56);
  final clientSeed = List<int>.generate(32, (index) => index + 1);
  final serverSeed = List<int>.generate(32, (index) => index + 33);
  final clientKeyPair = await X25519().newKeyPairFromSeed(clientSeed);
  final serverKeyPair = await X25519().newKeyPairFromSeed(serverSeed);
  final clientPrivateKey = await clientKeyPair.extractPrivateKeyBytes();
  final serverPrivateKey = await serverKeyPair.extractPrivateKeyBytes();
  final clientPublicKey = await clientKeyPair.extractPublicKey();
  final serverPublicKey = await serverKeyPair.extractPublicKey();
  final client = await EncryptedGatewayClient.create(
    keyRing: GatewayServerKeyRing(currentKeyId: keyId, currentPublicKey: serverPublicKey.bytes),
    clientKeyPair: clientKeyPair,
  );
  final server = EncryptedGatewayServer(serverKeyPairs: {keyId: serverKeyPair});
  final encrypted = await client.encryptRequest(
    GatewayRequestPayload(
      method: 'POST',
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
    requestId: List<int>.generate(16, (index) => 0x20 + index),
    nonce: List<int>.generate(24, (index) => 0x40 + index),
    fixedPaddingByte: 0,
  );
  final decrypted = await server.decryptRequest(encrypted.bytes, now: timestamp);
  final responseTimestamp = timestamp.add(const Duration(seconds: 1));
  final responseEnvelope = await server.encryptResponse(
    decrypted.context,
    GatewayResponsePayload(
      statusCode: 403,
      headers: const {'content-type': 'application/json'},
      body: utf8.encode('{"status":"fail","message":"denied"}'),
    ),
    timestamp: responseTimestamp,
    nonce: List<int>.generate(24, (index) => 0x60 + index),
    fixedPaddingByte: 1,
  );

  stdout.write(const JsonEncoder.withIndent('  ').convert({
    'version': 1,
    'key_id': keyId,
    'timestamp_ms': timestamp.millisecondsSinceEpoch,
    'client_private_key': _base64Url(clientPrivateKey),
    'client_public_key': _base64Url(clientPublicKey.bytes),
    'server_private_key': _base64Url(serverPrivateKey),
    'server_public_key': _base64Url(serverPublicKey.bytes),
    'request_id': _base64Url(encrypted.requestId),
    'request_envelope': _base64Url(encrypted.bytes),
    'response_timestamp_ms': responseTimestamp.millisecondsSinceEpoch,
    'response_envelope': _base64Url(responseEnvelope),
  }));
}

String _base64Url(List<int> bytes) => base64Url.encode(bytes).replaceAll('=', '');