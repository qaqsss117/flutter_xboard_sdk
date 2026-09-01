import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_xboard_sdk/src/core/http/http_config.dart';

void main() {
  final publicKey = base64Url.encode(List<int>.generate(32, (index) => index)).replaceAll('=', '');

  test('accepts a complete encrypted gateway configuration', () {
    final config = EncryptedGatewayConfig(
      path: '/abcdefghijklmnopqrstuvwxyz012345',
      keyId: 7,
      serverPublicKey: publicKey,
    );

    expect(config.serverPublicKeyBytes, hasLength(32));
  });

  test('rejects an invalid gateway path', () {
    expect(
      () => EncryptedGatewayConfig(
        path: '/api/v1/gateway',
        keyId: 7,
        serverPublicKey: publicKey,
      ),
      throwsArgumentError,
    );
  });

  test('rejects a public key with the wrong length', () {
    expect(
      () => EncryptedGatewayConfig(
        path: '/abcdefghijklmnopqrstuvwxyz012345',
        keyId: 7,
        serverPublicKey: base64Url.encode([1, 2, 3]).replaceAll('=', ''),
      ),
      throwsArgumentError,
    );
  });

  test('builds a key ring carrying both current and previous keys', () {
    final previousPublicKey =
        base64Url.encode(List<int>.generate(32, (index) => index + 1)).replaceAll('=', '');
    final config = EncryptedGatewayConfig(
      path: '/abcdefghijklmnopqrstuvwxyz012345',
      keyId: 7,
      serverPublicKey: publicKey,
      previousKeyId: 6,
      previousServerPublicKey: previousPublicKey,
    );

    expect(config.keyRing.currentKeyId, 7);
    expect(config.keyRing.previousKeyId, 6);
    expect(config.keyRing.previousPublicKey, hasLength(32));
  });

  test('rejects a previous key id without a matching previous public key', () {
    expect(
      () => EncryptedGatewayConfig(
        path: '/abcdefghijklmnopqrstuvwxyz012345',
        keyId: 7,
        serverPublicKey: publicKey,
        previousKeyId: 6,
      ),
      throwsArgumentError,
    );
  });
}