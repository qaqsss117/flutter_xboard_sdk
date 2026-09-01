part of 'encrypted_transport.dart';

class GatewayEncryptedRequest {
  GatewayEncryptedRequest(this.bytes, this.requestId);

  final Uint8List bytes;
  final Uint8List requestId;
}

class EncryptedGatewayClient {
  EncryptedGatewayClient._({
    required this.keyRing,
    required SimplePublicKey serverPublicKey,
    required KeyPair clientKeyPair,
    required Uint8List clientPublicKey,
    required this.paddingPolicy,
    required this.allowedClockSkew,
  })  : _serverPublicKey = serverPublicKey,
        _clientKeyPair = clientKeyPair,
        _clientPublicKey = clientPublicKey;

  final GatewayServerKeyRing keyRing;
  final SimplePublicKey _serverPublicKey;
  final KeyPair _clientKeyPair;
  final Uint8List _clientPublicKey;
  final GatewayPaddingPolicy paddingPolicy;
  final Duration allowedClockSkew;

  /// 当前用于加密新请求的服务端 key id（始终来自 [keyRing.currentKeyId]）。
  int get keyId => keyRing.currentKeyId;

  static Future<EncryptedGatewayClient> create({
    required GatewayServerKeyRing keyRing,
    KeyPair? clientKeyPair,
    GatewayPaddingPolicy paddingPolicy = const GatewayPaddingPolicy(),
    Duration allowedClockSkew = const Duration(minutes: 2),
  }) async {
    final x25519 = X25519();
    final pair = clientKeyPair ?? await x25519.newKeyPair();
    final publicKey = await pair.extractPublicKey();
    if (publicKey is! SimplePublicKey || publicKey.type != KeyPairType.x25519) {
      throw ArgumentError('Expected an X25519 client key pair');
    }
    return EncryptedGatewayClient._(
      keyRing: keyRing,
      serverPublicKey: SimplePublicKey(keyRing.currentPublicKey, type: KeyPairType.x25519),
      clientKeyPair: pair,
      clientPublicKey: Uint8List.fromList(publicKey.bytes),
      paddingPolicy: paddingPolicy,
      allowedClockSkew: allowedClockSkew,
    );
  }

  List<int> get clientPublicKey => List.unmodifiable(_clientPublicKey);

  Future<GatewayEncryptedRequest> encryptRequest(
    GatewayRequestPayload payload, {
    DateTime? timestamp,
    List<int>? requestId,
    List<int>? nonce,
    int? fixedPaddingByte,
  }) async {
    final actualRequestId = Uint8List.fromList(requestId ?? _randomBytes(16));
    final actualNonce = Uint8List.fromList(nonce ?? _randomBytes(24));
    _expectLength(actualRequestId, 16, 'request id');
    _expectLength(actualNonce, 24, 'nonce');
    final keys = await _deriveKeys(
      localKeyPair: _clientKeyPair,
      remotePublicKey: _serverPublicKey,
      keyId: keyRing.currentKeyId,
      clientPublicKey: _clientPublicKey,
      requestId: actualRequestId,
    );
    final bytes = await _sealJson(
      jsonWithoutPadding: payload.toJson(''),
      direction: GatewayEnvelopeDirection.request,
      keyId: keyRing.currentKeyId,
      clientPublicKey: _clientPublicKey,
      nonce: actualNonce,
      timestamp: timestamp ?? DateTime.now().toUtc(),
      requestId: actualRequestId,
      secretKey: keys.request,
      paddingPolicy: paddingPolicy,
      fixedPaddingByte: fixedPaddingByte,
    );
    return GatewayEncryptedRequest(bytes, actualRequestId);
  }

  Future<GatewayResponsePayload> decryptResponse(
    List<int> envelope, {
    required List<int> expectedRequestId,
    DateTime? now,
  }) async {
    final decoded = _decodeEnvelope(envelope, paddingPolicy.maxEnvelopeSize);
    _validateHeader(
      decoded.header,
      expectedDirection: GatewayEnvelopeDirection.response,
      expectedKeyId: keyRing.currentKeyId,
      expectedClientPublicKey: _clientPublicKey,
      expectedRequestId: expectedRequestId,
      now: now ?? DateTime.now().toUtc(),
      allowedClockSkew: allowedClockSkew,
    );
    final keys = await _deriveKeys(
      localKeyPair: _clientKeyPair,
      remotePublicKey: _serverPublicKey,
      keyId: keyRing.currentKeyId,
      clientPublicKey: _clientPublicKey,
      requestId: decoded.header.requestId,
    );
    final json = await _openJson(decoded, keys.response);
    return GatewayResponsePayload.fromJson(json);
  }
}
