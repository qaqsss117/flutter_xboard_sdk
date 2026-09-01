part of 'encrypted_transport.dart';

class GatewayRequestContext {
  GatewayRequestContext._({
    required this.keyId,
    required this.clientPublicKey,
    required this.requestId,
    required SecretKey responseKey,
  }) : _responseKey = responseKey;

  final int keyId;
  final Uint8List clientPublicKey;
  final Uint8List requestId;
  final SecretKey _responseKey;
}

class GatewayDecryptedRequest {
  GatewayDecryptedRequest(this.payload, this.context);

  final GatewayRequestPayload payload;
  final GatewayRequestContext context;
}

class EncryptedGatewayServer {
  EncryptedGatewayServer({
    required this.serverKeyPairs,
    this.paddingPolicy = const GatewayPaddingPolicy(),
    this.allowedClockSkew = const Duration(minutes: 2),
  });

  final Map<int, KeyPair> serverKeyPairs;
  final GatewayPaddingPolicy paddingPolicy;
  final Duration allowedClockSkew;

  Future<GatewayDecryptedRequest> decryptRequest(
    List<int> envelope, {
    DateTime? now,
  }) async {
    final decoded = _decodeEnvelope(envelope, paddingPolicy.maxEnvelopeSize);
    _validateHeader(
      decoded.header,
      expectedDirection: GatewayEnvelopeDirection.request,
      now: now ?? DateTime.now().toUtc(),
      allowedClockSkew: allowedClockSkew,
    );
    final keyPair = serverKeyPairs[decoded.header.keyId];
    if (keyPair == null) {
      throw GatewayProtocolException('Unknown server key id');
    }
    final clientPublicKey = SimplePublicKey(
      decoded.header.clientPublicKey,
      type: KeyPairType.x25519,
    );
    final keys = await _deriveKeys(
      localKeyPair: keyPair,
      remotePublicKey: clientPublicKey,
      keyId: decoded.header.keyId,
      clientPublicKey: decoded.header.clientPublicKey,
      requestId: decoded.header.requestId,
    );
    final json = await _openJson(decoded, keys.request);
    return GatewayDecryptedRequest(
      GatewayRequestPayload.fromJson(json),
      GatewayRequestContext._(
        keyId: decoded.header.keyId,
        clientPublicKey: decoded.header.clientPublicKey,
        requestId: decoded.header.requestId,
        responseKey: keys.response,
      ),
    );
  }

  Future<Uint8List> encryptResponse(
    GatewayRequestContext context,
    GatewayResponsePayload payload, {
    DateTime? timestamp,
    List<int>? nonce,
    int? fixedPaddingByte,
  }) async {
    final actualNonce = Uint8List.fromList(nonce ?? _randomBytes(24));
    _expectLength(actualNonce, 24, 'nonce');
    return _sealJson(
      jsonWithoutPadding: payload.toJson(''),
      direction: GatewayEnvelopeDirection.response,
      keyId: context.keyId,
      clientPublicKey: context.clientPublicKey,
      nonce: actualNonce,
      timestamp: timestamp ?? DateTime.now().toUtc(),
      requestId: context.requestId,
      secretKey: context._responseKey,
      paddingPolicy: paddingPolicy,
      fixedPaddingByte: fixedPaddingByte,
    );
  }
}
