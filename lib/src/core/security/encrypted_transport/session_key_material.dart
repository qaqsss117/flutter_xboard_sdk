part of 'encrypted_transport.dart';

const _hkdfSaltLabel = 'uuvpn-egw-v1-salt';
const _hkdfInfoLabel = 'uuvpn-encrypted-gateway/v1';

class _GatewayKeys {
  _GatewayKeys(this.request, this.response);

  final SecretKey request;
  final SecretKey response;
}

Future<_GatewayKeys> _deriveKeys({
  required KeyPair localKeyPair,
  required SimplePublicKey remotePublicKey,
  required int keyId,
  required List<int> clientPublicKey,
  required List<int> requestId,
}) async {
  final sharedSecret = await X25519().sharedSecretKey(
    keyPair: localKeyPair,
    remotePublicKey: remotePublicKey,
  );
  final salt = BytesBuilder(copy: false)
    ..add(utf8.encode(_hkdfSaltLabel))
    ..add(_uint32Bytes(keyId))
    ..add(requestId);
  final info = BytesBuilder(copy: false)
    ..add(utf8.encode(_hkdfInfoLabel))
    ..add(clientPublicKey);
  final derived = await Hkdf(hmac: Hmac.sha256(), outputLength: 64).deriveKey(
    secretKey: sharedSecret,
    nonce: salt.takeBytes(),
    info: info.takeBytes(),
  );
  return _GatewayKeys(
    SecretKey(derived.bytes.sublist(0, 32)),
    SecretKey(derived.bytes.sublist(32, 64)),
  );
}
