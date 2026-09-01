part of 'encrypted_transport.dart';

enum GatewayEnvelopeDirection {
  request(1),
  response(2);

  const GatewayEnvelopeDirection(this.value);

  final int value;
}

const _magic = [0x55, 0x55, 0x56, 0x31];
const _version = 1;
const _headerLength = 94;
const _macLength = 16;

class _GatewayHeader {
  _GatewayHeader({
    required this.direction,
    required this.keyId,
    required this.clientPublicKey,
    required this.nonce,
    required this.timestampMilliseconds,
    required this.requestId,
    required this.ciphertextLength,
  });

  final GatewayEnvelopeDirection direction;
  final int keyId;
  final Uint8List clientPublicKey;
  final Uint8List nonce;
  final int timestampMilliseconds;
  final Uint8List requestId;
  final int ciphertextLength;
}

class _DecodedEnvelope {
  _DecodedEnvelope(this.header, this.aad, this.ciphertext, this.mac);

  final _GatewayHeader header;
  final Uint8List aad;
  final Uint8List ciphertext;
  final Uint8List mac;
}

Future<Uint8List> _sealJson({
  required Map<String, Object?> jsonWithoutPadding,
  required GatewayEnvelopeDirection direction,
  required int keyId,
  required List<int> clientPublicKey,
  required List<int> nonce,
  required DateTime timestamp,
  required List<int> requestId,
  required SecretKey secretKey,
  required GatewayPaddingPolicy paddingPolicy,
  int? fixedPaddingByte,
}) async {
  final unpadded = utf8.encode(jsonEncode(jsonWithoutPadding));
  final envelopeSize = paddingPolicy.envelopeSizeFor(_headerLength + _macLength + unpadded.length);
  final paddingLength = envelopeSize - _headerLength - _macLength - unpadded.length;
  jsonWithoutPadding['z'] = _randomPadding(paddingLength, fixedPaddingByte);
  final plaintext = utf8.encode(jsonEncode(jsonWithoutPadding));
  if (plaintext.length != unpadded.length + paddingLength) {
    throw StateError('Padding did not produce the requested envelope size');
  }
  final header = _encodeHeader(
    direction: direction,
    keyId: keyId,
    clientPublicKey: clientPublicKey,
    nonce: nonce,
    timestampMilliseconds: timestamp.toUtc().millisecondsSinceEpoch,
    requestId: requestId,
    ciphertextLength: plaintext.length + _macLength,
  );
  final secretBox = await Xchacha20.poly1305Aead().encrypt(
    plaintext,
    secretKey: secretKey,
    nonce: nonce,
    aad: header,
  );
  return Uint8List.fromList([
    ...header,
    ...secretBox.cipherText,
    ...secretBox.mac.bytes,
  ]);
}

Future<Map<String, Object?>> _openJson(_DecodedEnvelope decoded, SecretKey secretKey) async {
  try {
    final plaintext = await Xchacha20.poly1305Aead().decrypt(
      SecretBox(
        decoded.ciphertext,
        nonce: decoded.header.nonce,
        mac: Mac(decoded.mac),
      ),
      secretKey: secretKey,
      aad: decoded.aad,
    );
    final value = jsonDecode(utf8.decode(plaintext, allowMalformed: false));
    if (value is! Map<String, dynamic>) {
      throw GatewayProtocolException('Encrypted payload must be a JSON object');
    }
    return value.cast<String, Object?>();
  } on SecretBoxAuthenticationError {
    throw GatewayProtocolException('Envelope authentication failed');
  } on FormatException {
    throw GatewayProtocolException('Encrypted payload is not valid UTF-8 JSON');
  }
}

Uint8List _encodeHeader({
  required GatewayEnvelopeDirection direction,
  required int keyId,
  required List<int> clientPublicKey,
  required List<int> nonce,
  required int timestampMilliseconds,
  required List<int> requestId,
  required int ciphertextLength,
}) {
  _validateKeyId(keyId);
  _expectLength(clientPublicKey, 32, 'client public key');
  _expectLength(nonce, 24, 'nonce');
  _expectLength(requestId, 16, 'request id');
  final bytes = Uint8List(_headerLength);
  bytes.setRange(0, 4, _magic);
  bytes[4] = _version;
  bytes[5] = direction.value;
  final data = ByteData.sublistView(bytes);
  data.setUint32(6, keyId, Endian.big);
  bytes.setRange(10, 42, clientPublicKey);
  bytes.setRange(42, 66, nonce);
  data.setInt64(66, timestampMilliseconds, Endian.big);
  bytes.setRange(74, 90, requestId);
  data.setUint32(90, ciphertextLength, Endian.big);
  return bytes;
}

_DecodedEnvelope _decodeEnvelope(List<int> envelope, int maxEnvelopeSize) {
  if (envelope.length < _headerLength + _macLength || envelope.length > maxEnvelopeSize) {
    throw GatewayProtocolException('Invalid envelope length');
  }
  final bytes = Uint8List.fromList(envelope);
  if (!_bytesEqual(bytes.sublist(0, 4), _magic) || bytes[4] != _version) {
    throw GatewayProtocolException('Unsupported gateway protocol');
  }
  final direction = switch (bytes[5]) {
    1 => GatewayEnvelopeDirection.request,
    2 => GatewayEnvelopeDirection.response,
    _ => throw GatewayProtocolException('Invalid envelope direction'),
  };
  final data = ByteData.sublistView(bytes);
  final ciphertextLength = data.getUint32(90, Endian.big);
  if (ciphertextLength < _macLength || _headerLength + ciphertextLength != bytes.length) {
    throw GatewayProtocolException('Ciphertext length mismatch');
  }
  final ciphertextEnd = bytes.length - _macLength;
  return _DecodedEnvelope(
    _GatewayHeader(
      direction: direction,
      keyId: data.getUint32(6, Endian.big),
      clientPublicKey: Uint8List.fromList(bytes.sublist(10, 42)),
      nonce: Uint8List.fromList(bytes.sublist(42, 66)),
      timestampMilliseconds: data.getInt64(66, Endian.big),
      requestId: Uint8List.fromList(bytes.sublist(74, 90)),
      ciphertextLength: ciphertextLength,
    ),
    Uint8List.fromList(bytes.sublist(0, _headerLength)),
    Uint8List.fromList(bytes.sublist(_headerLength, ciphertextEnd)),
    Uint8List.fromList(bytes.sublist(ciphertextEnd)),
  );
}

void _validateHeader(
  _GatewayHeader header, {
  required GatewayEnvelopeDirection expectedDirection,
  int? expectedKeyId,
  List<int>? expectedClientPublicKey,
  List<int>? expectedRequestId,
  required DateTime now,
  required Duration allowedClockSkew,
}) {
  if (header.direction != expectedDirection) {
    throw GatewayProtocolException('Unexpected envelope direction');
  }
  if (expectedKeyId != null && header.keyId != expectedKeyId) {
    throw GatewayProtocolException('Unexpected server key id');
  }
  if (expectedClientPublicKey != null &&
      !_bytesEqual(header.clientPublicKey, expectedClientPublicKey)) {
    throw GatewayProtocolException('Unexpected client public key');
  }
  if (expectedRequestId != null && !_bytesEqual(header.requestId, expectedRequestId)) {
    throw GatewayProtocolException('Unexpected request id');
  }
  final difference = now.toUtc().millisecondsSinceEpoch - header.timestampMilliseconds;
  if (difference.abs() > allowedClockSkew.inMilliseconds) {
    throw GatewayProtocolException('Envelope timestamp is outside the allowed window');
  }
}

Uint8List _randomBytes(int length) {
  final random = Random.secure();
  return Uint8List.fromList(List.generate(length, (_) => random.nextInt(256)));
}

Uint8List _uint32Bytes(int value) {
  final result = Uint8List(4);
  ByteData.sublistView(result).setUint32(0, value, Endian.big);
  return result;
}

void _validateKeyId(int keyId) {
  if (keyId < 0 || keyId > 0xffffffff) {
    throw ArgumentError.value(keyId, 'keyId', 'Expected an unsigned 32-bit integer');
  }
}

void _expectLength(List<int> value, int expected, String name) {
  if (value.length != expected) {
    throw ArgumentError.value(value.length, name, 'Expected $expected bytes');
  }
}

bool _bytesEqual(List<int> left, List<int> right) {
  if (left.length != right.length) {
    return false;
  }
  var difference = 0;
  for (var index = 0; index < left.length; index++) {
    difference |= left[index] ^ right[index];
  }
  return difference == 0;
}
