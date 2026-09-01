part of 'encrypted_transport.dart';

const _paddingAlphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';

class GatewayPaddingPolicy {
  const GatewayPaddingPolicy({
    this.buckets = const [1024, 4096, 16384, 65536],
    this.largeBucketSize = 65536,
    this.maxEnvelopeSize = 4 * 1024 * 1024,
  });

  final List<int> buckets;
  final int largeBucketSize;
  final int maxEnvelopeSize;

  int envelopeSizeFor(int minimumSize) {
    for (final bucket in buckets) {
      if (minimumSize <= bucket) {
        return bucket;
      }
    }
    final result = ((minimumSize + largeBucketSize - 1) ~/ largeBucketSize) * largeBucketSize;
    if (result > maxEnvelopeSize) {
      throw GatewayProtocolException('Envelope exceeds configured maximum');
    }
    return result;
  }
}

String _randomPadding(int length, int? fixedByte) {
  if (fixedByte != null && (fixedByte < 0 || fixedByte >= _paddingAlphabet.length)) {
    throw ArgumentError.value(fixedByte, 'fixedPaddingByte');
  }
  final random = Random.secure();
  return String.fromCharCodes(List.generate(
    length,
    (_) => _paddingAlphabet.codeUnitAt(fixedByte ?? random.nextInt(_paddingAlphabet.length)),
  ));
}
