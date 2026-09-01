part of 'encrypted_transport.dart';

/// 客户端侧服务端公钥集合：加密新请求始终使用 [currentKeyId]/[currentPublicKey]。
/// [previousKeyId]/[previousPublicKey] 仅作配置灰度切换预留——协议对所有解密/协议错误
/// 返回统一的桶化响应（不区分"未知 key id"与其他错误，避免成为可探测的 oracle），
/// 因此客户端不会在请求失败后自动改用 previous key 重试。
class GatewayServerKeyRing {
  GatewayServerKeyRing({
    required this.currentKeyId,
    required List<int> currentPublicKey,
    this.previousKeyId,
    List<int>? previousPublicKey,
  })  : currentPublicKey = Uint8List.fromList(currentPublicKey),
        previousPublicKey =
            previousPublicKey == null ? null : Uint8List.fromList(previousPublicKey) {
    _validateKeyId(currentKeyId);
    _expectLength(this.currentPublicKey, 32, 'current server public key');
    if ((previousKeyId == null) != (this.previousPublicKey == null)) {
      throw ArgumentError('previousKeyId and previousPublicKey must be provided together');
    }
    if (previousKeyId != null) {
      _validateKeyId(previousKeyId!);
      _expectLength(this.previousPublicKey!, 32, 'previous server public key');
    }
  }

  final int currentKeyId;
  final Uint8List currentPublicKey;
  final int? previousKeyId;
  final Uint8List? previousPublicKey;
}
