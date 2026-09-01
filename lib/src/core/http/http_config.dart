import 'dart:convert';
import 'dart:typed_data';

import '../security/encrypted_transport/encrypted_transport.dart';

class EncryptedGatewayConfig {
  EncryptedGatewayConfig({
    required this.path,
    required this.keyId,
    required this.serverPublicKey,
    this.previousKeyId,
    this.previousServerPublicKey,
    this.allowedClockSkew = const Duration(minutes: 2),
    this.maxEnvelopeSize = 4 * 1024 * 1024,
  }) {
    if (!RegExp(r'^/[A-Za-z0-9_-]{24,128}$').hasMatch(path)) {
      throw ArgumentError.value(
        path,
        'path',
        'Expected a random URL-safe path of 24-128 characters',
      );
    }
    if (keyId < 0 || keyId > 0xffffffff) {
      throw ArgumentError.value(keyId, 'keyId', 'Expected an unsigned 32-bit integer');
    }
    if (_decodePublicKey(serverPublicKey).length != 32) {
      throw ArgumentError.value(serverPublicKey, 'serverPublicKey', 'Expected 32 bytes');
    }
    if ((previousKeyId == null) != (previousServerPublicKey == null)) {
      throw ArgumentError('previousKeyId and previousServerPublicKey must be provided together');
    }
    if (previousKeyId != null) {
      if (previousKeyId! < 0 || previousKeyId! > 0xffffffff) {
        throw ArgumentError.value(
          previousKeyId,
          'previousKeyId',
          'Expected an unsigned 32-bit integer',
        );
      }
      if (_decodePublicKey(previousServerPublicKey!).length != 32) {
        throw ArgumentError.value(
          previousServerPublicKey,
          'previousServerPublicKey',
          'Expected 32 bytes',
        );
      }
    }
    if (allowedClockSkew <= Duration.zero || maxEnvelopeSize < 1024) {
      throw ArgumentError('Invalid encrypted gateway limits');
    }
  }

  final String path;
  final int keyId;
  final String serverPublicKey;

  /// 配置灰度切换预留：协议不支持失败后自动改用 previous key 重试。
  final int? previousKeyId;
  final String? previousServerPublicKey;
  final Duration allowedClockSkew;
  final int maxEnvelopeSize;

  Uint8List get serverPublicKeyBytes => _decodePublicKey(serverPublicKey);

  /// 供 [EncryptedGatewayClient] 使用的服务端公钥集合。
  GatewayServerKeyRing get keyRing => GatewayServerKeyRing(
        currentKeyId: keyId,
        currentPublicKey: serverPublicKeyBytes,
        previousKeyId: previousKeyId,
        previousPublicKey:
            previousServerPublicKey == null ? null : _decodePublicKey(previousServerPublicKey!),
      );

  static Uint8List _decodePublicKey(String value) {
    if (!RegExp(r'^[A-Za-z0-9_-]+$').hasMatch(value) || value.length % 4 == 1) {
      throw ArgumentError.value(value, 'serverPublicKey', 'Invalid base64url');
    }
    final padded = value.padRight(value.length + ((4 - value.length % 4) % 4), '=');
    try {
      return Uint8List.fromList(base64Url.decode(padded));
    } on FormatException {
      throw ArgumentError.value(value, 'serverPublicKey', 'Invalid base64url');
    }
  }
}

/// HTTP 配置类
/// 
/// 用于管理 SDK 的 HTTP 相关配置，包括：
/// - User-Agent 配置
/// - 响应混淆配置
/// - 证书固定配置
/// - 代理配置
class HttpConfig {
  /// 应用层加密网关配置。为 null 时使用原始 HTTP API。
  final EncryptedGatewayConfig? encryptedGateway;

  /// User-Agent 字符串
  /// 
  /// 如果为 null，将使用默认的 User-Agent
  /// 建议从配置文件或配置提供者读取此值
  final String? userAgent;

  /// 响应混淆前缀
  /// 
  /// 某些服务端会在响应中添加混淆前缀（如 Caddy 反代）
  /// 例如：'OBFS_9K8L7M6N_'
  /// 如果为 null，将不进行反混淆处理
  final String? obfuscationPrefix;

  /// 是否启用证书固定（Certificate Pinning）
  /// 
  /// 默认为 false，使用标准的 SSL 验证
  /// 如果为 true，需要提供 certificatePath
  final bool enableCertificatePinning;

  /// 证书文件路径（相对于 assets 目录）
  /// 
  /// 从配置文件读取：xboard.config.yaml -> security.certificate.path
  /// 例如：'packages/flutter_xboard_sdk/assets/cer/client-cert.crt'
  final String? certificatePath;

  /// 是否忽略证书主机名验证
  /// 
  /// ⚠️ 警告：仅在开发/测试环境使用，生产环境应该为 false
  /// 默认为 false，进行标准的主机名验证
  final bool ignoreCertificateHostname;

  /// HTTP 代理 URL
  /// 
  /// 格式：'host:port' 或 'http://host:port'
  /// 如果为 null，将不使用代理
  final String? proxyUrl;

  /// 是否启用自动反混淆
  /// 
  /// 如果为 true，当检测到混淆前缀时会自动反混淆
  /// 如果为 false，即使设置了 obfuscationPrefix 也不会进行反混淆
  final bool enableAutoDeobfuscation;

  /// 连接超时时间（秒）
  final int connectTimeoutSeconds;

  /// 接收超时时间（秒）
  final int receiveTimeoutSeconds;

  /// 发送超时时间（秒）
  final int sendTimeoutSeconds;

  const HttpConfig({
    this.encryptedGateway,
    this.userAgent,
    this.obfuscationPrefix,
    this.enableCertificatePinning = false,
    this.certificatePath,
    this.ignoreCertificateHostname = false,
    this.proxyUrl,
    this.enableAutoDeobfuscation = true,
    this.connectTimeoutSeconds = 30,
    this.receiveTimeoutSeconds = 30,
    this.sendTimeoutSeconds = 30,
  });

  /// 创建默认配置
  factory HttpConfig.defaultConfig() {
    return const HttpConfig(
      userAgent: 'FlClash-XBoard-SDK/1.0',
      enableAutoDeobfuscation: true,
      enableCertificatePinning: false,
    );
  }

  /// 创建开发环境配置
  /// 
  /// ⚠️ 警告：此配置仅用于开发/测试，不应在生产环境使用
  factory HttpConfig.development({
    String? userAgent,
    String? proxyUrl,
  }) {
    return HttpConfig(
      userAgent: userAgent ?? 'FlClash-XBoard-SDK/1.0-dev',
      proxyUrl: proxyUrl,
      enableCertificatePinning: false,
      ignoreCertificateHostname: true, // 开发环境可以忽略主机名验证
      enableAutoDeobfuscation: true,
    );
  }

  /// 创建生产环境配置
  factory HttpConfig.production({
    required String userAgent,
    EncryptedGatewayConfig? encryptedGateway,
    String? obfuscationPrefix,
    bool enableCertificatePinning = false,
    String? certificatePath,
  }) {
    // 生产环境的安全检查
    if (enableCertificatePinning && certificatePath == null) {
      throw ArgumentError(
        'enableCertificatePinning is true but certificatePath is null. '
        'Certificate pinning requires a certificate path from config file.',
      );
    }

    return HttpConfig(
      encryptedGateway: encryptedGateway,
      userAgent: userAgent,
      obfuscationPrefix: obfuscationPrefix,
      enableCertificatePinning: enableCertificatePinning,
      certificatePath: certificatePath,
      ignoreCertificateHostname: false, // 生产环境必须验证主机名
      enableAutoDeobfuscation: obfuscationPrefix != null,
    );
  }

  /// 从配置提供者创建（与主项目集成）
  /// 
  /// 示例：
  /// ```dart
  /// final config = await HttpConfig.fromConfigProvider(
  ///   getUserAgent: () => UserAgentConfig.get(UserAgentScenario.apiEncrypted),
  ///   getObfuscationPrefix: () => ConfigFileLoaderHelper.getObfuscationPrefix(),
  ///   getCertificatePath: () => ConfigFileLoaderHelper.getCertificatePath(),
  ///   enableCertificatePinning: () => ConfigFileLoaderHelper.isCertificatePinningEnabled(),
  /// );
  /// ```
  static Future<HttpConfig> fromConfigProvider({
    required Future<String> Function() getUserAgent,
    Future<EncryptedGatewayConfig?> Function()? getEncryptedGateway,
    Future<String?> Function()? getObfuscationPrefix,
    Future<String?> Function()? getCertificatePath,
    Future<bool> Function()? enableCertificatePinning,
    String? proxyUrl,
  }) async {
    final userAgent = await getUserAgent();
    final encryptedGateway = getEncryptedGateway == null
      ? null
      : await getEncryptedGateway();
    final obfuscationPrefix = getObfuscationPrefix != null 
        ? await getObfuscationPrefix() 
        : null;
    final certPath = getCertificatePath != null
        ? await getCertificatePath()
        : null;
    final certPinning = enableCertificatePinning != null
        ? await enableCertificatePinning()
        : false;

    return HttpConfig(
      encryptedGateway: encryptedGateway,
      userAgent: userAgent,
      obfuscationPrefix: obfuscationPrefix,
      proxyUrl: proxyUrl,
      enableCertificatePinning: certPinning,
      certificatePath: certPath,
      enableAutoDeobfuscation: obfuscationPrefix != null,
    );
  }

  /// 复制配置并修改部分字段
  HttpConfig copyWith({
    EncryptedGatewayConfig? encryptedGateway,
    String? userAgent,
    String? obfuscationPrefix,
    bool? enableCertificatePinning,
    String? certificatePath,
    bool? ignoreCertificateHostname,
    String? proxyUrl,
    bool? enableAutoDeobfuscation,
    int? connectTimeoutSeconds,
    int? receiveTimeoutSeconds,
    int? sendTimeoutSeconds,
  }) {
    return HttpConfig(
      encryptedGateway: encryptedGateway ?? this.encryptedGateway,
      userAgent: userAgent ?? this.userAgent,
      obfuscationPrefix: obfuscationPrefix ?? this.obfuscationPrefix,
      enableCertificatePinning: enableCertificatePinning ?? this.enableCertificatePinning,
      certificatePath: certificatePath ?? this.certificatePath,
      ignoreCertificateHostname: ignoreCertificateHostname ?? this.ignoreCertificateHostname,
      proxyUrl: proxyUrl ?? this.proxyUrl,
      enableAutoDeobfuscation: enableAutoDeobfuscation ?? this.enableAutoDeobfuscation,
      connectTimeoutSeconds: connectTimeoutSeconds ?? this.connectTimeoutSeconds,
      receiveTimeoutSeconds: receiveTimeoutSeconds ?? this.receiveTimeoutSeconds,
      sendTimeoutSeconds: sendTimeoutSeconds ?? this.sendTimeoutSeconds,
    );
  }

  @override
  String toString() {
    return 'HttpConfig('
      'encryptedGateway: ${encryptedGateway == null ? "disabled" : "enabled"}, '
        'userAgent: $userAgent, '
        'obfuscationPrefix: ${obfuscationPrefix != null ? "***" : "null"}, '
        'enableCertificatePinning: $enableCertificatePinning, '
        'ignoreCertificateHostname: $ignoreCertificateHostname, '
        'proxyUrl: $proxyUrl'
        ')';
  }
}

