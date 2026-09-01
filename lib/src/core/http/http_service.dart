import 'dart:convert';
import 'dart:io';
import 'package:dio/dio.dart';
import 'package:dio/io.dart';
import 'package:flutter/services.dart';
import 'package:socks5_proxy/socks_client.dart';
import '../exceptions/xboard_exceptions.dart';
import '../auth/token_manager.dart';
import '../auth/auth_interceptor.dart';
import '../logging/sdk_logger.dart';
import '../security/encrypted_gateway_protocol.dart';
import 'http_config.dart';

class HttpService {
  final String baseUrl;
  final HttpConfig httpConfig;
  late final Dio _dio;
  EncryptedGatewayClient? _encryptedGatewayClient;
  TokenManager? _tokenManager;
  AuthInterceptor? _authInterceptor;
  String? _expectedCertificatePem;
  bool _certificateLoadFailed = false;

  HttpService._internal(
    this.baseUrl,
    this.httpConfig,
    this._tokenManager,
  );

  /// 创建 HttpService 实例（异步工厂方法）
  static Future<HttpService> create(
    String baseUrl, {
    TokenManager? tokenManager,
    HttpConfig? httpConfig,
    bool requireEncryptedGateway = false,
  }) async {
    final config = httpConfig ?? HttpConfig.defaultConfig();
    if (requireEncryptedGateway && config.encryptedGateway == null) {
      throw ConfigException('Encrypted gateway is required but not configured');
    }
    final service = HttpService._internal(baseUrl, config, tokenManager);

    if (config.encryptedGateway != null) {
      final gateway = config.encryptedGateway!;
      service._encryptedGatewayClient = await EncryptedGatewayClient.create(
        keyRing: gateway.keyRing,
        allowedClockSkew: gateway.allowedClockSkew,
        paddingPolicy: GatewayPaddingPolicy(maxEnvelopeSize: gateway.maxEnvelopeSize),
      );
    }
    
    // 如果启用证书固定，先加载证书
    if (config.enableCertificatePinning == true) {
      await service._loadClientCertificate();
    }
    
    // 初始化 Dio
    service._initializeDio();
    
    return service;
  }

  /// 初始化Dio配置
  void _initializeDio() {
    _dio = Dio(BaseOptions(
      baseUrl: baseUrl,
      connectTimeout: Duration(seconds: httpConfig.connectTimeoutSeconds),
      receiveTimeout: Duration(seconds: httpConfig.receiveTimeoutSeconds),
      sendTimeout: Duration(seconds: httpConfig.sendTimeoutSeconds),
      responseType: ResponseType.plain,
      headers: {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
        // 使用配置的 User-Agent，如果未设置则使用默认值
        'User-Agent': httpConfig.userAgent ?? 'FlClash-XBoard-SDK/1.0',
      },
    ));

    // 配置客户端证书和SSL验证
    (_dio.httpClientAdapter as IOHttpClientAdapter).createHttpClient = () {
      SdkLogger.d('[XBoardSDK] 🔨 创建 HttpClient...');
      final client = HttpClient();

      // 配置代理
      if (httpConfig.proxyUrl != null && httpConfig.proxyUrl!.isNotEmpty) {
        SdkLogger.d('[XBoardSDK] 🔌 配置代理: ${httpConfig.proxyUrl}');

        final proxyConfig = _parseProxyConfig(httpConfig.proxyUrl!);
        SdkLogger.d('[XBoardSDK] 🔄 解析: host=${proxyConfig['host']}, port=${proxyConfig['port']}, auth=${proxyConfig['username'] != null}');

        // 使用 socks5_proxy 配置代理
        final proxySettings = ProxySettings(
          InternetAddress(proxyConfig['host']!),
          int.parse(proxyConfig['port']!),
          username: proxyConfig['username'],
          password: proxyConfig['password'],
        );

        SocksTCPClient.assignToHttpClient(client, [proxySettings]);
        SdkLogger.i('[XBoardSDK] ✅ SOCKS5 代理配置完成');
      }
      
      // 配置SSL证书验证
      if (httpConfig.enableCertificatePinning || httpConfig.ignoreCertificateHostname) {
        client.badCertificateCallback = (X509Certificate cert, String host, int port) {
          // 如果启用了证书固定，进行严格验证
          if (httpConfig.enableCertificatePinning) {
            return _verifyCertificate(cert, host, port);
          }
          // 如果允许忽略主机名验证（仅开发环境）
          if (httpConfig.ignoreCertificateHostname) {
            return true;
          }
          // 默认使用标准验证
          return false;
        };
      }
      
      return client;
    };

    // 认证必须先运行，使 Authorization 被加密进内层信封。
    if (_tokenManager != null) {
      _authInterceptor = AuthInterceptor(tokenManager: _tokenManager!);
      _dio.interceptors.add(_authInterceptor!);
    }

    // 添加请求日志和响应格式化拦截器
    _dio.interceptors.add(InterceptorsWrapper(
      onRequest: (options, handler) async {
        if (_encryptedGatewayClient != null) {
          try {
            await _encryptRequestOptions(options);
          } catch (error) {
            handler.reject(DioException(
              requestOptions: options,
              type: DioExceptionType.unknown,
              error: error,
              message: 'Failed to encrypt gateway request',
            ));
            return;
          }
        }

        // 打印请求信息和代理状态（隐藏 query，避免泄漏 token 等敏感参数）
        final proxyStatus = httpConfig.proxyUrl != null && httpConfig.proxyUrl!.isNotEmpty;
        final proxyInfo = proxyStatus ? httpConfig.proxyUrl : 'DIRECT';
        SdkLogger.d('[XBoardSDK] request ${options.method} ${_sanitizedUri(options.uri)} | proxy: $proxyStatus ($proxyInfo)');

        handler.next(options);
      },
      onResponse: (response, handler) async {
        if (response.requestOptions.extra[_gatewayRequestIdKey] case final List<int> requestId) {
          try {
            final payload = await _encryptedGatewayClient!.decryptResponse(
              _expectByteResponse(response.data),
              expectedRequestId: requestId,
            );
            response
              ..statusCode = payload.statusCode
              ..headers = Headers.fromMap(
                payload.headers.map((name, value) => MapEntry(name, [value])),
              );

            if (response.requestOptions.extra[_rawGatewayResponseKey] == true) {
              response.data = payload.body;
            } else {
              response.data = _decodeGatewayBody(payload);
            }

            if (payload.statusCode < 200 || payload.statusCode >= 300) {
              handler.reject(_handleDioError(DioException.badResponse(
                statusCode: payload.statusCode,
                requestOptions: response.requestOptions,
                response: response,
              )));
              return;
            }
            if (response.requestOptions.extra[_rawGatewayResponseKey] == true) {
              handler.next(response);
              return;
            }
          } catch (error) {
            handler.reject(DioException(
              requestOptions: response.requestOptions,
              type: DioExceptionType.unknown,
              error: error,
              message: 'Encrypted gateway response validation failed',
            ));
            return;
          }
        }

        // 检查是否需要解混淆
        response.data = _deobfuscateResponse(response);
        response.data = _normalizeResponse(response.data);
        handler.next(response);
      },
      onError: (error, handler) {
        final normalizedError = _handleDioError(error);
        handler.next(normalizedError);
      },
    ));

  }

  /// 设置TokenManager
  void setTokenManager(TokenManager tokenManager) {
    _tokenManager = tokenManager;
    
    // 移除旧的认证拦截器
    if (_authInterceptor != null) {
      _dio.interceptors.remove(_authInterceptor!);
    }
    
    // 认证必须保持在加密拦截器之前。
    _authInterceptor = AuthInterceptor(tokenManager: tokenManager);
    _dio.interceptors.insert(0, _authInterceptor!);
  }

  Future<void> _encryptRequestOptions(RequestOptions options) async {
    final gateway = httpConfig.encryptedGateway!;
    final originalUri = options.uri;
    final headers = <String, String>{};
    const allowedHeaders = {
      'accept',
      'accept-language',
      'authorization',
      'user-agent',
      'x-client-version',
    };
    for (final entry in options.headers.entries) {
      final name = entry.key.toLowerCase();
      if (allowedHeaders.contains(name)) {
        headers[name] = entry.value.toString();
      }
    }
    final query = <GatewayQueryParameter>[];
    for (final entry in originalUri.queryParametersAll.entries) {
      for (final value in entry.value) {
        query.add(GatewayQueryParameter(entry.key, value));
      }
    }
    final contentType = options.contentType ?? options.headers['Content-Type']?.toString();
    final encrypted = await _encryptedGatewayClient!.encryptRequest(
      GatewayRequestPayload(
        method: options.method,
        path: originalUri.path,
        query: query,
        headers: headers,
        body: _encodeRequestBody(options.data),
        contentType: contentType,
      ),
    );

    options.extra[_gatewayRequestIdKey] = encrypted.requestId;
    options
      ..method = 'POST'
      ..path = gateway.path
      ..data = encrypted.bytes
      ..responseType = ResponseType.bytes
      ..contentType = 'application/octet-stream';
    options.queryParameters.clear();
    options.headers
      ..clear()
      ..addAll({
        'Accept': 'application/octet-stream',
        'Content-Type': 'application/octet-stream',
        'User-Agent': httpConfig.userAgent ?? 'Mozilla/5.0',
      });
  }

  List<int> _encodeRequestBody(dynamic data) {
    if (data == null) {
      return const [];
    }
    if (data is Uint8List) {
      return data;
    }
    if (data is List<int>) {
      return data;
    }
    if (data is String) {
      return utf8.encode(data);
    }
    if (data is Map || data is List || data is num || data is bool) {
      return utf8.encode(jsonEncode(data));
    }
    throw GatewayProtocolException('Unsupported encrypted request body type');
  }

  List<int> _expectByteResponse(dynamic data) {
    if (data is List<int>) {
      return data;
    }
    throw GatewayProtocolException('Encrypted gateway returned a non-binary response');
  }

  /// 日志用途：去掉 query 部分，避免明文模式下打印 token 等敏感参数。
  String _sanitizedUri(Uri uri) {
    return uri.query.isEmpty ? uri.toString() : uri.replace(query: '').toString();
  }

  dynamic _decodeGatewayBody(GatewayResponsePayload payload) {
    if (payload.body.isEmpty) {
      return '';
    }
    final text = utf8.decode(payload.body, allowMalformed: false);
    final contentType = payload.headers['content-type']?.toLowerCase() ?? '';
    if (contentType.contains('json') || text.trimLeft().startsWith('{') || text.trimLeft().startsWith('[')) {
      return jsonDecode(text);
    }
    return text;
  }

  /// 发送GET请求
  Future<Map<String, dynamic>> getRequest(String path, {Map<String, String>? headers}) async {
    try {
      final response = await _dio.get(
        path,
        options: Options(headers: headers),
      );
      
      return response.data as Map<String, dynamic>;
    } catch (e) {
      throw _convertDioError(e);
    }
  }

  /// 发送POST请求
  Future<Map<String, dynamic>> postRequest(String path, Map<String, dynamic> data, {Map<String, String>? headers}) async {
    try {
      final response = await _dio.post(
        path,
        data: data,
        options: Options(headers: headers),
      );
      
      return response.data as Map<String, dynamic>;
    } catch (e) {
      throw _convertDioError(e);
    }
  }

  /// 发送PUT请求
  Future<Map<String, dynamic>> putRequest(String path, Map<String, dynamic> data, {Map<String, String>? headers}) async {
    try {
      final response = await _dio.put(
        path,
        data: data,
        options: Options(headers: headers),
      );
      
      return response.data as Map<String, dynamic>;
    } catch (e) {
      throw _convertDioError(e);
    }
  }

  /// 发送DELETE请求
  Future<Map<String, dynamic>> deleteRequest(String path, {Map<String, String>? headers}) async {
    try {
      final response = await _dio.delete(
        path,
        options: Options(headers: headers),
      );
      
      return response.data as Map<String, dynamic>;
    } catch (e) {
      throw _convertDioError(e);
    }
  }

  /// 通过加密网关获取原始响应字节，不允许回退到明文 HTTP。
  Future<RawHttpResponse> getEncryptedRawRequest(
    String path, {
    Map<String, String>? headers,
  }) async {
    if (_encryptedGatewayClient == null) {
      throw ConfigException('Encrypted gateway is required for raw requests');
    }
    try {
      final response = await _dio.get<List<int>>(
        path,
        options: Options(
          headers: headers,
          responseType: ResponseType.bytes,
          extra: const {_rawGatewayResponseKey: true},
        ),
      );
      final responseHeaders = <String, String>{};
      response.headers.forEach((name, values) {
        responseHeaders[name] = values.join(', ');
      });
      return RawHttpResponse(
        statusCode: response.statusCode ?? 200,
        headers: responseHeaders,
        body: Uint8List.fromList(response.data ?? const []),
      );
    } catch (error) {
      throw _convertDioError(error);
    }
  }

  /// 解混淆响应数据
  /// 
  /// 根据配置的混淆前缀自动检测并反混淆响应数据
  /// 例如 Caddy 混淆规则：replace "{\"status\"" "OBFS_9K8L7M6N_{\"status\""
  dynamic _deobfuscateResponse(Response response) {
    try {
      final responseText = response.data as String;
      
      // 检查是否启用了自动反混淆且配置了混淆前缀
      if (httpConfig.enableAutoDeobfuscation && 
          httpConfig.obfuscationPrefix != null &&
          httpConfig.obfuscationPrefix!.isNotEmpty) {
        
        // 检测是否包含混淆前缀
        final containsObfuscationPrefix = responseText.contains(httpConfig.obfuscationPrefix!);
        
        if (containsObfuscationPrefix) {
          // 反混淆：移除混淆前缀
          final deobfuscated = responseText.replaceAll(httpConfig.obfuscationPrefix!, '');
          return jsonDecode(deobfuscated);
        }
      }
      
      // 没有混淆或未启用反混淆，尝试直接解析JSON
      if (responseText.trim().startsWith('{') || responseText.trim().startsWith('[')) {
        return jsonDecode(responseText);
      } else {
        return responseText;
      }
    } catch (e) {
      // 解混淆失败，返回原始数据
      return response.data;
    }
  }

  /// 验证客户端证书（Certificate Pinning）
  /// 
  /// ⚠️ 安全改进：证书加载失败时拒绝连接
  /// [cert] 服务器证书
  /// [host] 主机名
  /// [port] 端口
  bool _verifyCertificate(X509Certificate cert, String host, int port) {
    try {
      SdkLogger.i('[HttpService] 🔐 开始验证证书: $host:$port');
      
      // 安全检查：如果证书加载失败，拒绝连接
      if (_certificateLoadFailed) {
        SdkLogger.e('[HttpService] ❌ 证书加载失败，拒绝连接');
        throw CertificateException(
          'Certificate pinning is enabled but certificate failed to load. '
          'Refusing connection for security reasons.'
        );
      }

      // 安全检查：如果启用了证书固定但没有期望的证书，拒绝连接
      if (httpConfig.enableCertificatePinning && _expectedCertificatePem == null) {
        SdkLogger.e('[HttpService] ❌ 证书固定已启用但未加载期望证书');
        throw CertificateException(
          'Certificate pinning is enabled but no expected certificate is available. '
          'Refusing connection for security reasons.'
        );
      }
      
      // 打印服务器证书信息
      SdkLogger.i('[HttpService] 📜 服务器证书信息:');
      SdkLogger.i('[HttpService]   - 主体: ${cert.subject}');
      SdkLogger.i('[HttpService]   - 签发者: ${cert.issuer}');
      SdkLogger.i('[HttpService]   - 有效期: ${cert.startValidity} ~ ${cert.endValidity}');
      
      // 获取当前证书的PEM格式
      final currentCertPem = cert.pem;
      
      SdkLogger.i('[HttpService] 🔍 比较证书指纹...');
      SdkLogger.i('[HttpService]   - 期望证书长度: ${_expectedCertificatePem!.length} 字符');
      SdkLogger.i('[HttpService]   - 服务器证书长度: ${currentCertPem.length} 字符');
      
      // 比较证书内容（忽略空白字符差异）
      final expectedNormalized = _expectedCertificatePem!.replaceAll(RegExp(r'\s+'), '');
      final currentNormalized = currentCertPem.replaceAll(RegExp(r'\s+'), '');
      
      SdkLogger.i('[HttpService]   - 标准化后期望证书长度: ${expectedNormalized.length}');
      SdkLogger.i('[HttpService]   - 标准化后服务器证书长度: ${currentNormalized.length}');
      
      final isValid = expectedNormalized == currentNormalized;
      
      if (!isValid) {
        SdkLogger.e('[HttpService] ❌ 证书不匹配！');
        SdkLogger.e('[HttpService]   - 期望证书前100字符: ${expectedNormalized.substring(0, 100.clamp(0, expectedNormalized.length))}');
        SdkLogger.e('[HttpService]   - 服务器证书前100字符: ${currentNormalized.substring(0, 100.clamp(0, currentNormalized.length))}');
        throw CertificateException(
          'Certificate verification failed for $host:$port. '
          'The certificate does not match the expected certificate.'
        );
      }
      
      SdkLogger.i('[HttpService] ✅ 证书验证成功！');
      return isValid;
    } catch (e) {
      // 证书验证出错，为安全起见拒绝连接
      SdkLogger.e('[HttpService] ⛔ 证书验证异常: $e');
      return false;
    }
  }
  
  /// 加载客户端证书
  /// 
  /// 从配置文件指定的路径加载证书（xboard.config.yaml -> security.certificate.path）
  /// 证书加载失败时会拒绝所有 HTTPS 连接以保证安全
  Future<void> _loadClientCertificate() async {
    SdkLogger.i('[HttpService] 📋 开始加载证书...');
    SdkLogger.i('[HttpService]   - 证书固定: ${httpConfig.enableCertificatePinning}');
    SdkLogger.i('[HttpService]   - 证书路径: ${httpConfig.certificatePath}');
    
    if (httpConfig.certificatePath == null || httpConfig.certificatePath!.isEmpty) {
      _certificateLoadFailed = true;
      _expectedCertificatePem = null;
      SdkLogger.w('[HttpService] ⚠️ 证书路径未配置');
      return;
    }

    final certPath = httpConfig.certificatePath!;

    try {
      SdkLogger.i('[HttpService] 🔄 正在从 assets 加载证书: $certPath');
      
      // 同步等待证书加载
      final certContent = await rootBundle.loadString(certPath);
      
      _expectedCertificatePem = certContent;
      _certificateLoadFailed = false;
      
      SdkLogger.i('[HttpService] ✅ 证书加载成功！');
      SdkLogger.i('[HttpService]   - 证书内容长度: ${certContent.length} 字符');
    } catch (error) {
      _certificateLoadFailed = true;
      _expectedCertificatePem = null;
      SdkLogger.e('[HttpService] ❌ 证书加载失败！');
      SdkLogger.e('[HttpService]   - 错误: $error');
      SdkLogger.e('[HttpService]   - 所有 HTTPS 连接将被拒绝');
    }
  }

  /// 标准化响应格式
  Map<String, dynamic> _normalizeResponse(dynamic responseData) {
    if (responseData is! Map<String, dynamic>) {
      return {
        'success': true,
        'data': responseData,
      };
    }

    final jsonResponse = responseData;

    // 兼容两种响应格式：
    // 1. XBoard格式: {status: "success", data: {...}}
    // 2. 通用格式: {success: true, data: {...}}
    
    if (jsonResponse.containsKey('status')) {
      // XBoard格式 -> 转换为通用格式
      return {
        'success': jsonResponse['status'] == 'success',
        'status': jsonResponse['status'],
        'message': jsonResponse['message'],
        'data': jsonResponse['data'],
        'total': jsonResponse['total'],
      };
    } else if (jsonResponse.containsKey('success')) {
      // 已经是通用格式，直接返回
      return jsonResponse;
    } else {
      // 其他格式，包装为通用格式
      return {
        'success': true,
        'data': jsonResponse,
      };
    }
  }

  /// 处理Dio错误
  DioException _handleDioError(DioException error) {
    if (error.response != null) {
      final statusCode = error.response!.statusCode!;
      
      // 先解混淆和解析响应数据
      dynamic responseData = _deobfuscateResponse(error.response!);
      
      String errorMessage = '请求失败 (状态码: $statusCode)';
      
      // 尝试从响应中提取错误信息
      if (responseData is Map<String, dynamic>) {
        // 优先级：message > error > data
        if (responseData.containsKey('message') && 
            responseData['message'] != null && 
            responseData['message'].toString().isNotEmpty) {
          errorMessage = responseData['message'].toString();
        } else if (responseData.containsKey('error') && 
                   responseData['error'] != null &&
                   responseData['error'].toString().isNotEmpty) {
          // error 可能是字符串或对象
          final errorField = responseData['error'];
          if (errorField is String) {
            errorMessage = errorField;
          } else if (errorField is Map) {
            errorMessage = errorField.toString();
          }
        } else if (responseData.containsKey('data') && responseData['data'] is String) {
          errorMessage = responseData['data'].toString();
        }
      } else if (responseData is String && responseData.isNotEmpty) {
        // 如果响应是纯文本，尝试提取有用信息
        errorMessage = responseData;
      }
      
      SdkLogger.w('[HttpService] Request failed with status $statusCode');

      // 创建新的DioException，保持原有的错误信息但添加我们的错误消息
      return DioException(
        requestOptions: error.requestOptions,
        response: error.response,
        type: error.type,
        error: errorMessage,
        message: errorMessage,
      );
    }
    
    return error;
  }

  /// 转换Dio错误为XBoard异常
  XBoardException _convertDioError(dynamic error) {
    if (error is DioException) {
      if (error.response != null) {
        final statusCode = error.response!.statusCode!;
        // 直接使用已经提取的错误消息（在 _handleDioError 中处理）
        final errorMessage = error.message ?? error.error?.toString() ?? '请求失败';
        
        if (statusCode == 401) {
          return AuthException(errorMessage);
        } else if (statusCode >= 400 && statusCode < 500) {
          return ApiException(errorMessage, statusCode);
        } else {
          return NetworkException(errorMessage);
        }
      } else {
        // 网络错误 - 直接使用 Dio 的原始错误信息
        String errorMsg = error.error?.toString() ?? error.message ?? error.type.toString();
        return NetworkException(errorMsg);
      }
    } else if (error is XBoardException) {
      return error;
    } else {
      return ApiException(error.toString());
    }
  }

  /// 释放资源
  void dispose() {
    _dio.close();
  }

  /// 获取Dio实例（用于高级用法）
  Dio get dio => _dio;

  /// 获取TokenManager
  TokenManager? get tokenManager => _tokenManager;

  /// 解析代理配置
  ///
  /// 输入格式:
  /// - `socks5://user:pass@host:port`
  /// - `socks5://host:port`
  /// - `http://user:pass@host:port`
  ///
  /// 返回: { host, port, username?, password? }
  static Map<String, String?> _parseProxyConfig(String proxyUrl) {
    String url = proxyUrl.trim();

    // 去除协议前缀
    if (url.toLowerCase().startsWith('socks5://')) {
      url = url.substring(9);
    } else if (url.toLowerCase().startsWith('http://')) {
      url = url.substring(7);
    } else if (url.toLowerCase().startsWith('https://')) {
      url = url.substring(8);
    }

    String? username;
    String? password;
    String hostPort = url;

    // 解析认证信息 user:pass@host:port
    if (url.contains('@')) {
      final atIndex = url.lastIndexOf('@');
      final authPart = url.substring(0, atIndex);
      hostPort = url.substring(atIndex + 1);

      if (authPart.contains(':')) {
        final colonIndex = authPart.indexOf(':');
        username = authPart.substring(0, colonIndex);
        password = authPart.substring(colonIndex + 1);
      }
    }

    // 解析 host:port
    final parts = hostPort.split(':');
    final host = parts[0];
    final port = parts.length > 1 ? parts[1] : '1080';

    return {
      'host': host,
      'port': port,
      'username': username,
      'password': password,
    };
  }
}

const _gatewayRequestIdKey = 'encrypted_gateway.request_id';
const _rawGatewayResponseKey = 'encrypted_gateway.raw_response';

class RawHttpResponse {
  const RawHttpResponse({
    required this.statusCode,
    required this.headers,
    required this.body,
  });

  final int statusCode;
  final Map<String, String> headers;
  final Uint8List body;
}