part of 'encrypted_transport.dart';

class GatewayProtocolException implements Exception {
  GatewayProtocolException(this.message);

  final String message;

  @override
  String toString() => 'GatewayProtocolException: $message';
}
