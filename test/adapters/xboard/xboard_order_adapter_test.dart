import 'dart:convert';
import 'dart:typed_data';
import 'package:dio/dio.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_xboard_sdk/src/adapters/xboard/xboard_order_adapter.dart';
import 'package:flutter_xboard_sdk/src/api/models/payment_model.dart';
import 'package:flutter_xboard_sdk/src/core/http/http_service.dart';
import 'package:flutter_xboard_sdk/src/panels/xboard/apis/xboard_coupon_api.dart';
import 'package:flutter_xboard_sdk/src/panels/xboard/apis/xboard_order_api.dart';

class _CheckoutHttpAdapter implements HttpClientAdapter {
  final Map<String, dynamic> result;
  final void Function(RequestOptions)? onRequest;

  _CheckoutHttpAdapter(this.result, this.onRequest);

  @override
  Future<ResponseBody> fetch(
    RequestOptions options,
    Stream<Uint8List>? requestStream,
    Future<void>? cancelFuture,
  ) async {
    onRequest?.call(options);
    return ResponseBody.fromString(
      jsonEncode(result),
      200,
      headers: {
        'content-type': ['application/json'],
      },
    );
  }

  @override
  void close({bool force = false}) {}
}

void main() {
  late HttpService httpService;

  setUp(() async {
    httpService = await HttpService.create('https://example.com');
  });

  tearDown(() => httpService.dispose());

  XBoardOrderAdapter createAdapter(
    Map<String, dynamic> result, {
    void Function(RequestOptions)? onRequest,
  }) {
    httpService.dio.httpClientAdapter = _CheckoutHttpAdapter(result, onRequest);
    return XBoardOrderAdapter(
      XBoardOrderApi(httpService),
      XBoardCouponApi(httpService),
    );
  }

  test('maps Xboard type 0 payment data to a QR code result', () async {
    final adapter = createAdapter({
      'type': 0,
      'data': 'weixin://wxpay/example',
    });

    final result = await adapter.checkoutOrder('ORDER-1', '7');

    expect(result, isA<PaymentResultRedirect>());
    final redirect = result as PaymentResultRedirect;
    expect(redirect.url, 'weixin://wxpay/example');
    expect(redirect.method, 'qr_code');
  });

  test('maps Xboard type 1 payment data to a redirect result', () async {
    final adapter = createAdapter({
      'type': 1,
      'data': 'https://pay.example/ORDER-2',
    });

    final result = await adapter.checkoutOrder('ORDER-2', '8');

    expect(result, isA<PaymentResultRedirect>());
    final redirect = result as PaymentResultRedirect;
    expect(redirect.url, 'https://pay.example/ORDER-2');
    expect(redirect.method, isNull);
  });

  for (final mode in ['qrcode', 'url']) {
    test('sends the $mode preference through the checkout API', () async {
      RequestOptions? checkout;
      final adapter = createAdapter({
        'type': 1,
        'data': 'https://pay.example/checkout',
      }, onRequest: (request) => checkout = request);

      await adapter.checkoutOrder('ORDER-3', '7', paymentMode: mode);

      expect(checkout?.method, 'POST');
      expect(checkout?.path, '/api/v1/user/order/checkout');
      expect(checkout?.data, {
        'trade_no': 'ORDER-3',
        'method': '7',
        'payment_mode': mode,
      });
    });
  }

  test(
    'keeps legacy checkout requests and balance payment compatible',
    () async {
      RequestOptions? checkout;
      final adapter = createAdapter({
        'type': -1,
        'data': true,
      }, onRequest: (request) => checkout = request);

      final result = await adapter.checkoutOrder('FREE-ORDER', '7');

      expect(result, isA<PaymentResultSuccess>());
      expect(checkout?.data, {'trade_no': 'FREE-ORDER', 'method': '7'});
    },
  );

  test('also accepts a wrapped checkout response', () async {
    final adapter = createAdapter({
      'status': 'success',
      'data': {'type': 0, 'data': 'https://qr.example/checkout'},
    });

    final result = await adapter.checkoutOrder('ORDER-4', '7');

    expect(
      result,
      const PaymentResultModel.redirect(
        url: 'https://qr.example/checkout',
        method: 'qr_code',
      ),
    );
  });
}
