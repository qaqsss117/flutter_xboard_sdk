import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_xboard_sdk/src/adapters/xboard/xboard_order_adapter.dart';
import 'package:flutter_xboard_sdk/src/api/models/payment_model.dart';
import 'package:flutter_xboard_sdk/src/core/http/http_service.dart';
import 'package:flutter_xboard_sdk/src/panels/xboard/apis/xboard_coupon_api.dart';
import 'package:flutter_xboard_sdk/src/panels/xboard/apis/xboard_order_api.dart';
import 'package:flutter_xboard_sdk/src/panels/xboard/models/xboard_order_models.dart';

class _FakeOrderApi extends XBoardOrderApi {
  final CheckoutResult checkoutResult;

  _FakeOrderApi(super.httpService, this.checkoutResult);

  @override
  Future<CheckoutResult> submitPayment({
    required String tradeNo,
    required String method,
  }) async {
    return checkoutResult;
  }
}

void main() {
  late HttpService httpService;

  setUpAll(() async {
    httpService = await HttpService.create('https://example.com');
  });

  XBoardOrderAdapter createAdapter(CheckoutResult result) {
    return XBoardOrderAdapter(
      _FakeOrderApi(httpService, result),
      XBoardCouponApi(httpService),
    );
  }

  test('maps Xboard type 0 payment data to a QR code result', () async {
    final adapter = createAdapter(
      CheckoutResult(type: 0, data: 'weixin://wxpay/example'),
    );

    final result = await adapter.checkoutOrder('ORDER-1', '7');

    expect(result, isA<PaymentResultRedirect>());
    final redirect = result as PaymentResultRedirect;
    expect(redirect.url, 'weixin://wxpay/example');
    expect(redirect.method, 'qr_code');
  });

  test('maps Xboard type 1 payment data to a redirect result', () async {
    final adapter = createAdapter(
      CheckoutResult(type: 1, data: 'https://pay.example/ORDER-2'),
    );

    final result = await adapter.checkoutOrder('ORDER-2', '8');

    expect(result, isA<PaymentResultRedirect>());
    final redirect = result as PaymentResultRedirect;
    expect(redirect.url, 'https://pay.example/ORDER-2');
    expect(redirect.method, isNull);
  });
}
