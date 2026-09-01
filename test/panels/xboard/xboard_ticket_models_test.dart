import 'package:flutter_test/flutter_test.dart';
import 'package:flutter_xboard_sdk/src/panels/xboard/models/xboard_ticket_models.dart';

void main() {
  test('parses an Xboard ticket detail response', () {
    final ticket = TicketDetail.fromJson({
      'id': 12,
      'level': 1,
      'reply_status': 0,
      'status': 0,
      'subject': 'Connection issue',
      'message': [
        {
          'id': 24,
          'ticket_id': 12,
          'is_me': true,
          'message': 'Please help',
          'created_at': 1700000000,
          'updated_at': 1700000000,
        },
      ],
      'created_at': 1700000000,
      'updated_at': 1700000000,
    });

    expect(ticket.userId, 0);
    expect(ticket.messages, hasLength(1));
    expect(ticket.messages.single.message, 'Please help');
    expect(ticket.messages.single.isMe, isTrue);
  });
}