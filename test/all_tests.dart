library jose_jwt.test.all_tests;

import 'package:unittest/unittest.dart';
import 'jose/all_tests.dart' as jose_all_tests;
import 'jwk/all_tests.dart' as jwk_all_tests;
import 'jwt/all_tests.dart' as jwt_all_tests;

void main() {
  group('jose_all_tests', jose_all_tests.main);
  group('jwk_all_tests', jwk_all_tests.main);
  group('jwt_all_tests', jwt_all_tests.main);
}
