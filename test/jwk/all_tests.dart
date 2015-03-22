library jose_jwt.jwk.all_tests;

import 'package:unittest/unittest.dart';
import 'ec_key_test.dart' as ec_key_test;
import 'jwk_selector_test.dart' as jwk_selector_test;
import 'jwk_set_test.dart' as jwk_set_test;
import 'jwk_test.dart' as jwk_test;
import 'key_operation_test.dart' as key_operation_test;
import 'key_type_test.dart' as key_type_test;
import 'key_use_test.dart' as key_use_test;
import 'octet_sequence_key_test.dart' as octet_sequence_key_test;
import 'rsa_key_test.dart' as rsa_key_test;

void main() {
  group('ECKeyTest', ec_key_test.main);
  group('JWKSelectorTest', jwk_selector_test.main);
  group('JWKSetTest', jwk_set_test.main);
  group('JWKTest', jwk_test.main);
  group('KeyOperationTest', key_operation_test.main);
  group('KeyTypeTest', key_type_test.main);
  group('KeyUseTest', key_use_test.main);
  group('OctetSequenceKeyTest', octet_sequence_key_test.main);
  group('RSAKeyTest', rsa_key_test.main);
}
