library jose_jwt.jwk.all_tests;

import 'package:unittest/unittest.dart';
import 'ec_key_test.dart' as ec_key_test;

void main() {
  group('ECKeyTest', ec_key_test.main);
}
