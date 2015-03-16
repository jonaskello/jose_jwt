library jose_jwt.all_tests;

import 'package:unittest/unittest.dart';
import 'encrypted_jwt_test.dart' as encrypted_jwt_test;
import 'jwt_claims_set_test.dart' as jwt_claims_set_test;
import 'signed_jwt_test.dart' as signed_jwt_test;

void main() {
  group('EncryptedJWTTest', encrypted_jwt_test.main);
  group('JWTClaimsSetTest', jwt_claims_set_test.main);
  group('SignedJWTTest', signed_jwt_test.main);
}
