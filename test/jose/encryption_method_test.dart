library jose_jwt.test.jose.encryption_method_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';

/**
 * Tests the EncryptionMethod class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-05-23)
 */
//public class EncryptionMethodTest extends TestCase {
main() {

  test('testCMKLengths', () {

    expect(256, EncryptionMethod.A128CBC_HS256.cekBitLength());
    expect(384, EncryptionMethod.A192CBC_HS384.cekBitLength());
    expect(512, EncryptionMethod.A256CBC_HS512.cekBitLength());

    expect(128, EncryptionMethod.A128GCM.cekBitLength());
    expect(192, EncryptionMethod.A192GCM.cekBitLength());
    expect(256, EncryptionMethod.A256GCM.cekBitLength());

    expect(256, EncryptionMethod.A128CBC_HS256_DEPRECATED.cekBitLength());
    expect(512, EncryptionMethod.A256CBC_HS512_DEPRECATED.cekBitLength());
  });

}
