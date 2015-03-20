library jose_jwt.test.jose.jwe_crypto_parts_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/util.dart';

/**
 * Tests the JWE crypto parts class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-11)
 */
//public class JWECryptoPartsTest extends TestCase {
main() {

  test('testConstructorWithoutHeader', () {

    JWECryptoParts p = new JWECryptoParts.noKey(
        new Base64URL("abc"),
        new Base64URL("def"),
        new Base64URL("ghi"),
        new Base64URL("jkl")
    );


    expect(p.getHeader(), isNull);
    expect("abc", p.getEncryptedKey().toString());
    expect("def", p.getInitializationVector().toString());
    expect("ghi", p.getCipherText().toString());
    expect("jkl", p.getAuthenticationTag().toString());


    p = new JWECryptoParts.noKey(null, null, new Base64URL("abc"), null);

    expect(p.getHeader(), isNull);
    expect(p.getEncryptedKey(), isNull);
    expect(p.getInitializationVector(), isNull);
    expect("abc", p.getCipherText().toString());
    expect(p.getAuthenticationTag(), isNull);
  });


  test('testConstructorWithHeader', () {

    JWEHeader header = new JWEHeader.minimal(JWEAlgorithm.A128KW, EncryptionMethod.A128GCM);

    JWECryptoParts p = new JWECryptoParts(
        header,
        new Base64URL("abc"),
        new Base64URL("def"),
        new Base64URL("ghi"),
        new Base64URL("jkl")
    );

    expect(header, p.getHeader());
    expect("abc", p.getEncryptedKey().toString());
    expect("def", p.getInitializationVector().toString());
    expect("ghi", p.getCipherText().toString());
    expect("jkl", p.getAuthenticationTag().toString());

    p = new JWECryptoParts(null, null, null, new Base64URL("abc"), null);

    expect(p.getHeader(), isNull);
    expect(p.getEncryptedKey(), isNull);
    expect(p.getInitializationVector(), isNull);
    expect("abc", p.getCipherText().toString());
    expect(p.getAuthenticationTag(), isNull);
  });

/*
*/
}
