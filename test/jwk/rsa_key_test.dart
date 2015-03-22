library jose_jwt.test.jwk.rsa_key_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/jwk.dart';
import 'package:jose_jwt/src/util.dart';
import 'package:cipher/cipher.dart';

/**
 * Tests the RSA JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-21)
 */
//public class RSAKeyTest extends TestCase {
main() {

  expectNull(a) {
    return expect(a, isNull);
  }

  expectFalse(a) {
    return expect(a, isFalse);
  }

  expectTrue(a) {
    return expect(a, isTrue);
  }

  // Test parameters are from JPSK spec

  const String _n =
  "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx"
  "4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs"
  "tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2"
  "QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI"
  "SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb"
  "w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw";


  final String _e = "AQAB";


  const String _d =
  "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9"
  "M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij"
  "wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d"
  "_cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz"
  "nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz"
  "me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q";


  const String _p =
  "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV"
  "nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV"
  "WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs";


  const String _q =
  "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum"
  "qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx"
  "kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk";


  const String _dp =
  "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim"
  "YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu"
  "YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0";


  const String _dq =
  "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU"
  "vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9"
  "GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk";


  const String _qi =
  "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg"
  "UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx"
  "yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU";


  test('testFullConstructorAndSerialization', () {

    Uri x5u = Uri.parse("http://example.com/jwk.json");
    Base64URL x5t = new Base64URL("abc");
    List<Base64> x5c = new List();
    x5c.add(new Base64("def"));

    RSAKey key = new RSAKey(new Base64URL(_n), new Base64URL(_e), new Base64URL(_d),
    new Base64URL(_p), new Base64URL(_q),
    new Base64URL(_dp), new Base64URL(_dq), new Base64URL(_qi),
    null,
    KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
    x5u, x5t, x5c);

    // Test getters
    expect(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());
    expect(x5u.toString(), key.getX509CertURL().toString());
    expect(x5t.toString(), key.getX509CertThumbprint().toString());
    expect(x5c.length, key.getX509CertChain().length);

    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());

    expect(new Base64URL(_d), key.getPrivateExponent());

    expect(new Base64URL(_p), key.getFirstPrimeFactor());
    expect(new Base64URL(_q), key.getSecondPrimeFactor());

    expect(new Base64URL(_dp), key.getFirstFactorCRTExponent());
    expect(new Base64URL(_dq), key.getSecondFactorCRTExponent());

    expect(new Base64URL(_qi), key.getFirstCRTCoefficient());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());


    String jwkString = key.toJsonString();

    key = RSAKey.fromJsonString(jwkString);

    // Test getters
    expect(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());
    expect(x5u.toString(), key.getX509CertURL().toString());
    expect(x5t.toString(), key.getX509CertThumbprint().toString());
    expect(x5c.length, key.getX509CertChain().length);

    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());

    expect(new Base64URL(_d), key.getPrivateExponent());

    expect(new Base64URL(_p), key.getFirstPrimeFactor());
    expect(new Base64URL(_q), key.getSecondPrimeFactor());

    expect(new Base64URL(_dp), key.getFirstFactorCRTExponent());
    expect(new Base64URL(_dq), key.getSecondFactorCRTExponent());

    expect(new Base64URL(_qi), key.getFirstCRTCoefficient());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());


    // Test conversion to public JWK

    key = key.toPublicJWK();
    expect(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());

    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());

    expectNull(key.getPrivateExponent());

    expectNull(key.getFirstPrimeFactor());
    expectNull(key.getSecondPrimeFactor());

    expectNull(key.getFirstFactorCRTExponent());
    expectNull(key.getSecondFactorCRTExponent());

    expectNull(key.getFirstCRTCoefficient());

    expectTrue(key.getOtherPrimes().isEmpty);

    expect(key.isPrivate(), isFalse);
  });

  test('testBase64Builder', () {

    Uri x5u = Uri.parse("http://example.com/jwk.json");
    Base64URL x5t = new Base64URL("abc");
    List<Base64> x5c = new List();
    x5c.add(new Base64("def"));

    RSAKey key = new RSAKeyBuilder(new Base64URL(_n), new Base64URL(_e)).
    privateExponent(new Base64URL(_d)).
    firstPrimeFactor(new Base64URL(_p)).
    secondPrimeFactor(new Base64URL(_q)).
    firstFactorCRTExponent(new Base64URL(_dp)).
    secondFactorCRTExponent(new Base64URL(_dq)).
    firstCRTCoefficient(new Base64URL(_qi)).
    keyUse(KeyUse.SIGNATURE).
    algorithm(JWSAlgorithm.RS256).
    keyID("1").
    x509CertURL(x5u).
    x509CertThumbprint(x5t).
    x509CertChain(x5c).
    build();

    // Test getters
    expect(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());
    expect(x5u.toString(), key.getX509CertURL().toString());
    expect(x5t.toString(), key.getX509CertThumbprint().toString());
    expect(x5c.length, key.getX509CertChain().length);

    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());

    expect(new Base64URL(_d), key.getPrivateExponent());

    expect(new Base64URL(_p), key.getFirstPrimeFactor());
    expect(new Base64URL(_q), key.getSecondPrimeFactor());

    expect(new Base64URL(_dp), key.getFirstFactorCRTExponent());
    expect(new Base64URL(_dq), key.getSecondFactorCRTExponent());

    expect(new Base64URL(_qi), key.getFirstCRTCoefficient());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());


    String jwkString = key.toJsonString();

    key = RSAKey.fromJsonString(jwkString);

    // Test getters
    expect(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());
    expect(x5u.toString(), key.getX509CertURL().toString());
    expect(x5t.toString(), key.getX509CertThumbprint().toString());
    expect(x5c.length, key.getX509CertChain().length);

    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());

    expect(new Base64URL(_d), key.getPrivateExponent());

    expect(new Base64URL(_p), key.getFirstPrimeFactor());
    expect(new Base64URL(_q), key.getSecondPrimeFactor());

    expect(new Base64URL(_dp), key.getFirstFactorCRTExponent());
    expect(new Base64URL(_dq), key.getSecondFactorCRTExponent());

    expect(new Base64URL(_qi), key.getFirstCRTCoefficient());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());
  });


  test('testObjectBuilder', () {

    Uri x5u = Uri.parse("http://example.com/jwk.json");
    Base64URL x5t = new Base64URL("abc");
    List<Base64> x5c = new List();
    x5c.add(new Base64("def"));

    Set<KeyOperation> ops = [KeyOperation.SIGN, KeyOperation.VERIFY].toSet();

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);
    AsymmetricKeyPair keyPair = keyGen.genKeyPair();
    RSAPublicKey publicKey = keyPair.publicKey as RSAPublicKey;
    RSAPrivateKey privateKey = keyPair.privateKey as RSAPrivateKey;

    RSAKey key = new RSAKeyBuilder.publicKey(publicKey).
    privateKey(privateKey).
    keyUse(null).
    keyOperations(ops).
    algorithm(JWSAlgorithm.RS256).
    keyID("1").
    x509CertURL(x5u).
    x509CertThumbprint(x5t).
    x509CertChain(x5c).
    build();

    // Test getters
    expectNull(key.getKeyUse());
    expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
    expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
    expect(2, key.getKeyOperations().length);
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());
    expect(x5u.toString(), key.getX509CertURL().toString());
    expect(x5t.toString(), key.getX509CertThumbprint().toString());
    expect(x5c.length, key.getX509CertChain().length);

    expectTrue(publicKey.modulus == key.getModulus().decodeToBigInteger());
    expectTrue(publicKey.exponent == key.getPublicExponent().decodeToBigInteger());

    expectTrue(privateKey.exponent == key.getPrivateExponent().decodeToBigInteger());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());


    String jwkString = key.toJsonString();

    key = RSAKey.fromJsonString(jwkString);

    // Test getters
    expectNull(key.getKeyUse());
    expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
    expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
    expect(2, key.getKeyOperations().length);
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());
    expect(x5u.toString(), key.getX509CertURL().toString());
    expect(x5t.toString(), key.getX509CertThumbprint().toString());
    expect(x5c.length, key.getX509CertChain().length);

    expectTrue(publicKey.modulus == key.getModulus().decodeToBigInteger());
    expectTrue(publicKey.exponent == key.getPublicExponent().decodeToBigInteger());

    expectTrue(privateKey.exponent == key.getPrivateExponent().decodeToBigInteger());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());
  });

  test('testPublicKeyExportAndImport', () {

    RSAKey key = new RSAKey.publicKey(new Base64URL(_n), new Base64URL(_e),
    null, null, null, null,
    null, null, null);

    // Public key export
    RSAPublicKey pubKey = key.toRSAPublicKey();
    expect(new Base64URL(_n).decodeToBigInteger(), pubKey.modulus);
    expect(new Base64URL(_e).decodeToBigInteger(), pubKey.exponent);
    expect("RSA", pubKey.getAlgorithm());


    // Public key import
    key = new RSAKey.publicKey2(pubKey, null, null, null, null, null, null, null);
    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());
  });

  test('testPrivateKeyExportAndImport', () {

    RSAKey key = new RSAKey(new Base64URL(_n), new Base64URL(_e), new Base64URL(_d),
    new Base64URL(_p), new Base64URL(_q),
    new Base64URL(_dp), new Base64URL(_dq), new Base64URL(_qi),
    null,
    KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1",
    null, null, null);

    // Private key export with CRT (2nd form)
    RSAPrivateKey privKey = key.toRSAPrivateKey();
    expect(new Base64URL(_n).decodeToBigInteger(), privKey.modulus);
    expect(new Base64URL(_d).decodeToBigInteger(), privKey.exponent);

    expectTrue(privKey is RSAPrivateCrtKey);
    RSAPrivateCrtKey privCrtKey = privKey as RSAPrivateCrtKey;
    expect(new Base64URL(_e).decodeToBigInteger(), privCrtKey.getPublicExponent());
    expect(new Base64URL(_p).decodeToBigInteger(), privCrtKey.getPrimeP());
    expect(new Base64URL(_q).decodeToBigInteger(), privCrtKey.getPrimeQ());
    expect(new Base64URL(_dp).decodeToBigInteger(), privCrtKey.getPrimeExponentP());
    expect(new Base64URL(_dq).decodeToBigInteger(), privCrtKey.getPrimeExponentQ());
    expect(new Base64URL(_qi).decodeToBigInteger(), privCrtKey.getCrtCoefficient());


    // Key pair export
    KeyPair pair = key.toKeyPair();

    RSAPublicKey pubKey = pair.getPublic() as RSAPublicKey;
    expect(new Base64URL(_n).decodeToBigInteger(), pubKey.modulus);
    expect(new Base64URL(_e).decodeToBigInteger(), pubKey.exponent);
    expect("RSA", pubKey.getAlgorithm());

    privKey = pair.getPrivate() as RSAPrivateKey;
    expect(new Base64URL(_n).decodeToBigInteger(), privKey.modulus);
    expect(new Base64URL(_d).decodeToBigInteger(), privKey.exponent);

    expectTrue(privKey is RSAPrivateCrtKey);
    privCrtKey = privKey as RSAPrivateCrtKey;
    expect(new Base64URL(_e).decodeToBigInteger(), privCrtKey.getPublicExponent());
    expect(new Base64URL(_p).decodeToBigInteger(), privCrtKey.getPrimeP());
    expect(new Base64URL(_q).decodeToBigInteger(), privCrtKey.getPrimeQ());
    expect(new Base64URL(_dp).decodeToBigInteger(), privCrtKey.getPrimeExponentP());
    expect(new Base64URL(_dq).decodeToBigInteger(), privCrtKey.getPrimeExponentQ());
    expect(new Base64URL(_qi).decodeToBigInteger(), privCrtKey.getCrtCoefficient());


    // Key pair import, 1st private form
    key = new RSAKey.keyPair2(pubKey, privKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null, null);
    expect(KeyUse.SIGNATURE, key.getKeyUse());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());

    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());

    expect(new Base64URL(_d), key.getPrivateExponent());

    expectNull(key.getFirstPrimeFactor());
    expectNull(key.getSecondPrimeFactor());

    expectNull(key.getFirstFactorCRTExponent());
    expectNull(key.getSecondFactorCRTExponent());

    expectNull(key.getFirstCRTCoefficient());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());


    // Key pair import, 2nd private form
    key = new RSAKey.keyPair2(pubKey, privCrtKey, KeyUse.SIGNATURE, null, JWSAlgorithm.RS256, "1", null, null, null);
    expect(KeyUse.SIGNATURE, key.getKeyUse());
    expect(JWSAlgorithm.RS256, key.getAlgorithm());
    expect("1", key.getKeyID());

    expect(new Base64URL(_n), key.getModulus());
    expect(new Base64URL(_e), key.getPublicExponent());

    expect(new Base64URL(_d), key.getPrivateExponent());

    expect(new Base64URL(_p), key.getFirstPrimeFactor());
    expect(new Base64URL(_q), key.getSecondPrimeFactor());

    expect(new Base64URL(_dp), key.getFirstFactorCRTExponent());
    expect(new Base64URL(_dq), key.getSecondFactorCRTExponent());

    expect(new Base64URL(_qi), key.getFirstCRTCoefficient());

    expectTrue(key.getOtherPrimes().isEmpty);

    expectTrue(key.isPrivate());
  });

  test('testParseSomeKey', () {

    String json = "{\n" +
    "      \"kty\": \"RSA\",\n" +
    "      \"n\": \"f9BhJgBgoDKGcYLh+xl6qulS8fUFYxuWSz4Sk+7Yw2Wv4Wroe3yLzJjqEqH8IFR0Ow8Sr3pZo0IwOPcWHQZMQr0s2kWbKSpBrnDsK4vsdBvoP1jOaylA9XsHPF9EZ/1F+eQkVHoMsc9eccf0nmr3ubD56LjSorTsbOuxi8nqEzisvhDHthacW/qxbpR/jojQNfdWyDz6NC+MA2LYYpdsw5TG8AVdKjobHWfQvXYdcpvQRkDDhgbwQt1KD8ZJ1VL+nJcIfSppPzCbfM2eY78y/c4euL/SQPs7kGf+u3R9hden7FjMUuIFZoAictiBgjVZ/JOaK+C++L+IsnCKqauhEQ==\",\n" +
    "      \"e\": \"AQAB\",\n" +
    "      \"alg\": \"RS256\"\n" +
    "}";

    RSAKey key = RSAKey.fromJsonString(json);

    expect(JWSAlgorithm.RS256, key.getAlgorithm());

    expect(256, key.getModulus().decode().length);
  });

  test('testKeyConversionRoundTrip', () {

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);
    AsymmetricKeyPair<RSAPublicKey, RSAPrivateKey> keyPair = keyGen.genKeyPair();
    RSAPublicKey rsaPublicKeyIn = keyPair.publicKey;
    RSAPrivateKey rsaPrivateKeyIn = keyPair.privateKey;

    RSAKey rsaJWK = new RSAKeyBuilder(rsaPublicKeyIn).privateKey(rsaPrivateKeyIn).build();

    // Compare JWK values with original Java RSA values
    expect(rsaPublicKeyIn.exponent, rsaJWK.getPublicExponent().decodeToBigInteger());
    expect(rsaPublicKeyIn.modulus, rsaJWK.getModulus().decodeToBigInteger());
    expect(rsaPrivateKeyIn.exponent, rsaJWK.getPrivateExponent().decodeToBigInteger());

    // Convert back to Java RSA keys
    RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
    RSAPrivateKey rsaPrivateKeyOut = rsaJWK.toRSAPrivateKey();

    expect(rsaPublicKeyIn.getAlgorithm(), rsaPublicKeyOut.getAlgorithm());
    expect(rsaPublicKeyIn.exponent, rsaPublicKeyOut.exponent);
    expect(rsaPublicKeyIn.modulus, rsaPublicKeyOut.modulus);

    expect(rsaPrivateKeyIn.getAlgorithm(), rsaPrivateKeyOut.getAlgorithm());
    expect(rsaPrivateKeyIn.exponent, rsaPrivateKeyOut.exponent);

    // Compare encoded forms
//    expect("Public RSA", Base64.encodeString(rsaPublicKeyIn.getEncoded()).toString(), Base64.encode(rsaPublicKeyOut.getEncoded()).toString());
    expect("Public RSA", Base64.encodeString(rsaPublicKeyIn.getEncoded()).toString());
    expect("Public RSA", Base64.encodeString(rsaPublicKeyOut.getEncoded()).toString());
//    expect("Private RSA", Base64.encodeString(rsaPrivateKeyIn.getEncoded()).toString(), Base64.encode(rsaPrivateKeyOut.getEncoded()).toString());
    expect("Private RSA", Base64.encodeString(rsaPrivateKeyIn.getEncoded()).toString());
    expect("Private RSA", Base64.encodeString(rsaPrivateKeyOut.getEncoded()).toString());

    RSAKey rsaJWK2 = new RSAKeyBuilder(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

    // Compare JWK values with original Java RSA values
    expect(rsaPublicKeyIn.exponent, rsaJWK2.getPublicExponent().decodeToBigInteger());
    expect(rsaPublicKeyIn.modulus, rsaJWK2.getModulus().decodeToBigInteger());
    expect(rsaPrivateKeyIn.exponent, rsaJWK2.getPrivateExponent().decodeToBigInteger());
  });

  test('testKeyConversionRoundTripWithCRTParams', () {

    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
    keyGen.initialize(512);
    AsymmetricKeyPair keyPair = keyGen.genKeyPair();
    RSAPublicKey rsaPublicKeyIn = keyPair.publicKey as RSAPublicKey;
    RSAPrivateCrtKey rsaPrivateKeyIn = keyPair.privateKey as RSAPrivateCrtKey;

    RSAKey rsaJWK = new RSAKey.keyPair2(rsaPublicKeyIn, rsaPrivateKeyIn, null, null, null, null, null, null, null);

    // Compare JWK values with original Java RSA values
    expect(rsaPublicKeyIn.exponent, rsaJWK.getPublicExponent().decodeToBigInteger());
    expect(rsaPublicKeyIn.modulus, rsaJWK.getModulus().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK.getPrivateExponent().decodeToBigInteger());

    // Compare CRT params
    expect(rsaPrivateKeyIn.getPrimeP(), rsaJWK.getFirstPrimeFactor().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrimeQ(), rsaJWK.getSecondPrimeFactor().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrimeExponentP(), rsaJWK.getFirstFactorCRTExponent().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrimeExponentQ(), rsaJWK.getSecondFactorCRTExponent().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getCrtCoefficient(), rsaJWK.getFirstCRTCoefficient().decodeToBigInteger());
    expectTrue(rsaJWK.getOtherPrimes() == null || rsaJWK.getOtherPrimes().isEmpty);

    // Convert back to Java RSA keys
    RSAPublicKey rsaPublicKeyOut = rsaJWK.toRSAPublicKey();
    RSAPrivateCrtKey rsaPrivateKeyOut = rsaJWK.toRSAPrivateKey() as RSAPrivateCrtKey;

    expect(rsaPublicKeyIn.getAlgorithm(), rsaPublicKeyOut.getAlgorithm());
    expect(rsaPublicKeyIn.exponent, rsaPublicKeyOut.exponent);
    expect(rsaPublicKeyIn.modulus, rsaPublicKeyOut.modulus);

    expect(rsaPrivateKeyIn.getAlgorithm(), rsaPrivateKeyOut.getAlgorithm());
    expect(rsaPrivateKeyIn.getPrivateExponent(), rsaPrivateKeyOut.getPrivateExponent());

    expect(rsaPrivateKeyIn.getPrimeP(), rsaPrivateKeyOut.getPrimeP());
    expect(rsaPrivateKeyIn.getPrimeQ(), rsaPrivateKeyOut.getPrimeQ());
    expect(rsaPrivateKeyIn.getPrimeExponentP(), rsaPrivateKeyOut.getPrimeExponentP());
    expect(rsaPrivateKeyIn.getPrimeExponentQ(), rsaPrivateKeyOut.getPrimeExponentQ());
    expect(rsaPrivateKeyIn.getCrtCoefficient(), rsaPrivateKeyOut.getCrtCoefficient());

    // Compare encoded forms
//    expect("Public RSA", Base64.encode(rsaPublicKeyIn.getEncoded()).toString(), Base64.encode(rsaPublicKeyOut.getEncoded()).toString());
    expect("Public RSA", Base64.encodeString(rsaPublicKeyIn.getEncoded()).toString());
    expect("Public RSA", Base64.encodeString(rsaPublicKeyOut.getEncoded()).toString());
//    expect("Private RSA", Base64.encode(rsaPrivateKeyIn.getEncoded()).toString(), Base64.encode(rsaPrivateKeyOut.getEncoded()).toString());
    expect("Private RSA", Base64.encodeString(rsaPrivateKeyIn.getEncoded()).toString());
    expect("Private RSA", Base64.encodeString(rsaPrivateKeyOut.getEncoded()).toString());

    RSAKey rsaJWK2 = new RSAKeyBuilder.publicKey(rsaPublicKeyOut).privateKey(rsaPrivateKeyOut).build();

    // Compare JWK values with original Java RSA values
    expect(rsaPublicKeyIn.exponent, rsaJWK2.getPublicExponent().decodeToBigInteger());
    expect(rsaPublicKeyIn.modulus, rsaJWK2.getModulus().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrivateExponent(), rsaJWK2.getPrivateExponent().decodeToBigInteger());

    // Compare CRT params
    expect(rsaPrivateKeyIn.getPrimeP(), rsaJWK2.getFirstPrimeFactor().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrimeQ(), rsaJWK2.getSecondPrimeFactor().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrimeExponentP(), rsaJWK2.getFirstFactorCRTExponent().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getPrimeExponentQ(), rsaJWK2.getSecondFactorCRTExponent().decodeToBigInteger());
    expect(rsaPrivateKeyIn.getCrtCoefficient(), rsaJWK2.getFirstCRTCoefficient().decodeToBigInteger());
    expectTrue(rsaJWK2.getOtherPrimes() == null || rsaJWK2.getOtherPrimes().isEmpty);
  });

  test('testRejectKeyUseWithOps', () {

    KeyUse use = KeyUse.SIGNATURE;

    Set<KeyOperation> ops = [KeyOperation.SIGN, KeyOperation.VERIFY].toSet();

//		try {
    expect(() =>
    new RSAKey.publicKey(new Base64URL(_n), new Base64URL(_e), use, ops, null, null, null, null, null),
    throwsA(new isInstanceOf<ArgumentError>()));

//    fail();
//		} catch (IllegalArgumentException e) {
//			// ok
//		}

//		try {
    expect(() =>
    new RSAKeyBuilder(new Base64URL(_n), new Base64URL(_e)).
    keyUse(use).keyOperations(ops).build(),
    throwsA(new isInstanceOf<StateError>()));
//    fail();
//		} catch (IllegalStateException e) {
//			// ok
//		}
  });

  test('testParseCookbookExample', () {

    // See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-3.1.1

    String json = "{" +
    "\"kty\": \"RSA\"," +
    "\"kid\": \"bilbo.baggins@hobbiton.example\"," +
    "\"use\": \"sig\"," +
    "\"n\": \"n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
    "HdrNP5zw\"," +
    "\"e\": \"AQAB\"," +
    "\"d\": \"bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
    "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
    "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
    "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
    "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
    "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
    "OpBrQzwQ\"," +
    "\"p\": \"3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
    "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
    "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
    "bUq0k\"," +
    "\"q\": \"uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
    "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
    "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
    "s7pFc\"," +
    "\"dp\": \"B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
    "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
    "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
    "59ehik\"," +
    "\"dq\": \"CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
    "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
    "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
    "T1cYF8\"," +
    "\"qi\": \"3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
    "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
    "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
    "z8aaI4\"" +
    "}";

    RSAKey jwk = RSAKey.fromJsonString(json);

    expect(KeyType.RSA, jwk.getKeyType());
    expect("bilbo.baggins@hobbiton.example", jwk.getKeyID());
    expect(KeyUse.SIGNATURE, jwk.getKeyUse());

    expect("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
    "HdrNP5zw", jwk.getModulus().toString());

    expect("AQAB", jwk.getPublicExponent().toString());

    expect("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
    "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
    "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
    "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
    "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
    "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
    "OpBrQzwQ", jwk.getPrivateExponent().toString());

    expect("3Slxg_DwTXJcb6095RoXygQCAZ5RnAvZlno1yhHtnUex_fp7AZ_9nR" +
    "aO7HX_-SFfGQeutao2TDjDAWU4Vupk8rw9JR0AzZ0N2fvuIAmr_WCsmG" +
    "peNqQnev1T7IyEsnh8UMt-n5CafhkikzhEsrmndH6LxOrvRJlsPp6Zv8" +
    "bUq0k", jwk.getFirstPrimeFactor().toString());

    expect("uKE2dh-cTf6ERF4k4e_jy78GfPYUIaUyoSSJuBzp3Cubk3OCqs6grT" +
    "8bR_cu0Dm1MZwWmtdqDyI95HrUeq3MP15vMMON8lHTeZu2lmKvwqW7an" +
    "V5UzhM1iZ7z4yMkuUwFWoBvyY898EXvRD-hdqRxHlSqAZ192zB3pVFJ0" +
    "s7pFc", jwk.getSecondPrimeFactor().toString());

    expect("B8PVvXkvJrj2L-GYQ7v3y9r6Kw5g9SahXBwsWUzp19TVlgI-YV85q" +
    "1NIb1rxQtD-IsXXR3-TanevuRPRt5OBOdiMGQp8pbt26gljYfKU_E9xn" +
    "-RULHz0-ed9E9gXLKD4VGngpz-PfQ_q29pk5xWHoJp009Qf1HvChixRX" +
    "59ehik", jwk.getFirstFactorCRTExponent().toString());

    expect("CLDmDGduhylc9o7r84rEUVn7pzQ6PF83Y-iBZx5NT-TpnOZKF1pEr" +
    "AMVeKzFEl41DlHHqqBLSM0W1sOFbwTxYWZDm6sI6og5iTbwQGIC3gnJK" +
    "bi_7k_vJgGHwHxgPaX2PnvP-zyEkDERuf-ry4c_Z11Cq9AqC2yeL6kdK" +
    "T1cYF8", jwk.getSecondFactorCRTExponent().toString());

    expect("3PiqvXQN0zwMeE-sBvZgi289XP9XCQF3VWqPzMKnIgQp7_Tugo6-N" +
    "ZBKCQsMf3HaEGBjTVJs_jcK8-TRXvaKe-7ZMaQj8VfBdYkssbu0NKDDh" +
    "jJ-GtiseaDVWt7dcH0cfwxgFUHpQh7FoCrjFJ6h6ZEpMF6xmujs4qMpP" +
    "z8aaI4", jwk.getFirstCRTCoefficient().toString());

    // Convert to Java RSA key object
    RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
    RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

    jwk = new RSAKeyBuilder.publicKey(rsaPublicKey).privateKey(rsaPrivateKey).build();

    expect("n4EPtAOCc9AlkeQHPzHStgAbgs7bTZLwUBZdR8_KuKPEHLd4rHVTeT" +
    "-O-XV2jRojdNhxJWTDvNd7nqQ0VEiZQHz_AJmSCpMaJMRBSFKrKb2wqV" +
    "wGU_NsYOYL-QtiWN2lbzcEe6XC0dApr5ydQLrHqkHHig3RBordaZ6Aj-" +
    "oBHqFEHYpPe7Tpe-OfVfHd1E6cS6M1FZcD1NNLYD5lFHpPI9bTwJlsde" +
    "3uhGqC0ZCuEHg8lhzwOHrtIQbS0FVbb9k3-tVTU4fg_3L_vniUFAKwuC" +
    "LqKnS2BYwdq_mzSnbLY7h_qixoR7jig3__kRhuaxwUkRz5iaiQkqgc5g" +
    "HdrNP5zw", jwk.getModulus().toString());

    expect("AQAB", jwk.getPublicExponent().toString());

    expect("bWUC9B-EFRIo8kpGfh0ZuyGPvMNKvYWNtB_ikiH9k20eT-O1q_I78e" +
    "iZkpXxXQ0UTEs2LsNRS-8uJbvQ-A1irkwMSMkK1J3XTGgdrhCku9gRld" +
    "Y7sNA_AKZGh-Q661_42rINLRCe8W-nZ34ui_qOfkLnK9QWDDqpaIsA-b" +
    "MwWWSDFu2MUBYwkHTMEzLYGqOe04noqeq1hExBTHBOBdkMXiuFhUq1BU" +
    "6l-DqEiWxqg82sXt2h-LMnT3046AOYJoRioz75tSUQfGCshWTBnP5uDj" +
    "d18kKhyv07lhfSJdrPdM5Plyl21hsFf4L_mHCuoFau7gdsPfHPxxjVOc" +
    "OpBrQzwQ", jwk.getPrivateExponent().toString());
  });

  test('testParseCookbookExample2', () {

    // See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-4.1.1

    String json = "{" +
    "\"kty\":\"RSA\"," +
    "\"kid\":\"frodo.baggins@hobbiton.example\"," +
    "\"use\":\"enc\"," +
    "\"n\":\"maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
    "HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
    "6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
    "NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
    "R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
    "pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
    "VotGlvMQ\"," +
    "\"e\":\"AQAB\"," +
    "\"d\":\"Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
    "bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
    "5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
    "Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
    "1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
    "miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
    "pzj85bQQ\"," +
    "\"p\":\"2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE" +
    "oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH" +
    "7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ" +
    "2VFmU\"," +
    "\"q\":\"te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V" +
    "F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb" +
    "9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8" +
    "d6Et0\"," +
    "\"dp\":\"UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH" +
    "QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV" +
    "RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf" +
    "lo0rYU\"," +
    "\"dq\":\"iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb" +
    "pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A" +
    "CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14" +
    "TkXlHE\"," +
    "\"qi\":\"kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ" +
    "lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7" +
    "Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx" +
    "2bQ_mM\"" +
    "}";

    RSAKey jwk = RSAKey.fromJsonString(json);

    expect(KeyType.RSA, jwk.getKeyType());
    expect("frodo.baggins@hobbiton.example", jwk.getKeyID());
    expect(KeyUse.ENCRYPTION, jwk.getKeyUse());

    expect("maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
    "HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
    "6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
    "NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
    "R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
    "pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
    "VotGlvMQ", jwk.getModulus().toString());

    expect("AQAB", jwk.getPublicExponent().toString());

    expect("Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
    "bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
    "5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
    "Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
    "1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
    "miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
    "pzj85bQQ", jwk.getPrivateExponent().toString());

    expect("2DwQmZ43FoTnQ8IkUj3BmKRf5Eh2mizZA5xEJ2MinUE3sdTYKSLtaE" +
    "oekX9vbBZuWxHdVhM6UnKCJ_2iNk8Z0ayLYHL0_G21aXf9-unynEpUsH" +
    "7HHTklLpYAzOOx1ZgVljoxAdWNn3hiEFrjZLZGS7lOH-a3QQlDDQoJOJ" +
    "2VFmU", jwk.getFirstPrimeFactor().toString());

    expect("te8LY4-W7IyaqH1ExujjMqkTAlTeRbv0VLQnfLY2xINnrWdwiQ93_V" +
    "F099aP1ESeLja2nw-6iKIe-qT7mtCPozKfVtUYfz5HrJ_XY2kfexJINb" +
    "9lhZHMv5p1skZpeIS-GPHCC6gRlKo1q-idn_qxyusfWv7WAxlSVfQfk8" +
    "d6Et0", jwk.getSecondPrimeFactor().toString());

    expect("UfYKcL_or492vVc0PzwLSplbg4L3-Z5wL48mwiswbpzOyIgd2xHTH" +
    "QmjJpFAIZ8q-zf9RmgJXkDrFs9rkdxPtAsL1WYdeCT5c125Fkdg317JV" +
    "RDo1inX7x2Kdh8ERCreW8_4zXItuTl_KiXZNU5lvMQjWbIw2eTx1lpsf" +
    "lo0rYU", jwk.getFirstFactorCRTExponent().toString());

    expect("iEgcO-QfpepdH8FWd7mUFyrXdnOkXJBCogChY6YKuIHGc_p8Le9Mb" +
    "pFKESzEaLlN1Ehf3B6oGBl5Iz_ayUlZj2IoQZ82znoUrpa9fVYNot87A" +
    "CfzIG7q9Mv7RiPAderZi03tkVXAdaBau_9vs5rS-7HMtxkVrxSUvJY14" +
    "TkXlHE", jwk.getSecondFactorCRTExponent().toString());

    expect("kC-lzZOqoFaZCr5l0tOVtREKoVqaAYhQiqIRGL-MzS4sCmRkxm5vZ" +
    "lXYx6RtE1n_AagjqajlkjieGlxTTThHD8Iga6foGBMaAr5uR1hGQpSc7" +
    "Gl7CF1DZkBJMTQN6EshYzZfxW08mIO8M6Rzuh0beL6fG9mkDcIyPrBXx" +
    "2bQ_mM", jwk.getFirstCRTCoefficient().toString());

    // Convert to Java RSA key object
    RSAPublicKey rsaPublicKey = jwk.toRSAPublicKey();
    RSAPrivateKey rsaPrivateKey = jwk.toRSAPrivateKey();

    jwk = new RSAKeyBuilder.publicKey(rsaPublicKey).privateKey(rsaPrivateKey).build();

    expect("maxhbsmBtdQ3CNrKvprUE6n9lYcregDMLYNeTAWcLj8NnPU9XIYegT" +
    "HVHQjxKDSHP2l-F5jS7sppG1wgdAqZyhnWvXhYNvcM7RfgKxqNx_xAHx" +
    "6f3yy7s-M9PSNCwPC2lh6UAkR4I00EhV9lrypM9Pi4lBUop9t5fS9W5U" +
    "NwaAllhrd-osQGPjIeI1deHTwx-ZTHu3C60Pu_LJIl6hKn9wbwaUmA4c" +
    "R5Bd2pgbaY7ASgsjCUbtYJaNIHSoHXprUdJZKUMAzV0WOKPfA6OPI4oy" +
    "pBadjvMZ4ZAj3BnXaSYsEZhaueTXvZB4eZOAjIyh2e_VOIKVMsnDrJYA" +
    "VotGlvMQ", jwk.getModulus().toString());

    expect("AQAB", jwk.getPublicExponent().toString());

    expect("Kn9tgoHfiTVi8uPu5b9TnwyHwG5dK6RE0uFdlpCGnJN7ZEi963R7wy" +
    "bQ1PLAHmpIbNTztfrheoAniRV1NCIqXaW_qS461xiDTp4ntEPnqcKsyO" +
    "5jMAji7-CL8vhpYYowNFvIesgMoVaPRYMYT9TW63hNM0aWs7USZ_hLg6" +
    "Oe1mY0vHTI3FucjSM86Nff4oIENt43r2fspgEPGRrdE6fpLc9Oaq-qeP" +
    "1GFULimrRdndm-P8q8kvN3KHlNAtEgrQAgTTgz80S-3VD0FgWfgnb1PN" +
    "miuPUxO8OpI9KDIfu_acc6fg14nsNaJqXe6RESvhGPH2afjHqSy_Fd2v" +
    "pzj85bQQ", jwk.getPrivateExponent().toString());
  });

}
