library jose_jwt.test.jwk.ec_key_test.dart;

import 'dart:typed_data';
import 'package:unittest/unittest.dart';
import 'package:cipher/cipher.dart';
//import 'package:cipher/impl/server.dart';
import 'package:bignum/bignum.dart';
import 'package:jose_jwt/src/jwk.dart';
import 'package:jose_jwt/src/jose.dart';
//import 'package:jose_jwt/src/crypto.dart';
//import 'package:uuid/uuid.dart';
import 'package:jose_jwt/src/util.dart';

/**
 * Tests the EC JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-22)
 */
//public class ECKeyTest extends TestCase {

expectEquals(a, b) {
  return expect(a, equals(b));
}

expectNull(a) {
  return expect(a, isNull);
}

expectFalse(a) {
  return expect(a, isFalse);
}

expectTrue(a) {
  return expect(a, isTrue);
}

// Test parameters are from JWK spec
class _ExampleKeyP256 {

  static final ECKeyCurve CRV = ECKeyCurve.P_256;
  static final Base64URL X = new Base64URL("MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4");
  static final Base64URL Y = new Base64URL("4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM");
  static final Base64URL D = new Base64URL("870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE");
}

// Test parameters are from Anders Rundgren, public only
class _ExampleKeyP256Alt {

  static final ECKeyCurve CRV = ECKeyCurve.P_256;
  static final Base64URL X = new Base64URL("3l2Da_flYc-AuUTm2QzxgyvJxYM_2TeB9DMlwz7j1PE");
  static final Base64URL Y = new Base64URL("-kjT7Wrfhwsi9SG6H4UXiyUiVE9GHCLauslksZ3-_t0");
}

// Test parameters are from Anders Rundgren, public only
class _ExampleKeyP384Alt {

  static final ECKeyCurve CRV = ECKeyCurve.P_384;
  static final Base64URL X = new Base64URL("Xy0mn0LmRyDBeHBjZrqH9z5Weu5pzCZYl1FJGHdoEj1utAoCpD4-Wn3VAIT-qgFF");
  static final Base64URL Y = new Base64URL("mrZQ1aB1E7JksXe6LXmM3BiGzqtlwCtMN0cpJb5EU62JMSISSK8l7cXSFt84A25z");
}

// Test parameters are from Anders Rundgren, public only
class _ExampleKeyP521Alt {

  static final ECKeyCurve CRV = ECKeyCurve.P_521;
  static final Base64URL X = new Base64URL("AfwEaSkqoPQynn4SdAXOqbyDuK6KsbI04i-6aWvh3GdvREZuHaWFyg791gcvJ4OqG13-gzfYxZxfblPMqfOtQrzk");
  static final Base64URL Y = new Base64URL("AHgOZhhJb2ZiozkquiEa0Z9SfERJbWaaE7qEnCuk9VVZaWruKWKNzZadoIRPt8h305r14KRoxu8AfV20X-d_2Ups");
}


main() {

  test('testAltECKeyParamLengths', () {

    expectEquals(32, _ExampleKeyP256Alt.X.decode().length);
    expectEquals(32, _ExampleKeyP256Alt.Y.decode().length);

    expectEquals(48, _ExampleKeyP384Alt.X.decode().length);
    expectEquals(48, _ExampleKeyP384Alt.Y.decode().length);

    expectEquals(66, _ExampleKeyP521Alt.X.decode().length);
    expectEquals(66, _ExampleKeyP521Alt.Y.decode().length);
  });

  test('testCoordinateEncoding', () {

    Uint8List unpadded = [1, 2, 3, 4, 5];
    BigInteger bigInteger = new BigInteger(1, unpadded);

    // With no padding required
    int fieldSize = unpadded.length * 8;
    expectEquals(Base64URL.encodeBytes(unpadded), ECKey.encodeCoordinate(fieldSize, bigInteger));

    // With two leading zeros padding required
    fieldSize = unpadded.length * 8 + 2 * 8;
    expectEquals(Base64URL.encodeBytes(new Uint8List.fromList([ 0, 0, 1, 2, 3, 4, 5])), ECKey.encodeCoordinate(fieldSize, bigInteger));
    expectEquals(bigInteger.toString(), ECKey.encodeCoordinate(fieldSize, bigInteger).decodeToBigInteger().toString());
  });


  test('testFullConstructorAndSerialization', () {

    Uri x5u = Uri.parse("http://example.com/jwk.json");
    Base64URL x5t = new Base64URL("abc");
    List<Base64> x5c = new List();
    x5c.add(new Base64("def"));

    Set<KeyOperation> ops = null;

    ECKey key = new ECKey.keyPair(_ExampleKeyP256.CRV, _ExampleKeyP256.X, _ExampleKeyP256.Y, _ExampleKeyP256.D,
    KeyUse.SIGNATURE, ops, JWSAlgorithm.ES256, "1", x5u, x5t, x5c);

    // Test getters
    expectEquals(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());
    expectEquals(x5u.toString(), key.getX509CertURL().toString());
    expectEquals(x5t.toString(), key.getX509CertThumbprint().toString());
    expectEquals(x5c.length, key.getX509CertChain().length);

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectEquals(_ExampleKeyP256.D, key.getD());

    expectTrue(key.isPrivate());


    String jwkString = key.toJson().toString();

    key = ECKey.fromJsonString(jwkString);

    // Test getters
    expectEquals(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectEquals(_ExampleKeyP256.D, key.getD());

    expectTrue(key.isPrivate());


    // Test conversion to public JWK

    key = key.toPublicJWK();

    expectEquals(KeyUse.SIGNATURE, key.getKeyUse());
    expectNull(key.getKeyOperations());
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());
    expectEquals(x5u.toString(), key.getX509CertURL().toString());
    expectEquals(x5t.toString(), key.getX509CertThumbprint().toString());
    expectEquals(x5c.length, key.getX509CertChain().length);

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectNull(key.getD());

    expectFalse(key.isPrivate());
  });

  test('testFullConstructorAndSerializationWithOps', () {

    Uri x5u = Uri.parse("http://example.com/jwk.json");
    Base64URL x5t = new Base64URL("abc");
    List<Base64> x5c = new List();
    x5c.add(new Base64("def"));

    KeyUse use = null;
    Set<KeyOperation> ops = new Set.from([KeyOperation.SIGN, KeyOperation.VERIFY]);

    ECKey key = new ECKey.keyPair(_ExampleKeyP256.CRV, _ExampleKeyP256.X, _ExampleKeyP256.Y, _ExampleKeyP256.D,
    use, ops, JWSAlgorithm.ES256, "1", x5u, x5t, x5c);

    // Test getters
    expectNull(key.getKeyUse());
    expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
    expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
    expectEquals(2, key.getKeyOperations().length);
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());
    expectEquals(x5u.toString(), key.getX509CertURL().toString());
    expectEquals(x5t.toString(), key.getX509CertThumbprint().toString());
    expectEquals(x5c.length, key.getX509CertChain().length);

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectEquals(_ExampleKeyP256.D, key.getD());

    expectTrue(key.isPrivate());


    String jwkString = key.toJson().toString();

    key = ECKey.fromJsonString(jwkString);

    // Test getters
    expectNull(key.getKeyUse());
    expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
    expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
    expectEquals(2, key.getKeyOperations().length);
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectEquals(_ExampleKeyP256.D, key.getD());

    expectTrue(key.isPrivate());


    // Test conversion to public JWK

    key = key.toPublicJWK();

    expectNull(key.getKeyUse());
    expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
    expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
    expectEquals(2, key.getKeyOperations().length);
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());
    expectEquals(x5u.toString(), key.getX509CertURL().toString());
    expectEquals(x5t.toString(), key.getX509CertThumbprint().toString());
    expectEquals(x5c.length, key.getX509CertChain().length);

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectNull(key.getD());

    expectFalse(key.isPrivate());
  });

  test('testBuilder', () {

    Uri x5u = Uri.parse("http://example.com/jwk.json");
    Base64URL x5t = new Base64URL("abc");
    List<Base64> x5c = new List();
    x5c.add(new Base64("def"));

    ECKey key = new ECKeyBuilder(ECKeyCurve.P_256, _ExampleKeyP256.X, _ExampleKeyP256.Y).
    d(_ExampleKeyP256.D).
    keyUse(KeyUse.SIGNATURE).
    algorithm(JWSAlgorithm.ES256).
    keyID("1").
    x509CertURL(x5u).
    x509CertThumbprint(x5t).
    x509CertChain(x5c).
    build();

    // Test getters
    expectEquals(KeyUse.SIGNATURE, key.getKeyUse());
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());
    expectEquals(x5u.toString(), key.getX509CertURL().toString());
    expectEquals(x5t.toString(), key.getX509CertThumbprint().toString());
    expectEquals(x5c.length, key.getX509CertChain().length);

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectEquals(_ExampleKeyP256.D, key.getD());

    expectTrue(key.isPrivate());


    String jwkString = key.toJson().toString();

    key = ECKey.fromJsonString(jwkString);

    // Test getters
    expectEquals(KeyUse.SIGNATURE, key.getKeyUse());
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectEquals(_ExampleKeyP256.D, key.getD());

    expectTrue(key.isPrivate());


    // Test conversion to public JWK

    key = key.toPublicJWK();

    expectEquals(KeyUse.SIGNATURE, key.getKeyUse());
    expectEquals(JWSAlgorithm.ES256, key.getAlgorithm());
    expectEquals("1", key.getKeyID());
    expectEquals(x5u.toString(), key.getX509CertURL().toString());
    expectEquals(x5t.toString(), key.getX509CertThumbprint().toString());
    expectEquals(x5c.length, key.getX509CertChain().length);

    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectNull(key.getD());

    expectFalse(key.isPrivate());

  });

  test('testP256ExportAndImport', () {

    // Public + private

    ECKey key = new ECKeyBuilder(_ExampleKeyP256.CRV, _ExampleKeyP256.X, _ExampleKeyP256.Y).d(_ExampleKeyP256.D).build();

    // Export
    AsymmetricKeyPair pair = key.toKeyPair();

    ECPublicKey pub = pair.publicKey as ECPublicKey;
    expectEquals(256, pub.parameters.curve.fieldSize);
    expectEquals(_ExampleKeyP256.X.decodeToBigInteger(), pub.Q.x);
    expectEquals(_ExampleKeyP256.Y.decodeToBigInteger(), pub.Q.y);

    ECPrivateKey priv = pair.privateKey as ECPrivateKey;
    expectEquals(256, priv.parameters.curve.fieldSize);
    expectEquals(_ExampleKeyP256.D.decodeToBigInteger(), priv.d);

    // Import
    key = new ECKeyBuilder.pub(ECKeyCurve.P_256, pub).privateKey(priv).build();
    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256.X, key.getX());
    expectEquals(_ExampleKeyP256.Y, key.getY());
    expectEquals(_ExampleKeyP256.D, key.getD());
    expectEquals(32, _ExampleKeyP256.D.decode().length);

    expectTrue(key.isPrivate());
  });

  test('testP256AltExportAndImport', () {

    ECKey key = new ECKeyBuilder(_ExampleKeyP256Alt.CRV, _ExampleKeyP256Alt.X, _ExampleKeyP256Alt.Y).build();

    // Export
    AsymmetricKeyPair pair = key.toKeyPair();

    ECPublicKey pub = pair.publicKey as ECPublicKey;
    expectEquals(256, pub.parameters.curve.fieldSize);
    expectEquals(_ExampleKeyP256Alt.X.decodeToBigInteger(), pub.Q.x);
    expectEquals(_ExampleKeyP256Alt.Y.decodeToBigInteger(), pub.Q.x);

    // Import
    key = new ECKeyBuilder.pub(_ExampleKeyP256Alt.CRV, pub).build();
    expectEquals(ECKeyCurve.P_256, key.getCurve());
    expectEquals(_ExampleKeyP256Alt.X, key.getX());
    expectEquals(_ExampleKeyP256Alt.Y, key.getY());

    expectFalse(key.isPrivate());
  });

  test('testP384AltExportAndImport', () {

    ECKey key = new ECKeyBuilder(_ExampleKeyP384Alt.CRV, _ExampleKeyP384Alt.X, _ExampleKeyP384Alt.Y).build();

    // Export
    AsymmetricKeyPair pair = key.toKeyPair();

    ECPublicKey pub = pair.publicKey as ECPublicKey;
    expectEquals(384, pub.parameters.curve.fieldSize);
    expectEquals(_ExampleKeyP384Alt.X.decodeToBigInteger(), pub.Q.x);
    expectEquals(_ExampleKeyP384Alt.Y.decodeToBigInteger(), pub.Q.y);

    // Import
    key = new ECKeyBuilder.pub(_ExampleKeyP384Alt.CRV, pub).build();
    expectEquals(ECKeyCurve.P_384, key.getCurve());
    expectEquals(_ExampleKeyP384Alt.X, key.getX());
    expectEquals(_ExampleKeyP384Alt.Y, key.getY());

    expectFalse(key.isPrivate());
  });

  test('testP521AltExportAndImport', () {

    ECKey key = new ECKeyBuilder(_ExampleKeyP521Alt.CRV, _ExampleKeyP521Alt.X, _ExampleKeyP521Alt.Y).build();

    // Export
    AsymmetricKeyPair pair = key.toKeyPair();

    ECPublicKey pub = pair.publicKey as ECPublicKey;
    expectEquals(521, pub.parameters.curve.fieldSize);
    expectEquals(_ExampleKeyP521Alt.X.decodeToBigInteger(), pub.Q.x);
    expectEquals(_ExampleKeyP521Alt.Y.decodeToBigInteger(), pub.Q.y);

    // Import
    key = new ECKeyBuilder.pub(_ExampleKeyP521Alt.CRV, pub).build();
    expectEquals(ECKeyCurve.P_521, key.getCurve());
    expectEquals(_ExampleKeyP521Alt.X, key.getX());
    expectEquals(_ExampleKeyP521Alt.Y, key.getY());

    expectFalse(key.isPrivate());
  });

  test('testRejectKeyUseWithOps', () {

    KeyUse use = KeyUse.SIGNATURE;

    Set<KeyOperation> ops = new Set.from([KeyOperation.SIGN, KeyOperation.VERIFY]);

//    try {
    expect(() => new ECKey.key(_ExampleKeyP256.CRV, _ExampleKeyP256.X, _ExampleKeyP256.Y, use, ops, null, null, null, null, null),
    throwsA(new isInstanceOf<ArgumentError>()));

//      fail();
//    } catch (e) {
//      if (e is! ArgumentError) throw e;
//      // ok
//    }

//    try {
    expect(() => new ECKeyBuilder(_ExampleKeyP256.CRV, _ExampleKeyP256.X, _ExampleKeyP256.Y).
    keyUse(use).keyOperations(ops).build(),
    throwsA(new isInstanceOf<ArgumentError>()));
//      fail();
//    } catch (e) {
//      if (e is! StateError) throw e;
//      // ok
//    }
  });

  test('testCookbookExampleKey', () {

    // See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-3.3.1

    String json = "{" +
    "\"kty\":\"EC\"," +
    "\"kid\":\"bilbo.baggins@hobbiton.example\"," +
    "\"use\":\"sig\"," +
    "\"crv\":\"P-521\"," +
    "\"x\":\"AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
    "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt\"," +
    "\"y\":\"AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
    "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1\"," +
    "\"d\":\"AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
    "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt\"" +
    "}";

    ECKey jwk = ECKey.fromJsonString(json);

    expectEquals(KeyType.EC, jwk.getKeyType());
    expectEquals("bilbo.baggins@hobbiton.example", jwk.getKeyID());
    expectEquals(KeyUse.SIGNATURE, jwk.getKeyUse());
    expectEquals(ECKeyCurve.P_521, jwk.getCurve());

    expectEquals("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
    "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt", jwk.getX().toString());

    expectEquals("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
    "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1", jwk.getY().toString());

    expectEquals("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
    "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt", jwk.getD().toString());

    // Convert to Java EC key object
    ECPublicKey ecPublicKey = jwk.toECPublicKey();
    ECPrivateKey ecPrivateKey = jwk.toECPrivateKey();

    jwk = new ECKeyBuilder.pub(ECKeyCurve.P_521, ecPublicKey).privateKey(ecPrivateKey).build();

    expectEquals("AHKZLLOsCOzz5cY97ewNUajB957y-C-U88c3v13nmGZx6sYl_oJXu9" +
    "A5RkTKqjqvjyekWF-7ytDyRXYgCF5cj0Kt", jwk.getX().toString());

    expectEquals("AdymlHvOiLxXkEhayXQnNCvDX4h9htZaCJN34kfmC6pV5OhQHiraVy" +
    "SsUdaQkAgDPrwQrJmbnX9cwlGfP-HqHZR1", jwk.getY().toString());

    expectEquals("AAhRON2r9cqXX1hg-RoI6R1tX5p2rUAYdmpHZoC1XNM56KtscrX6zb" +
    "KipQrCW9CGZH3T4ubpnoTKLDYJ_fF3_rJt", jwk.getD().toString());
  });

}
