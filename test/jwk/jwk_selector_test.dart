library jose_jwt.test.jwk.jwk_selector_test;

import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jwk.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/util.dart';

/**
 * Tests the JWK selector.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-03)
 */
//public class JWKSelectorTest extends TestCase {
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

  test('testConstructor', () {

    JWKSelector selector = new JWKSelector();

    expectNull(selector.getKeyTypes());
    expectNull(selector.getKeyUses());
    expectNull(selector.getKeyOperations());
    expectNull(selector.getAlgorithms());
    expectNull(selector.getKeyIDs());
    expectFalse(selector.isPrivateOnly());
    expectFalse(selector.isPublicOnly());
  });

  test('testPrivateAndPublicOnlySetters', () {

    JWKSelector selector = new JWKSelector();

    expectFalse(selector.isPrivateOnly());
    expectFalse(selector.isPublicOnly());

    selector.setPrivateOnly(true);
    expectTrue(selector.isPrivateOnly());

    selector.setPublicOnly(true);
    expectTrue(selector.isPublicOnly());
  });

  test('testSetSetters', () {

    JWKSelector selector = new JWKSelector();

    Set<KeyType> types = new Set();
    types.add(KeyType.RSA);
    selector.setKeyTypes(types);
    expect(types, selector.getKeyTypes());

    Set<KeyUse> uses = new Set();
    uses.add(KeyUse.SIGNATURE);
    selector.setKeyUses(uses);
    expect(uses, selector.getKeyUses());

    Set<KeyOperation> ops = new Set();
    ops.add(KeyOperation.SIGN);
    ops.add(KeyOperation.VERIFY);
    selector.setKeyOperations(ops);
    expect(ops, selector.getKeyOperations());

    Set<Algorithm> algs = new Set();
    algs.add(JWSAlgorithm.PS256);
    selector.setAlgorithms(algs);
    expect(algs, selector.getAlgorithms());

    Set<String> ids = new Set();
    ids.add("1");
    selector.setKeyIDs(ids);
    expect(ids, selector.getKeyIDs());
  });

  test('testVarArgSetters', () {

    JWKSelector selector = new JWKSelector();

    selector.setKeyTypes([KeyType.EC, KeyType.RSA, null].toSet());
    Set<KeyType> types = selector.getKeyTypes();
    expectTrue(types.containsAll([KeyType.EC, KeyType.RSA, null]));
    expect(3, types.length);

    selector.setKeyUses([KeyUse.SIGNATURE, null].toSet());
    Set<KeyUse> uses = selector.getKeyUses();
    expectTrue(uses.containsAll([KeyUse.SIGNATURE, null]));
    expect(2, uses.length);

    selector.setKeyOperations([KeyOperation.SIGN, null].toSet());
    Set<KeyOperation> ops = selector.getKeyOperations();
    expectTrue(ops.containsAll([KeyOperation.SIGN, null]));
    expect(2, ops.length);

    selector.setAlgorithms([JWSAlgorithm.RS256, JWSAlgorithm.PS256].toSet());
    Set<Algorithm> algs = selector.getAlgorithms();
    expectTrue(algs.containsAll([JWSAlgorithm.RS256, JWSAlgorithm.PS256]));
    expect(2, algs.length);

    selector.setKeyIDs(["1", "2", "3", null].toSet());
    Set<String> ids = selector.getKeyIDs();
    expectTrue(ids.containsAll(["1", "2", "3", null]));
    expect(4, ids.length);
  });

  test('testSelectFromNullSet', () {

    List<JWK> matches = new JWKSelector().select(null);

    expectTrue(matches.isEmpty);
  });

  test('testSelectFromEmptySet', () {

    List<JWK> matches = new JWKSelector().select(new JWKSet());

    expectTrue(matches.isEmpty);
  });

  test('testMatchType', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyType(KeyType.RSA);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect(KeyType.RSA, key1.getKeyType());
    expect("1", key1.getKeyID());

    expect(1, matches.length);
  });

  test('testMatchTwoTypes', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyTypes([KeyType.RSA, KeyType.EC].toSet());

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect(KeyType.RSA, key1.getKeyType());
    expect("1", key1.getKeyID());

    ECKey key2 = matches[1] as ECKey;
    expect(KeyType.EC, key2.getKeyType());
    expect("2", key2.getKeyID());

    expect(2, matches.length);
  });

  test('testMatchUse', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyUse(KeyUse.ENCRYPTION);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.ENCRYPTION).build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect(KeyType.RSA, key1.getKeyType());
    expect(KeyUse.ENCRYPTION, key1.getKeyUse());
    expect("1", key1.getKeyID());

    expect(1, matches.length);
  });

  test('testMatchUseNotSpecifiedOrSignature', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyUses([KeyUse.SIGNATURE, null].toSet());

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.SIGNATURE).build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3").keyUse(KeyUse.ENCRYPTION).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect(KeyType.RSA, key1.getKeyType());
    expect(KeyUse.SIGNATURE, key1.getKeyUse());
    expect("1", key1.getKeyID());

    ECKey key2 = matches[1] as ECKey;
    expect(KeyType.EC, key2.getKeyType());
    expect("2", key2.getKeyID());

    expect(2, matches.length);
  });

  test('testMatchOperations', () {

    JWKSelector selector = new JWKSelector();
    Set<KeyOperation> ops = [KeyOperation.SIGN, KeyOperation.VERIFY].toSet();
    selector.setKeyOperations(ops);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1")
    .keyOperations(new Set.from([KeyOperation.SIGN, KeyOperation.VERIFY])).build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect(KeyType.RSA, key1.getKeyType());
    expect("1", key1.getKeyID());

    expect(1, matches.length);
  });

  test('testMatchOperationsNotSpecifiedOrSign', () {

    JWKSelector selector = new JWKSelector();
    Set<KeyOperation> ops = [KeyOperation.SIGN, null].toSet();
    selector.setKeyOperations(ops);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1")
    .keyOperations(new Set.from([KeyOperation.SIGN])).build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("2").build());
    keyList.add(new ECKeyBuilder(ECKeyCurve.P_256, new Base64URL("x"), new Base64URL("y")).keyID("3")
    .keyOperations(new Set.from([KeyOperation.ENCRYPT])).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect(KeyType.RSA, key1.getKeyType());
    expect("1", key1.getKeyID());

    ECKey key2 = matches[1] as ECKey;
    expect(KeyType.EC, key2.getKeyType());
    expect("2", key2.getKeyID());

    expect(2, matches.length);
  });

  test('testMatchAlgorithm', () {

    JWKSelector selector = new JWKSelector();
    selector.setAlgorithm(JWSAlgorithm.RS256);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.PS256).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect(KeyType.RSA, key1.getKeyType());
    expect(JWSAlgorithm.RS256, key1.getAlgorithm());
    expect("1", key1.getKeyID());

    expect(1, matches.length);
  });

  test('testMatchID', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyID("1");

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect("1", key1.getKeyID());

    expect(1, matches.length);
  });

  test('testMatchAnyID', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyID(null);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect("1", key1.getKeyID());

    RSAKey key2 = matches[1] as RSAKey;
    expect("2", key2.getKeyID());

    expect(2, matches.length);
  });

  test('testNoMatchesByID', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyID("1");

    RSAKey key = new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("2").build();

    JWKSet jwkSet = new JWKSet.fromKey(key);

    List<JWK> matches = selector.select(jwkSet);

    expectTrue(matches.isEmpty);
  });

  test('testMatchPrivateOnly', () {

    JWKSelector selector = new JWKSelector();
    selector.setPrivateOnly(true);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
    keyList.add(new OctetSequenceKeyBuilder(new Base64URL("k")).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    OctetSequenceKey key1 = matches[0] as OctetSequenceKey;
    expect("k", key1.getKeyValue().toString());

    expect(1, matches.length);
  });

  test('testMatchPublicOnly', () {

    JWKSelector selector = new JWKSelector();
    selector.setPublicOnly(true);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").algorithm(JWSAlgorithm.RS256).build());
    keyList.add(new OctetSequenceKeyBuilder(new Base64URL("k")).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect("1", key1.getKeyID());

    expect(1, matches.length);
  });

  test('testMatchComplex', () {

    JWKSelector selector = new JWKSelector();
    selector.setKeyType(KeyType.RSA);
    selector.setKeyUse(KeyUse.SIGNATURE);
    selector.setAlgorithm(JWSAlgorithm.RS256);
    selector.setKeyID("1");
    selector.setPublicOnly(true);

    List<JWK> keyList = new List();
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("1").keyUse(KeyUse.SIGNATURE).algorithm(JWSAlgorithm.RS256).build());
    keyList.add(new RSAKeyBuilder(new Base64URL("n"), new Base64URL("e")).keyID("2").algorithm(JWSAlgorithm.RS256).build());

    JWKSet jwkSet = new JWKSet.fromKeys(keyList);

    List<JWK> matches = selector.select(jwkSet);

    RSAKey key1 = matches[0] as RSAKey;
    expect("1", key1.getKeyID());

    expect(1, matches.length);
  });

}

