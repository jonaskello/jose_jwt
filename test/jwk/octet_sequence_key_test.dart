library jose_jwt.test.jwk.octet_sequence_key_test;

import 'dart:typed_data';
import 'package:unittest/unittest.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/jwk.dart';

/**
 * Tests the Octet Sequence JWK class.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-01-20)
 */
//public class OctetSequenceKeyTest extends TestCase {
main() {

  expectNull(a) {
    return expect(a, isNull);
  }

  expectTrue(a) {
    return expect(a, isTrue);
  }


  test('testConstructorAndSerialization', () {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		Uri x5u = Uri.parse("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new List();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = [KeyOperation.SIGN, KeyOperation.VERIFY].toSet();

		OctetSequenceKey key = new OctetSequenceKey(k, null, ops, JWSAlgorithm.HS256, "1", x5u, x5t, x5c);

		expect(KeyType.OCT, key.getKeyType());
		expect(key.getKeyUse(), isNull);
		expect(key.getKeyOperations().contains(KeyOperation.SIGN), isTrue);
		expect(key.getKeyOperations().contains(KeyOperation.VERIFY), isTrue);
		expect(2, key.getKeyOperations().length);
		expect(JWSAlgorithm.HS256, key.getAlgorithm());
		expect("1", key.getKeyID());
		expect(x5u.toString(), key.getX509CertURL().toString());
		expect(x5t.toString(), key.getX509CertThumbprint().toString());
		expect(x5c.length, key.getX509CertChain().length);

		expect(k, key.getKeyValue());

		Uint8List keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			expect(keyBytes[i], key.toByteArray()[i]);
		}

		expectNull(key.toPublicJWK());

		expectTrue(key.isPrivate());

		String jwkString = key.toJsonString();

		key = OctetSequenceKey.fromJsonString(jwkString);

		expect(KeyType.OCT, key.getKeyType());
		expectNull(key.getKeyUse());
		expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		expect(2, key.getKeyOperations().length);
		expect(JWSAlgorithm.HS256, key.getAlgorithm());
		expect("1", key.getKeyID());
		expect(x5u.toString(), key.getX509CertURL().toString());
		expect(x5t.toString(), key.getX509CertThumbprint().toString());
		expect(x5c.length, key.getX509CertChain().length);

		expect(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			expect(keyBytes[i], key.toByteArray()[i]);

		}

		expectNull(key.toPublicJWK());

		expectTrue(key.isPrivate());

  });

  test('testAltConstructorAndSerialization', () {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		Uri x5u = Uri.parse("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new List();
		x5c.add(new Base64("def"));

		OctetSequenceKey key = new OctetSequenceKey(k, KeyUse.SIGNATURE, null, JWSAlgorithm.HS256, "1", x5u, x5t, x5c);

		expect(KeyType.OCT, key.getKeyType());
		expect(KeyUse.SIGNATURE, key.getKeyUse());
		expectNull(key.getKeyOperations());
		expect(JWSAlgorithm.HS256, key.getAlgorithm());
		expect("1", key.getKeyID());
		expect(x5u.toString(), key.getX509CertURL().toString());
		expect(x5t.toString(), key.getX509CertThumbprint().toString());
		expect(x5c.length, key.getX509CertChain().length);

		expect(k, key.getKeyValue());

		Uint8List keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			expect(keyBytes[i], key.toByteArray()[i]);
		}

		expectNull(key.toPublicJWK());

		expectTrue(key.isPrivate());

		String jwkString = key.toJsonString();

		key = OctetSequenceKey.fromJsonString(jwkString);

		expect(KeyType.OCT, key.getKeyType());
		expect(KeyUse.SIGNATURE, key.getKeyUse());
		expectNull(key.getKeyOperations());
		expect(JWSAlgorithm.HS256, key.getAlgorithm());
		expect("1", key.getKeyID());
		expect(x5u.toString(), key.getX509CertURL().toString());
		expect(x5t.toString(), key.getX509CertThumbprint().toString());
		expect(x5c.length, key.getX509CertChain().length);

		expect(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {

			expect(keyBytes[i], key.toByteArray()[i]);

		}

		expectNull(key.toPublicJWK());

		expectTrue(key.isPrivate());
  });

  test('testRejectUseAndOpsTogether', () {

		Set<KeyOperation> ops =  [KeyOperation.SIGN, KeyOperation.VERIFY].toSet();

//		try {
			new OctetSequenceKey(new Base64URL("GawgguFyGrWKav7AX4VKUg"), KeyUse.SIGNATURE, ops, null, null, null, null, null);
			fail("");
//		} catch (IllegalArgumentException e) {
//			// ok
//		}
  });

  test('testBuilder', () {

		Base64URL k = new Base64URL("GawgguFyGrWKav7AX4VKUg");
		Uri x5u = Uri.parse("http://example.com/jwk.json");
		Base64URL x5t = new Base64URL("abc");
		List<Base64> x5c = new List();
		x5c.add(new Base64("def"));

		Set<KeyOperation> ops = [KeyOperation.SIGN, KeyOperation.VERIFY].toSet();

		OctetSequenceKey key = new OctetSequenceKeyBuilder(k).
			keyOperations(ops).
			algorithm(JWSAlgorithm.HS256).
			keyID("1").
			x509CertURL(x5u).
			x509CertThumbprint(x5t).
			x509CertChain(x5c).
			build();

		expect(KeyType.OCT, key.getKeyType());
		expectNull(key.getKeyUse());
		expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		expect(2, key.getKeyOperations().length);
		expect(JWSAlgorithm.HS256, key.getAlgorithm());
		expect("1", key.getKeyID());
		expect(x5u.toString(), key.getX509CertURL().toString());
		expect(x5t.toString(), key.getX509CertThumbprint().toString());
		expect(x5c.length, key.getX509CertChain().length);

		expect(k, key.getKeyValue());

		Uint8List keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			expect(keyBytes[i], key.toByteArray()[i]);
		}

		expectNull(key.toPublicJWK());

		expectTrue(key.isPrivate());


		String jwkString = key.toJsonString();

		key = OctetSequenceKey.fromJsonString(jwkString);


		expect(KeyType.OCT, key.getKeyType());
		expectNull(key.getKeyUse());
		expectTrue(key.getKeyOperations().contains(KeyOperation.SIGN));
		expectTrue(key.getKeyOperations().contains(KeyOperation.VERIFY));
		expect(2, key.getKeyOperations().length);
		expect(JWSAlgorithm.HS256, key.getAlgorithm());
		expect("1", key.getKeyID());
		expect(x5u.toString(), key.getX509CertURL().toString());
		expect(x5t.toString(), key.getX509CertThumbprint().toString());
		expect(x5c.length, key.getX509CertChain().length);

		expect(k, key.getKeyValue());

		keyBytes = k.decode();

		for (int i=0; i < keyBytes.length; i++) {
			expect(keyBytes[i], key.toByteArray()[i]);
		}

		expectNull(key.toPublicJWK());

		expectTrue(key.isPrivate());
  });

  test('testBuilderWithByteArray', () {

		Uint8List key = new Uint8List(32);
		new SecureRandom().nextBytes(key);

		OctetSequenceKey oct = new OctetSequenceKeyBuilder.fromBytes(key).build();

		expect(Base64URL.encodeBytes(key), oct.getKeyValue());
  });

  test('testCookbookHMACKeyExample', () {

		// See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-3.4.1
		
		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"018c0ae5-4d9b-471b-bfd6-eef314bc7037\","+
			"\"use\":\"sig\","+
			"\"k\":\"hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.fromJsonString(json);

		expect(KeyType.OCT, jwk.getKeyType());
		expect("018c0ae5-4d9b-471b-bfd6-eef314bc7037", jwk.getKeyID());
		expect(KeyUse.SIGNATURE, jwk.getKeyUse());

		expect("hJtXIZ2uSN5kbQfbtTNWbpdmhkV8FJG-Onbc6mxCcYg", jwk.getKeyValue().toString());
  });

  test('testCookbookAESKeyExample', () {

		// See http://tools.ietf.org/html/draft-ietf-jose-cookbook-02#section-4.6.1

		String json ="{"+
			"\"kty\":\"oct\","+
			"\"kid\":\"77c7e2b8-6e13-45cf-8672-617b5b45243a\","+
			"\"use\":\"enc\","+
			"\"alg\":\"A128GCM\","+
			"\"k\":\"XctOhJAkA-pD9Lh7ZgW_2A\""+
			"}";

		OctetSequenceKey jwk = OctetSequenceKey.fromJsonString(json);

		expect(KeyType.OCT, jwk.getKeyType());
		expect("77c7e2b8-6e13-45cf-8672-617b5b45243a", jwk.getKeyID());
		expect(KeyUse.ENCRYPTION, jwk.getKeyUse());
		expect(EncryptionMethod.A128GCM, jwk.getAlgorithm());

		expect("XctOhJAkA-pD9Lh7ZgW_2A", jwk.getKeyValue().toString());
  });

}
