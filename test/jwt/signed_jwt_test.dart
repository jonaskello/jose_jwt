library jose_jwt.test.jwt.jwt.signed_jwt_test;

import 'package:unittest/unittest.dart';
import 'package:cipher/cipher.dart';
import 'package:cipher/impl/server.dart';
import 'package:bignum/bignum.dart';
import 'package:jose_jwt/src/jwt.dart';
import 'package:jose_jwt/src/jose.dart';
import 'package:jose_jwt/src/crypto.dart';

/**
 * Tests signed JWTs.
 */
//public class SignedJWTTest extends TestCase {

main() {

  initCipher();

  test('testSignAndVerify', () {

//			KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
//			kpg.initialize(2048);

    var rsapars = new RSAKeyGeneratorParameters(new BigInteger("65537"), 2048, 12);
    var params = new ParametersWithRandom(rsapars, new SecureRandom("AES/CTR/PRNG"));
    var kpg = new KeyGenerator("RSA")
      ..init(params);

    AsymmetricKeyPair kp = kpg.generateKeyPair();
    RSAPublicKey publicKey = kp.publicKey;
    RSAPrivateKey privateKey = kp.privateKey;

    JWTClaimsSet claimsSet = new JWTClaimsSet();
    claimsSet.setSubject("alice");
    claimsSet.setIssueTime(new DateTime.fromMillisecondsSinceEpoch(123000));
    claimsSet.setIssuer("https://c2id.com");
    claimsSet.setCustomClaim("scope", "openid");

    JWSHeader header = new JWSHeaderBuilder(JWSAlgorithm.RS256).
    keyID("1").
    jwkURL(Uri.parse("https://c2id.com/jwks.json")).
    build();

    SignedJWT signedJWT = new SignedJWT(header, claimsSet);

    expect(JWSObjectState.UNSIGNED, equals(signedJWT.getState()));
    expect(header, equals(signedJWT.getHeader()));

    expect("alice", equals(signedJWT.getJWTClaimsSet().getSubject()));
    expect(123000, equals(signedJWT.getJWTClaimsSet().getIssueTime().millisecondsSinceEpoch));
    expect("https://c2id.com", equals(signedJWT.getJWTClaimsSet().getIssuer()));
    expect("openid", equals(signedJWT.getJWTClaimsSet().getStringClaim("scope")));
    expect(signedJWT.getSignature(), isNull);

    Base64URL sigInput = Base64URL.encodeBytes(signedJWT.getSigningInput());

    JWSSigner signer = new RSASSASigner(privateKey);

    signedJWT.sign(signer);

    expect(JWSObjectState.SIGNED, equals(signedJWT.getState()));
    expect(signedJWT.getSignature(), isNotNull);

    String serializedJWT = signedJWT.serialize();

    signedJWT = SignedJWT.parse(serializedJWT);
    expect(serializedJWT, equals(signedJWT.getParsedString()));

    expect(JWSObjectState.SIGNED, equals(signedJWT.getState()));
    expect(signedJWT.getSignature(), isNotNull);
    expect(sigInput == Base64URL.encodeBytes(signedJWT.getSigningInput()), isTrue);

    JWSVerifier verifier = new RSASSAVerifier(publicKey);
    expect(signedJWT.verify(verifier), isTrue);

  });

}
