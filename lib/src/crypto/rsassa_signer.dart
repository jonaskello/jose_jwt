part of jose_jwt.crypto;

/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) signer of
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#RS512}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#PS512}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-04)
 */
//@ThreadSafe
class RSASSASigner extends RSASSAProvider implements JWSSigner {

  /**
   * The private RSA key.
   */
  final RSAPrivateKey _privateKey;

  /**
   * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) signer.
   *
   * @param privateKey The private RSA key. Must not be {@code null}.
   */
  RSASSASigner(this._privateKey) {

    if (_privateKey == null) {
      throw new ArgumentError.notNull("privateKey");
    }
  }

  /**
   * Gets the private RSA key.
   *
   * @return The private RSA key.
   */
  RSAPrivateKey getPrivateKey() {

    return _privateKey;
  }

  @override
  Base64URL sign(final JWSHeader header, final Uint8List signingInput) {

    Signature signer = RSASSAProvider.getRSASignerAndVerifier(header.getAlgorithm(), provider);

    try {
      signer.initSign(_privateKey);
      signer.update(signingInput);
      return Base64URL.encodeBytes(signer.sign());

    } catch (e) {
//      if (e is InvalidKeyException)
//        throw new JOSEException("Invalid private RSA key: " + e.getMessage(), e);
//      if (e is SignatureException)
//        throw new JOSEException("RSA signature exception: " + e.getMessage(), e);
      throw new JOSEException(e.toString());
    }
  }
}

