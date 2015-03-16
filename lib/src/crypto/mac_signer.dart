part of jose_jwt.crypto;

/**
 * Message Authentication Code (MAC) signer of
 * {@link com.nimbusds.jose.JWSObject JWS objects}. This class is thread-safe.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS256}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS384}
 *     <li>{@link com.nimbusds.jose.JWSAlgorithm#HS512}
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2015-02-02)
 */
//@ThreadSafe
class MACSigner extends MACProvider implements JWSSigner {

  /**
   * Returns the minimal required secret size for the specified
   * HMAC JWS algorithm.
   *
   * @param hmacAlg The HMAC JWS algorithm. Must be
   *                {@link #SUPPORTED_ALGORITHMS supported} and not
   *                {@code null}.
   *
   * @return The minimal required secret size, in bits.
   *
   * @throws JOSEException If the algorithm is not supported.
   */
  static int getMinRequiredSecretSize(final JWSAlgorithm hmacAlg) {

    if (JWSAlgorithm.HS256 == hmacAlg) {
      return 256;
    } else if (JWSAlgorithm.HS384 == hmacAlg) {
      return 384;
    } else if (JWSAlgorithm.HS512 == hmacAlg) {
      return 512;
    } else {
      throw new JOSEException("Unsupported HMAC algorithm, must be HS256, HS384 or HS512");
    }
  }

  /**
   * Creates a new Message Authentication (MAC) signer.
   *
   * @param sharedSecret The shared secret. Must be at least 256 bits
   *                     long and not {@code null}.
   */
  MACSigner.secretBytes(final Uint8List sharedSecret) : super.secretBytes (sharedSecret);

  /**
   * Creates a new Message Authentication (MAC) signer.
   *
   * @param sharedSecretString The shared secret as a UTF-8 encoded
   *                           string. Must not be {@code null}.
   */
  MACSigner.secretString(final String sharedSecretString) : super.secretString(sharedSecretString);

  @override
  Base64URL sign(final JWSHeader header, final Uint8List signingInput) {
    throw new UnimplementedError();
    /*
    int minRequiredKeyLength = getMinRequiredSecretSize(header.getAlgorithm());

    if (getSharedSecret().length < minRequiredKeyLength / 8) {
      throw new JOSEException("The shared secret size must be at least " + minRequiredKeyLength + " bits for " + header.getAlgorithm());
    }

    String jcaAlg = getJCAAlgorithmName(header.getAlgorithm());
    Uint8List hmac = HMAC.compute(jcaAlg, getSharedSecret(), signingInput, provider);
    return Base64URL.encode(hmac);
    */
  }

}

