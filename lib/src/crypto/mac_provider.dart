part of jose_jwt.crypto;


/**
 * The base abstract class for Message Authentication Code (MAC) signers and
 * verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
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
abstract class MACProvider extends BaseJWSProvider {

  /**
   * The supported JWS algorithms.
   */
  static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = new UnmodifiableSetView(new Set.from([
      JWSAlgorithm.HS256,
      JWSAlgorithm.HS384,
      JWSAlgorithm.HS512
  ]));


//	/**
//	 * Initialises the supported algorithms.
//	 */
//	static init() {
//
//		Set<JWSAlgorithm> algs =
//		algs.add(JWSAlgorithm.HS256);
//		algs.add(JWSAlgorithm.HS384);
//		algs.add(JWSAlgorithm.HS512);
//		SUPPORTED_ALGORITHMS =
//	}


  /**
   * Gets the matching Java Cryptography Architecture (JCA) algorithm
   * name for the specified HMAC-based JSON Web Algorithm (JWA).
   *
   * @param alg The JSON Web Algorithm (JWA). Must be supported and not
   *            {@code null}.
   *
   * @return The matching JCA algorithm name.
   *
   * @throws JOSEException If the algorithm is not supported.
   */
  static String getJCAAlgorithmName(final JWSAlgorithm alg) {

    if (alg == JWSAlgorithm.HS256) {
      return "HMACSHA256";
    } else if (alg == JWSAlgorithm.HS384) {
      return "HMACSHA384";
    } else if (alg == JWSAlgorithm.HS512) {
      return "HMACSHA512";
    } else {
      throw new JOSEException("Unsupported HMAC algorithm, must be HS256, HS384 or HS512");
    }
  }

  /**
   * The shared secret.
   */
  final Uint8List _sharedSecret;


  /**
   * Creates a new Message Authentication (MAC) provider.
   *
   * @param sharedSecret The shared secret. Must be at least 256 bits
   *                     long and not {@code null}.
   */
  MACProvider.secretBytes(this._sharedSecret) : super(SUPPORTED_ALGORITHMS) {

    if (_sharedSecret.length < 256 / 8) {
      throw new ArgumentError("The shared secret size must be at least 256 bits");
    }

  }

  /**
   * Creates a new Message Authentication (MAC) provider.
   *
   * @param sharedSecretString The shared secret as a UTF-8 encoded
   *                           string. Must not be {@code null}.
   */
  MACProvider.secretString(final String sharedSecretString)
  : this.secretBytes(UTF8.encode(sharedSecretString));

  /**
   * Gets the shared secret.
   *
   * @return The shared secret.
   */
  Uint8List getSharedSecret() {

    return _sharedSecret;
  }

  /**
   * Gets the shared secret as a UTF-8 encoded string.
   *
   * @return The shared secret as a UTF-8 encoded string.
   */
  String getSharedSecretString() {

//    return new String(sharedSecret, Charset.forName("UTF-8"));
    return UTF8.decode(_sharedSecret);
  }

}

