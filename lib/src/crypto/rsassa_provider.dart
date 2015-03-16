part of jose_jwt.crypto;

/**
 * The base abstract class for RSA Signature-Scheme-with-Appendix (RSASSA)
 * signers and verifiers of {@link com.nimbusds.jose.JWSObject JWS objects}.
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
 * @version $version$ (2014-01-28)
 */
abstract class RSASSAProvider extends BaseJWSProvider {

  /**
   * The supported JWS algorithms.
   */
  static final Set<JWSAlgorithm> SUPPORTED_ALGORITHMS = new UnmodifiableSetView(new Set.from([
      JWSAlgorithm.RS256,
      JWSAlgorithm.RS384,
      JWSAlgorithm.RS512,
      JWSAlgorithm.PS256,
      JWSAlgorithm.PS384,
      JWSAlgorithm.PS512
  ]));

//	/**
//	 * Initialises the supported algorithms.
//	 */
//	static init() {
//
//		Set<JWSAlgorithm> algs = new Set();
//
//		algs.add(JWSAlgorithm.RS256);
//		algs.add(JWSAlgorithm.RS384);
//		algs.add(JWSAlgorithm.RS512);
//		algs.add(JWSAlgorithm.PS256);
//		algs.add(JWSAlgorithm.PS384);
//		algs.add(JWSAlgorithm.PS512);
//
//		SUPPORTED_ALGORITHMS = new UnmodifiableSetView(algs);
//	}


  /**
   * Creates a new RSASSA provider.
   */
  RSASSAProvider() : super(SUPPORTED_ALGORITHMS);

  /**
   * Gets a signer and verifier for the specified RSASSA-based JSON Web
   * Algorithm (JWA).
   *
   * @param alg The JSON Web Algorithm (JWA). Must be supported and not
   *            {@code null}.
   *
   * @return A signer and verifier instance.
   *
   * @throws JOSEException If the algorithm is not supported.
   */
  static Signature getRSASignerAndVerifier(final JWSAlgorithm alg,
                                           final Provider provider) {

    // The JCE crypto provider uses different alg names

    String internalAlgName;

    PSSParameterSpec pssSpec = null;

    if (alg == JWSAlgorithm.RS256) {

      internalAlgName = "SHA256withRSA";

    } else if (alg == JWSAlgorithm.RS384) {

      internalAlgName = "SHA384withRSA";

    } else if (alg == JWSAlgorithm.RS512) {

      internalAlgName = "SHA512withRSA";

    } else if (alg == JWSAlgorithm.PS256) {

      internalAlgName = "SHA256withRSAandMGF1";

      // JWA mandates salt length must equal hash
      pssSpec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);

    } else if (alg == JWSAlgorithm.PS384) {

      internalAlgName = "SHA384withRSAandMGF1";

      // JWA mandates salt length must equal hash
      pssSpec = new PSSParameterSpec("SHA384", "MGF1", MGF1ParameterSpec.SHA384, 48, 1);

    } else if (alg == JWSAlgorithm.PS512) {

      internalAlgName = "SHA512withRSAandMGF1";

      // JWA mandates salt length must equal hash
      pssSpec = new PSSParameterSpec("SHA512", "MGF1", MGF1ParameterSpec.SHA512, 64, 1);

    } else {

      throw new JOSEException("Unsupported RSASSA algorithm, must be RS256, RS384, RS512, PS256, PS384 or PS512");
    }

    Signature signature;

    try {
      if (provider != null) {
        signature = Signature.getInstance(internalAlgName, provider);
      } else {
        signature = Signature.getInstance(internalAlgName);
      }

    } catch (e) {

//      if (e is NoSuchAlgorithmException)
//        throw new JOSEException("Unsupported RSASSA algorithm: " + e.getMessage(), e);
      throw new JOSEException(e);
    }


    if (pssSpec != null) {

      try {
        signature.setParameter(pssSpec);

      } catch (e) {
//        if (e is InvalidAlgorithmParameterException)
//          throw new JOSEException("Invalid RSASSA-PSS salt length parameter: " + e.getMessage(), e);
        throw new JOSEException(e);
      }
    }


    return signature;
  }

/*
*/

}

