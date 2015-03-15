part of jose_jwt.jose;

/**
 * Common interface for JSON Web Signature (JWS) {@link JWSSigner signers} and
 * {@link JWSVerifier verifiers}.
 *
 * <p>Callers can query the JWS provider to determine its algorithm
 * capabilities.
 *
 * @author  Vladimir Dzhuvinov
 * @version $version$ (2014-04-20)
 */
abstract class JWSAlgorithmProvider extends AlgorithmProvider {


  /**
   * Returns the names of the supported JWS algorithms. These correspond
   * to the {@code alg} JWS header parameter.
   *
   * @return The supported JWS algorithms, empty set if none.
   */
  Set<JWSAlgorithm> supportedAlgorithms();
}
