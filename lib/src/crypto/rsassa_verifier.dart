part of jose_jwt.crypto;

/**
 * RSA Signature-Scheme-with-Appendix (RSASSA) verifier of
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
 * <p>Accepts all {@link com.nimbusds.jose.JWSHeader#getRegisteredParameterNames
 * registered JWS header parameters}. Use {@link #setAcceptedAlgorithms} to
 * restrict the acceptable JWS algorithms.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-22)
 */
//@ThreadSafe
class RSASSAVerifier extends RSASSAProvider implements JWSVerifier {

  /**
   * The accepted JWS algorithms.
   */
  Set<JWSAlgorithm> _acceptedAlgs; // = new Set(supportedAlgorithms());


  /**
   * The critical header parameter checker.
   */
  final CriticalHeaderParameterChecker _critParamChecker = new CriticalHeaderParameterChecker();


  /**
   * The public RSA key.
   */
  final RSAPublicKey _publicKey;


  /**
   * Creates a new RSA Signature-Scheme-with-Appendix (RSASSA) verifier.
   *
   * @param publicKey The public RSA key. Must not be {@code null}.
   */
  RSASSAVerifier(this._publicKey) {

    if (_publicKey == null) {

      throw new ArgumentError.notNull("_publicKey");
    }

    _acceptedAlgs = new Set.from(supportedAlgorithms());

  }

  /**
   * Gets the public RSA key.
   *
   * @return The public RSA key.
   */
  RSAPublicKey getPublicKey() {

    return _publicKey;
  }

  @override
  Set<JWSAlgorithm> getAcceptedAlgorithms() {

    return _acceptedAlgs;
  }


  @override
  void setAcceptedAlgorithms(final Set<JWSAlgorithm> acceptedAlgs) {

    if (acceptedAlgs == null) {
      throw new ArgumentError.notNull("acceptedAlgs");
    }

    if (!supportedAlgorithms().containsAll(acceptedAlgs)) {
      throw new ArgumentError("Unsupported JWS algorithm(s)");
    }

    _acceptedAlgs = acceptedAlgs;
  }

  @override
  Set<String> getIgnoredCriticalHeaderParameters() {

    return _critParamChecker.getIgnoredCriticalHeaders();
  }

  @override
  void setIgnoredCriticalHeaderParameters(final Set<String> headers) {

    _critParamChecker.setIgnoredCriticalHeaders(headers);
  }

  @override
  bool verify(final JWSHeader header,
              final Uint8List signedContent,
              final Base64URL signature) {

    throw new UnimplementedError();
/*
    if (!_critParamChecker.headerPasses(header)) {
      return false;
    }

    Signature verifier = RSASSAProvider.getRSASignerAndVerifier(header.getAlgorithm(), provider);

    try {
      verifier.initVerify(publicKey);

    } catch (e) {
      if (e is InvalidKeyException)
        throw new JOSEException("Invalid public RSA key: " + e.toString(), e);
      throw e;
    }

    try {
      verifier.update(signedContent);
      return verifier.verify(signature.decode());

    } catch (e) {
      if (e is SignatureException)
        return false;
      throw e;
    }
*/
  }

}
