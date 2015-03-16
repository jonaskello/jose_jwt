part of jose_jwt.crypto;

/**
 * The base abstract class for JSON Web Signature (JWS) signers and verifiers.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-01-28)
 */
abstract class BaseJWSProvider implements JWSAlgorithmProvider {

  /**
   * The supported algorithms.
   */
  final Set<JWSAlgorithm> _algs;

/*
  /**
   * The underlying cryptographic provider, {@code null} if not specified
   * (implies default one).
   */
  Provider provider = null;
*/

  /**
   * Creates a new base JWS provider.
   *
   * @param algs The supported JWS algorithms. Must not be {@code null}.
   */
  BaseJWSProvider(final Set<JWSAlgorithm> algs) :
  _algs = new UnmodifiableSetView(algs) {

    if (algs == null) {
      throw new ArgumentError.notNull("algs");
    }

  }

  @override
  Set<JWSAlgorithm> supportedAlgorithms() {

    return _algs;
  }
/*

	@Override
	public void setProvider(final Provider provider) {

		this.provider = provider;
	}

*/

}


