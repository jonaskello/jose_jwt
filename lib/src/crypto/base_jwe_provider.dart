part of jose_jwt.crypto;

/**
 * The base abstract class for JSON Web Encryption (JWE) encrypters and
 * decrypters.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-01-28)
 */
abstract class BaseJWEProvider implements JWEAlgorithmProvider {

  /**
   * The supported algorithms.
   */
  final Set<JWEAlgorithm> _algs;


  /**
   * The supported encryption methods.
   */
  final Set<EncryptionMethod> _encs;

/*
	/**
	 * The JCA provider for the key encryption, {@code null} if not
	 * specified (implies default one).
	 */
	protected Provider keyEncryptionProvider = null;


	/**
	 * The JCA provider for the content encryption, {@code null} if not
	 * specified (implies default one).
	 */
	protected Provider contentEncryptionProvider = null;

	/**
	 * The JCA provider for the MAC computation, {@code null} if not
	 * specified (implies default one).
	 */
	protected Provider macProvider = null;


	/**
	 * The SecureRandom instance used for encryption/decryption.
	 */
	private SecureRandom randomGen = null;

*/

  /**
   * Creates a new base JWE provider.
   *
   * @param algs The supported JWE algorithms. Must not be {@code null}.
   * @param encs The supported encryption methods. Must not be
   *             {@code null}.
   */
  BaseJWEProvider(final Set<JWEAlgorithm> algs,
                  final Set<EncryptionMethod> encs) :
  _algs = new UnmodifiableSetView(algs),
  _encs = encs {

    if (algs == null) {
      throw new ArgumentError.notNull("algs");
    }

    if (encs == null) {
      throw new ArgumentError.notNull("encs");
    }

  }

  @override
  Set<JWEAlgorithm> supportedAlgorithms() {

    return _algs;
  }

  @override
  Set<EncryptionMethod> supportedEncryptionMethods() {

    return _encs;
  }

/*

	@override
	void setProvider(final Provider provider) {

		setKeyEncryptionProvider(provider);
		setContentEncryptionProvider(provider);
		setMACProvider(provider);
	}

	@override
	public void setKeyEncryptionProvider(final Provider provider) {

		keyEncryptionProvider = provider;
	}


	@override
	public void setContentEncryptionProvider(final Provider provider) {

		contentEncryptionProvider = provider;
	}


	@override
	public void setMACProvider(final Provider provider) {

		macProvider = provider;
	}


	@override
	public void setSecureRandom(final SecureRandom randomGen) {

		this.randomGen = randomGen;
	}
*/

  /**
   * Returns the secure random generator for this JWE provider.
   *
   * @return The secure random generator.
   */
  SecureRandom getSecureRandom() {
    if (randomGen == null) {
      // Use default SecureRandom instance for this JVM/platform.
      this.randomGen = new SecureRandom();
      return randomGen;
    } else {
      // Use the specified instance.
      return randomGen;
    }
  }


}


