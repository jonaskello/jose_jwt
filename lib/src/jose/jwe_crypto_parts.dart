part of jose_jwt.jose;

/**
 * The cryptographic parts of a JSON Web Encryption (JWE) object. This class is
 * an immutable wrapper for returning the cipher text, initialisation vector
 * (IV), encrypted key and authentication authTag from {@link JWEEncrypter}
 * implementations.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-11)
 */
//@Immutable
class JWECryptoParts {

  /**
   * The modified JWE header (optional).
   */
  final JWEHeader _header;


  /**
   * The encrypted key (optional).
   */
  final Base64URL _encryptedKey;


  /**
   * The initialisation vector (optional).
   */
  final Base64URL _iv;


  /**
   * The cipher text.
   */
  final Base64URL _cipherText;


  /**
   * The authentication tag (optional).
   */
  final Base64URL _authenticationTag;


  /**
   * Creates a new cryptographic JWE parts instance.
   *
   * @param encryptedKey      The encrypted key, {@code null} if not
   *                          required by the encryption algorithm.
   * @param iv                The initialisation vector (IV),
   *                          {@code null} if not required by the
   *                          encryption algorithm.
   * @param cipherText        The cipher text. Must not be {@code null}.
   * @param authenticationTag The authentication tag, {@code null} if the
   *                          JWE algorithm provides built-in integrity
   *                          check.
   */
  JWECryptoParts.noKey(final Base64URL encryptedKey,
                       final Base64URL iv,
                       final Base64URL cipherText,
                       final Base64URL authenticationTag) : this(null, encryptedKey, iv, cipherText, authenticationTag);

  /**
   * Creates a new cryptographic JWE parts instance.
   *
   * @param header            The modified JWE header, {@code null} if
   *                          not.
   * @param encryptedKey      The encrypted key, {@code null} if not
   *                          required by the encryption algorithm.
   * @param iv                The initialisation vector (IV),
   *                          {@code null} if not required by the
   *                          encryption algorithm.
   * @param cipherText        The cipher text. Must not be {@code null}.
   * @param authenticationTag The authentication tag, {@code null} if the
   *                          JWE algorithm provides built-in integrity
   *                          check.
   */
  JWECryptoParts(this._header,
                 this._encryptedKey,
                 this._iv,
                 this._cipherText,
                 this._authenticationTag) {

//    this.header = header;
//    this.encryptedKey = encryptedKey;
//    this.iv = iv;

    if (_cipherText == null) {
      throw new ArgumentError.notNull("cipherText");
    }

//    this.cipherText = cipherText;
//    this.authenticationTag = authenticationTag;
  }


  /**
   * Gets the modified JWE header.
   *
   * @return The modified JWE header, {@code null} of not.
   */
  JWEHeader getHeader() {

    return _header;
  }

	/**
	 * Gets the encrypted key.
	 *
	 * @return The encrypted key, {@code null} if not required by 
	 *         the JWE algorithm.
	 */
	Base64URL getEncryptedKey() {

		return _encryptedKey;
	}

	/**
	 * Gets the initialisation vector (IV).
	 *
	 * @return The initialisation vector (IV), {@code null} if not required
	 *         by the JWE algorithm.
	 */
	Base64URL getInitializationVector() {

		return _iv;
	}

	/**
	 * Gets the cipher text.
	 *
	 * @return The cipher text.
	 */
	Base64URL getCipherText() {

		return _cipherText;
	}

	/**
	 * Gets the authentication tag.
	 *
	 * @return The authentication tag, {@code null} if the encryption
	 *         algorithm provides built-in integrity checking.
	 */
	Base64URL getAuthenticationTag() {

		return _authenticationTag;
	}

//	/**
//	 * Use {@link #getAuthenticationTag} instead.
//	 */
//	@Deprecated
//	Base64URL getIntegrityValue() {
//
//		return getAuthenticationTag();
//	}

}
