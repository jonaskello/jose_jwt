part of jose_jwt.jose;

/**
 * Enumeration of the states of a JSON Web Encryption (JWE) object.
 */
enum JWEObjectState {

/**
 * The JWE object is created but not encrypted yet.
 */
UNENCRYPTED,


/**
 * The JWE object is encrypted.
 */
ENCRYPTED,


/**
 * The JWE object is decrypted.
 */
DECRYPTED
}

/**
 * JSON Web Encryption (JWE) object. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 */
class JWEObject extends JOSEObject {

  /**
   * The header.
   */
  JWEHeader _header;


  /**
   * The encrypted key, {@code null} if not computed or applicable.
   */
  Base64URL _encryptedKey;


  /**
   * The initialisation vector, {@code null} if not generated or
   * applicable.
   */
  Base64URL _iv;


  /**
   * The cipher text, {@code null} if not computed.
   */
  Base64URL _cipherText;


  /**
   * The authentication tag, {@code null} if not computed or applicable.
   */
  Base64URL _authTag;


  /**
   * The JWE object state.
   */
  JWEObjectState _state;


  /**
   * Creates a new to-be-encrypted JSON Web Encryption (JWE) object with
   * the specified header and payload. The initial state will be
   * {@link State#UNENCRYPTED unencrypted}.
   *
   * @param header  The JWE header. Must not be {@code null}.
   * @param payload The payload. Must not be {@code null}.
   */
  JWEObject.toBeEncrypted(final JWEHeader header, final Payload payload) {

    if (header == null) {
      throw new ArgumentError.notNull("header");
    }

    this._header = header;

    if (payload == null) {
      throw new ArgumentError.notNull("payload");
    }


    setPayload(payload);

    _encryptedKey = null;

    _cipherText = null;

    _state = JWEObjectState.UNENCRYPTED;
  }


  /**
   * Creates a new encrypted JSON Web Encryption (JWE) object with the
   * specified serialised parts. The state will be {@link State#ENCRYPTED
   * encrypted}.
   *
   * @param firstPart  The first part, corresponding to the JWE header.
   *                   Must not be {@code null}.
   * @param secondPart The second part, corresponding to the encrypted
   *                   key. Empty or {@code null} if none.
   * @param thirdPart  The third part, corresponding to the
   *                   initialisation vector. Empty or {@code null} if
   *                   none.
   * @param fourthPart The fourth part, corresponding to the cipher text.
   *                   Must not be {@code null}.
   * @param fifthPart  The fifth part, corresponding to the
   *                   authentication tag. Empty of {@code null} if none.
   *
   * @throws ParseException If parsing of the serialised parts failed.
   */
  JWEObject(final Base64URL firstPart,
            final Base64URL secondPart,
            final Base64URL thirdPart,
            final Base64URL fourthPart,
            final Base64URL fifthPart) {

    if (firstPart == null) {
      throw new ArgumentError.notNull("firstPart");
    }

    try {
      this._header = JWEHeader.parse(firstPart);

    } catch (e) {
      //ParseException
      throw new ParseError("Invalid JWE header: " + e.getMessage(), 0);
    }

    if (secondPart == null || secondPart.toString().isEmpty) {
      _encryptedKey = null;

    } else {
      _encryptedKey = secondPart;
    }

    if (thirdPart == null || thirdPart.toString().isEmpty) {
      _iv = null;

    } else {
      _iv = thirdPart;
    }

    if (fourthPart == null) {
      throw new ArgumentError.notNull("fourthPart");
    }

    _cipherText = fourthPart;

    if (fifthPart == null || fifthPart.toString().isEmpty) {
      _authTag = null;
    } else {
      _authTag = fifthPart;
    }

    _state = JWEObjectState.ENCRYPTED; // but not decrypted yet!

    setParsedParts(firstPart, secondPart, thirdPart, fourthPart, fifthPart);
  }

  @override
  JWEHeader getHeader() {

    return _header;
  }


  /**
   * Returns the encrypted key of this JWE object.
   *
   * @return The encrypted key, {@code null} not applicable or the JWE
   *         object has not been encrypted yet.
   */
  Base64URL getEncryptedKey() {

    return _encryptedKey;
  }

  /**
   * Returns the initialisation vector (IV) of this JWE object.
   *
   * @return The initialisation vector (IV), {@code null} if not
   *         applicable or the JWE object has not been encrypted yet.
   */
  Base64URL getIV() {

    return _iv;
  }


  /**
   * Returns the cipher text of this JWE object.
   *
   * @return The cipher text, {@code null} if the JWE object has not been
   *         encrypted yet.
   */
  Base64URL getCipherText() {

    return _cipherText;
  }


  /**
   * Returns the authentication tag of this JWE object.
   *
   * @return The authentication tag, {@code null} if not applicable or
   *         the JWE object has not been encrypted yet.
   */
  Base64URL getAuthTag() {

    return _authTag;
  }


  /**
   * Returns the state of this JWE object.
   *
   * @return The state.
   */
  JWEObjectState getState() {

    return _state;
  }


  /**
   * Ensures the current state is {@link State#UNENCRYPTED unencrypted}.
   *
   * @throws IllegalStateException If the current state is not
   *                               unencrypted.
   */
  void _ensureUnencryptedState() {

    if (_state != JWEObjectState.UNENCRYPTED) {

      throw new StateError("The JWE object must be in an unencrypted state");
    }
  }


  /**
   * Ensures the current state is {@link State#ENCRYPTED encrypted}.
   *
   * @throws IllegalStateException If the current state is not encrypted.
   */
  void _ensureEncryptedState() {

    if (_state != JWEObjectState.ENCRYPTED) {

      throw new StateError("The JWE object must be in an encrypted state");
    }
  }


  /**
   * Ensures the current state is {@link State#ENCRYPTED encrypted} or
   * {@link State#DECRYPTED decrypted}.
   *
   * @throws IllegalStateException If the current state is not encrypted
   *                               or decrypted.
   */
  void _ensureEncryptedOrDecryptedState() {

    if (_state != JWEObjectState.ENCRYPTED && _state != JWEObjectState.DECRYPTED) {

      throw new StateError("The JWE object must be in an encrypted or decrypted state");
    }
  }

  /**
   * Ensures the specified JWE encrypter supports the algorithms of this
   * JWE object.
   *
   * @throws JOSEException If the JWE algorithms are not supported.
   */
  void _ensureJWEEncrypterSupport(final JWEEncrypter encrypter) {

    if (!encrypter.supportedAlgorithms().contains(getHeader().getAlgorithm())) {

      throw new JOSEException("The \"" + getHeader().getAlgorithm() +
      "\" algorithm is not supported by the JWE encrypter");
    }

    if (!encrypter.supportedEncryptionMethods().contains(getHeader().getEncryptionMethod())) {

      throw new JOSEException("The \"" + getHeader().getEncryptionMethod() +
      "\" encryption method is not supported by the JWE encrypter");
    }
  }

  /**
   * Ensures the specified JWE decrypter accepts the algorithms and the
   * headers of this JWE object.
   *
   * @throws JOSEException If the JWE algorithms or headers are not
   *                       accepted.
   */
  void _ensureJWEDecrypterAcceptance(final JWEDecrypter decrypter) {

    if (!decrypter.getAcceptedAlgorithms().contains(getHeader().getAlgorithm())) {

      throw new JOSEException("The \"" + getHeader().getAlgorithm() +
      "\" algorithm is not accepted by the JWE decrypter");
    }

    if (!decrypter.getAcceptedEncryptionMethods().contains(getHeader().getEncryptionMethod())) {

      throw new JOSEException("The \"" + getHeader().getEncryptionMethod() +
      "\" encryption method is not accepted by the JWE decrypter");
    }
  }

  /**
   * Encrypts this JWE object with the specified encrypter. The JWE
   * object must be in an {@link State#UNENCRYPTED unencrypted} state.
   *
   * @param encrypter The JWE encrypter. Must not be {@code null}.
   *
   * @throws IllegalStateException If the JWE object is not in an
   *                               {@link State#UNENCRYPTED unencrypted
   *                               state}.
   * @throws JOSEException         If the JWE object couldn't be
   *                               encrypted.
   */
  void encrypt(final JWEEncrypter encrypter) {

    ensureUnencryptedState();

    ensureJWEEncrypterSupport(encrypter);

    JWECryptoParts parts = null;

    try {
      parts = encrypter.encrypt(getHeader(), getPayload().toBytes());

    } catch (e) {
      // JOSEException
      if (e is JOSEException)
        throw e;

//    } catch (e) {
      // Exception
      // Prevent throwing unchecked exceptions at this point,
      // see issue #20

      throw new JOSEException.withCause(e.toString(), e);
    }

    // Check if the header has been modified
    if (parts.getHeader() != null) {
      _header = parts.getHeader();
    }

    _encryptedKey = parts.getEncryptedKey();
    _iv = parts.getInitializationVector();
    _cipherText = parts.getCipherText();
    _authTag = parts.getAuthenticationTag();

    _state = JWEObjectState.ENCRYPTED;
  }

  /**
   * Decrypts this JWE object with the specified decrypter. The JWE
   * object must be in a {@link State#ENCRYPTED encrypted} state.
   *
   * @param decrypter The JWE decrypter. Must not be {@code null}.
   *
   * @throws IllegalStateException If the JWE object is not in an
   *                               {@link State#ENCRYPTED encrypted
   *                               state}.
   * @throws JOSEException         If the JWE object couldn't be
   *                               decrypted.
   */
  void decrypt(final JWEDecrypter decrypter) {

    _ensureEncryptedState();

    _ensureJWEDecrypterAcceptance(decrypter);

    try {
      setPayload(new Payload(decrypter.decrypt(getHeader(),
      getEncryptedKey(),
      getIV(),
      getCipherText(),
      getAuthTag())));

    } catch (e) {

      if (e is JOSEException)
        throw e;

//		} catch (Exception e) {

      // Prevent throwing unchecked exceptions at this point,
      // see issue #20
      throw new JOSEException.withCause(e.getMessage(), e);
    }

    _state = JWEObjectState.DECRYPTED;
  }

  /**
   * Serialises this JWE object to its compact format consisting of
   * Base64URL-encoded parts delimited by period ('.') characters. It
   * must be in a {@link State#ENCRYPTED encrypted} or
   * {@link State#DECRYPTED decrypted} state.
   *
   * <pre>
   * [header-base64url].[encryptedKey-base64url].[iv-base64url].[cipherText-base64url].[authTag-base64url]
   * </pre>
   *
   * @return The serialised JWE object.
   *
   * @throws IllegalStateException If the JWE object is not in a
   *                               {@link State#ENCRYPTED encrypted} or
   *                               {@link State#DECRYPTED decrypted
   *                               state}.
   */
  @override
  String serialize() {

    _ensureEncryptedOrDecryptedState();

    StringBuffer sb = new StringBuffer(_header.toBase64URL().toString());
    sb.write('.');

    if (_encryptedKey != null) {

      sb.write(_encryptedKey.toString());
    }

    sb.write('.');

    if (_iv != null) {

      sb.write(_iv.toString());
    }

    sb.write('.');
    sb.write(_cipherText.toString());
    sb.write('.');

    if (_authTag != null) {

      sb.write(_authTag.toString());
    }

    return sb.toString();
  }

  /**
   * Parses a JWE object from the specified string in compact form. The
   * parsed JWE object will be given an {@link State#ENCRYPTED} state.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The JWE object.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                        JWE object.
   */
  static JWEObject parse(final String s) {

    List<Base64URL> parts = JOSEObject.split(s);

    if (parts.length != 5) {

      throw new ParseError("Unexpected number of Base64URL parts, must be five", 0);
    }

    return new JWEObject(parts[0], parts[1], parts[2], parts[3], parts[4]);
  }

}
