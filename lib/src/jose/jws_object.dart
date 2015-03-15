part of jose_jwt.jose;

/**
 * Enumeration of the states of a JSON Web Signature (JWS) object.
 */
enum JWSObjectState {

/**
 * The JWS object is created but not signed yet.
 */
UNSIGNED,


/**
 * The JWS object is signed but its signature is not verified.
 */
SIGNED,


/**
 * The JWS object is signed and its signature was successfully verified.
 */
VERIFIED
}

/**
 * JSON Web Signature (JWS) object. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
class JWSObject extends JOSEObject {

  /**
   * The header.
   */
  final JWSHeader _header;

  /**
   * The signing input for this JWS object.
   *
   * <p>Format:
   *
   * <pre>
   * [header-base64url].[payload-base64url]
   * </pre>
   */
  final String _signingInputString;


  /**
   * The signature, {@code null} if not signed.
   */
  Base64URL _signature;


  /**
   * The JWS object state.
   */
  JWSObjectState _state;

  /**
   * Creates a new to-be-signed JSON Web Signature (JWS) object with the
   * specified header and payload. The initial state will be
   * {@link State#UNSIGNED unsigned}.
   *
   * @param header  The JWS header. Must not be {@code null}.
   * @param payload The payload. Must not be {@code null}.
   */
  JWSObject(final JWSHeader header, final Payload payload)
  : _header = header,
  _signingInputString = _composeSigningInput(header.toBase64URL(), payload.toBase64URL()) {

    if (header == null) {
      throw new ArgumentError.notNull("header");
    }

    if (payload == null) {
      throw new ArgumentError.notNull("payload");
    }

    setPayload(payload);


    _signature = null;

    _state = JWSObjectState.UNSIGNED;
  }

  /**
   * Creates a new signed JSON Web Signature (JWS) object with the
   * specified serialised parts. The state will be
   * {@link State#SIGNED signed}.
   *
   * @param firstPart  The first part, corresponding to the JWS header.
   *                   Must not be {@code null}.
   * @param secondPart The second part, corresponding to the payload. Must
   *                   not be {@code null}.
   * @param thirdPart  The third part, corresponding to the signature.
   *                   Must not be {@code null}.
   *
   * @throws ParseException If parsing of the serialised parts failed.
   */
  JWSObject.fromParts(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart) :
  this._header = JWSHeader.parseBase64Url(firstPart),
  _signingInputString = _composeSigningInput(firstPart, secondPart) {

    if (firstPart == null) {
      throw new ArgumentError.notNull("firstPart");
    }

//    try {
//      this._header = JWSHeader.parse(firstPart);
//    } catch (e) {
//      // ParseException
//      throw new ParseError("Invalid JWS header: " + e.getMessage(), 0);
//    }

    if (secondPart == null) {
      throw new ArgumentError.notNull("secondPart");
    }

    setPayload(new Payload(secondPart));


    if (thirdPart == null) {
      throw new ArgumentError.notNull("thirdPart");
    }

    _signature = thirdPart;

    _state = JWSObjectState.SIGNED; // but signature not verified yet!

    setParsedParts([firstPart, secondPart, thirdPart]);
  }

  @override
  JWSHeader getHeader() {

    return _header;
  }

  /**
   * Composes the signing input for the specified JWS object parts.
   *
   * <p>Format:
   *
   * <pre>
   * [header-base64url].[payload-base64url]
   * </pre>
   *
   * @param firstPart  The first part, corresponding to the JWS header.
   *                   Must not be {@code null}.
   * @param secondPart The second part, corresponding to the payload.
   *                   Must not be {@code null}.
   *
   * @return The signing input string.
   */
  static String _composeSigningInput(final Base64URL firstPart, final Base64URL secondPart) {

    StringBuffer sb = new StringBuffer(firstPart.toString());
    sb.write('.');
    sb.write(secondPart.toString());
    return sb.toString();
  }

  /**
   * Returns the signing input for this JWS object.
   *
   * <p>Format:
   *
   * <pre>
   * [header-base64url].[payload-base64url]
   * </pre>
   *
   * @return The signing input, to be passed to a JWS signer or verifier.
   */
  Uint8List getSigningInput() {

    return _signingInputString.getBytes(Charset.forName("UTF-8"));
  }

//	/**
//	 * @deprecated Use {@link #getSigningInput} instead.
//	 */
//	@Deprecated
//	byte[] getSignableContent() {
//
//		return getSigningInput();
//	}

  /**
   * Returns the signature of this JWS object.
   *
   * @return The signature, {@code null} if the JWS object is not signed
   *         yet.
   */
  Base64URL getSignature() {

    return _signature;
  }

  /**
   * Returns the state of this JWS object.
   *
   * @return The state.
   */
  JWSObjectState _getState() {

    return _state;
  }

  /**
   * Ensures the current state is {@link State#UNSIGNED unsigned}.
   *
   * @throws IllegalStateException If the current state is not unsigned.
   */
  void _ensureUnsignedState() {

    if (_state != JWSObjectState.UNSIGNED) {
      throw new StateError("The JWS object must be in an unsigned state");
    }
  }

  /**
   * Ensures the current state is {@link State#SIGNED signed} or
   * {@link State#VERIFIED verified}.
   *
   * @throws IllegalStateException If the current state is not signed or
   *                               verified.
   */
  void _ensureSignedOrVerifiedState() {

    if (_state != JWSObjectState.SIGNED && _state != JWSObjectState.VERIFIED) {

      throw new StateError("The JWS object must be in a signed or verified state");
    }
  }

  /**
   * Ensures the specified JWS signer supports the algorithm of this JWS
   * object.
   *
   * @throws JOSEException If the JWS algorithm is not supported.
   */
  void _ensureJWSSignerSupport(final JWSSigner signer) {

    if (!signer.supportedAlgorithms().contains(getHeader().getAlgorithm())) {

      throw new JOSEException("The \"" + getHeader().getAlgorithm().toString() +
      "\" algorithm is not supported by the JWS signer");
    }
  }

  /**
   * Ensures the specified JWS verifier accepts the algorithm and the headers
   * of this JWS object.
   *
   * @throws JOSEException If the JWS algorithm or headers are not accepted.
   */
  void _ensureJWSVerifierAcceptance(final JWSVerifier verifier) {

    if (!verifier.getAcceptedAlgorithms().contains(getHeader().getAlgorithm())) {

      throw new JOSEException("The \"" + getHeader().getAlgorithm().toString() +
      "\" algorithm is not accepted by the JWS verifier");
    }
  }

  /**
   * Signs this JWS object with the specified signer. The JWS object must
   * be in a {@link State#UNSIGNED unsigned} state.
   *
   * @param signer The JWS signer. Must not be {@code null}.
   *
   * @throws IllegalStateException If the JWS object is not in an
   *                               {@link State#UNSIGNED unsigned state}.
   * @throws JOSEException         If the JWS object couldn't be signed.
   */
  void sign(final JWSSigner signer) {

    _ensureUnsignedState();

    _ensureJWSSignerSupport(signer);

    try {
      _signature = signer.sign(getHeader(), getSigningInput());

    } catch (e) {
// JOSEException
      if (e is JOSEException)
        throw e;

//		} catch (Exception e) {

      // Prevent throwing unchecked exceptions at this point,
      // see issue #20
      throw new JOSEException.withCause(e.toString(), e);
    }

    _state = JWSObjectState.SIGNED;
  }

  /**
   * Checks the signature of this JWS object with the specified verifier.
   * The JWS object must be in a {@link State#SIGNED signed} state.
   *
   * @param verifier The JWS verifier. Must not be {@code null}.
   *
   * @return {@code true} if the signature was successfully verified,
   *         else {@code false}.
   *
   * @throws IllegalStateException If the JWS object is not in a
   *                               {@link State#SIGNED signed} or
   *                               {@link State#VERIFIED verified state}.
   * @throws JOSEException         If the JWS object couldn't be verified.
   */
  bool verify(final JWSVerifier verifier) {

    _ensureSignedOrVerifiedState();

    _ensureJWSVerifierAcceptance(verifier);

    bool verified;

    try {
      verified = verifier.verify(getHeader(), getSigningInput(), getSignature());

    } catch (e) {
      if (e is JOSEException)
        throw e;

//		} catch (Exception e) {

      // Prevent throwing unchecked exceptions at this point,
      // see issue #20
      throw new JOSEException.withCause(e.toString(), e);
    }

    if (verified) {

      _state = JWSObjectState.VERIFIED;
    }

    return verified;
  }

  /**
   * Serialises this JWS object to its compact format consisting of
   * Base64URL-encoded parts delimited by period ('.') characters. It
   * must be in a {@link State#SIGNED signed} or
   * {@link State#VERIFIED verified} state.
   *
   * <pre>
   * [header-base64url].[payload-base64url].[signature-base64url]
   * </pre>
   *
   * @return The serialised JWS object.
   *
   * @throws IllegalStateException If the JWS object is not in a
   *                               {@link State#SIGNED signed} or
   *                               {@link State#VERIFIED verified} state.
   */
  @override
  String serialize() {

    _ensureSignedOrVerifiedState();

    StringBuffer sb = new StringBuffer(_signingInputString);
    sb.write('.');
    sb.write(_signature.toString());
    return sb.toString();
  }

  /**
   * Parses a JWS object from the specified string in compact format. The
   * parsed JWS object will be given a {@link State#SIGNED} state.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The JWS object.
   *
   * @throws ParseException If the string couldn't be parsed to a valid
   *                        JWS object.
   */
  static JWSObject parse(final String s) {

    List<Base64URL> parts = JOSEObject.split(s);

    if (parts.length != 3) {

      throw new ParseError("Unexpected number of Base64URL parts, must be three", 0);
    }

    return new JWSObject.fromParts(parts[0], parts[1], parts[2]);
  }

}
