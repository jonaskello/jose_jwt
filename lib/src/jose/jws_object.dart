part of jose_jwt.jose;

/**
 * JSON Web Signature (JWS) object. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
class JWSObject extends JOSEObject {

/*

	/**
	 * Enumeration of the states of a JSON Web Signature (JWS) object.
	 */
	static enum State {


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
	 * The header.
	 */
	private final JWSHeader header;


	/**
	 * The signing input for this JWS object.
	 *
	 * <p>Format:
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url]
	 * </pre>
	 */
	private final String signingInputString;


	/**
	 * The signature, {@code null} if not signed.
	 */
	private Base64URL signature;


	/**
	 * The JWS object state.
	 */
	private State state;


	/**
	 * Creates a new to-be-signed JSON Web Signature (JWS) object with the 
	 * specified header and payload. The initial state will be 
	 * {@link State#UNSIGNED unsigned}.
	 *
	 * @param header  The JWS header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	JWSObject(final JWSHeader header, final Payload payload) {

		if (header == null) {

			throw new IllegalArgumentException("The JWS header must not be null");
		}

		this.header = header;

		if (payload == null) {

			throw new IllegalArgumentException("The payload must not be null");
		}

		setPayload(payload);

		signingInputString = composeSigningInput(header.toBase64URL(), payload.toBase64URL());

		signature = null;

		state = State.UNSIGNED;
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
	JWSObject(final Base64URL firstPart, final Base64URL secondPart, final Base64URL thirdPart)
		throws ParseException {

		if (firstPart == null) {

			throw new IllegalArgumentException("The first part must not be null");
		}

		try {
			this.header = JWSHeader.parse(firstPart);

		} catch (ParseException e) {

			throw new ParseException("Invalid JWS header: " + e.getMessage(), 0);
		}

		if (secondPart == null) {

			throw new IllegalArgumentException("The second part must not be null");
		}

		setPayload(new Payload(secondPart));

		signingInputString = composeSigningInput(firstPart, secondPart);

		if (thirdPart == null) {
			throw new IllegalArgumentException("The third part must not be null");
		}

		signature = thirdPart;

		state = State.SIGNED; // but signature not verified yet!

		setParsedParts(firstPart, secondPart, thirdPart);
	}


	@override
	JWSHeader getHeader() {

		return header;
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
	private static String composeSigningInput(final Base64URL firstPart, final Base64URL secondPart) {

		StringBuilder sb = new StringBuilder(firstPart.toString());
		sb.append('.');
		sb.append(secondPart.toString());
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
	byte[] getSigningInput() {

		return signingInputString.getBytes(Charset.forName("UTF-8"));
	}


	/**
	 * @deprecated Use {@link #getSigningInput} instead.
	 */
	@Deprecated
	byte[] getSignableContent() {

		return getSigningInput();
	}


	/**
	 * Returns the signature of this JWS object.
	 *
	 * @return The signature, {@code null} if the JWS object is not signed 
	 *         yet.
	 */
	Base64URL getSignature() {

		return signature;
	}


	/**
	 * Returns the state of this JWS object.
	 *
	 * @return The state.
	 */
	State getState() {

		return state;
	}


	/**
	 * Ensures the current state is {@link State#UNSIGNED unsigned}.
	 *
	 * @throws IllegalStateException If the current state is not unsigned.
	 */
	private void ensureUnsignedState() {

		if (state != State.UNSIGNED) {

			throw new IllegalStateException("The JWS object must be in an unsigned state");
		}
	}


	/**
	 * Ensures the current state is {@link State#SIGNED signed} or
	 * {@link State#VERIFIED verified}.
	 *
	 * @throws IllegalStateException If the current state is not signed or
	 *                               verified.
	 */
	private void ensureSignedOrVerifiedState() {

		if (state != State.SIGNED && state != State.VERIFIED) {

			throw new IllegalStateException("The JWS object must be in a signed or verified state");
		}
	}


	/**
	 * Ensures the specified JWS signer supports the algorithm of this JWS
	 * object.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported.
	 */
	private void ensureJWSSignerSupport(final JWSSigner signer)
		throws JOSEException {

		if (! signer.supportedAlgorithms().contains(getHeader().getAlgorithm())) {

			throw new JOSEException("The \"" + getHeader().getAlgorithm() + 
			                        "\" algorithm is not supported by the JWS signer");
		}
	}


	/**
	 * Ensures the specified JWS verifier accepts the algorithm and the headers 
	 * of this JWS object.
	 *
	 * @throws JOSEException If the JWS algorithm or headers are not accepted.
	 */
	private void ensureJWSVerifierAcceptance(final JWSVerifier verifier)
		throws JOSEException {

		if (! verifier.getAcceptedAlgorithms().contains(getHeader().getAlgorithm())) {

			throw new JOSEException("The \"" + getHeader().getAlgorithm() + 
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
	synchronized void sign(final JWSSigner signer)
		throws JOSEException {

		ensureUnsignedState();

		ensureJWSSignerSupport(signer);

		try {
			signature = signer.sign(getHeader(), getSigningInput());

		} catch (JOSEException e) {

			throw e;
				
		} catch (Exception e) {

			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		state = State.SIGNED;
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
	synchronized boolean verify(final JWSVerifier verifier)
		throws JOSEException {

		ensureSignedOrVerifiedState();

		ensureJWSVerifierAcceptance(verifier);

		boolean verified;

		try {
			verified = verifier.verify(getHeader(), getSigningInput(), getSignature());

		} catch (JOSEException e) {

			throw e;

		} catch (Exception e) {

			// Prevent throwing unchecked exceptions at this point,
			// see issue #20
			throw new JOSEException(e.getMessage(), e);
		}

		if (verified) {

			state = State.VERIFIED;
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

		ensureSignedOrVerifiedState();

		StringBuilder sb = new StringBuilder(signingInputString);
		sb.append('.');
		sb.append(signature.toString());
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
	static JWSObject parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (parts.length != 3) {

			throw new ParseException("Unexpected number of Base64URL parts, must be three", 0);
		}

		return new JWSObject(parts[0], parts[1], parts[2]);
	}
*/

}
