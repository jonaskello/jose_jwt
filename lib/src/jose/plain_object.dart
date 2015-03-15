part of jose_jwt.jose;

/**
 * Plaintext (unsecured) JOSE object. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-08)
 */
class PlainObject extends JOSEObject {


	/*

	/**
	 * The header.
	 */
	private final PlainHeader header;


	/**
	 * Creates a new plaintext JOSE object with a default 
	 * {@link PlainHeader} and the specified payload.
	 *
	 * @param payload The payload. Must not be {@code null}.
	 */
	PlainObject(final Payload payload) {

		if (payload == null) {

			throw new IllegalArgumentException("The payload must not be null");
		}

		setPayload(payload);

		header = new PlainHeader();
	}


	/**
	 * Creates a new plaintext JOSE object with the specified header and 
	 * payload.
	 *
	 * @param header  The plaintext header. Must not be {@code null}.
	 * @param payload The payload. Must not be {@code null}.
	 */
	PlainObject(final PlainHeader header, final Payload payload) {

		if (header == null) {

			throw new IllegalArgumentException("The plain header must not be null");
		}

		this.header = header;

		if (payload == null) {

			throw new IllegalArgumentException("The payload must not be null");
		}

		setPayload(payload);
	}


	/**
	 * Creates a new plaintext JOSE object with the specified 
	 * Base64URL-encoded parts.
	 *
	 * @param firstPart  The first part, corresponding to the plaintext 
	 *                   header. Must not be {@code null}.
	 * @param secondPart The second part, corresponding to the payload. 
	 *                   Must not be {@code null}.
	 *
	 * @throws ParseException If parsing of the serialised parts failed.
	 */
	PlainObject(final Base64URL firstPart, final Base64URL secondPart)
		throws ParseException {

		if (firstPart == null) {

			throw new IllegalArgumentException("The first part must not be null");
		}

		try {
			header = PlainHeader.parse(firstPart);

		} catch (ParseException e) {

			throw new ParseException("Invalid plain header: " + e.getMessage(), 0);
		}

		if (secondPart == null) {

			throw new IllegalArgumentException("The second part must not be null");
		}

		setPayload(new Payload(secondPart));

		setParsedParts(firstPart, secondPart, null);
	}


	@override
	PlainHeader getHeader() {

		return header;
	}


	/**
	 * Serialises this plaintext JOSE object to its compact format 
	 * consisting of Base64URL-encoded parts delimited by period ('.') 
	 * characters.
	 *
	 * <pre>
	 * [header-base64url].[payload-base64url].[]
	 * </pre>
	 *
	 * @return The serialised plaintext JOSE object.
	 */
	@override
	String serialize() {

		StringBuilder sb = new StringBuilder(header.toBase64URL().toString());
		sb.append('.');
		sb.append(getPayload().toBase64URL().toString());
		sb.append('.');
		return sb.toString();
	}


	/**
	 * Parses a plaintext JOSE object from the specified string in compact 
	 * format.
	 *
	 * @param s The string to parse. Must not be {@code null}.
	 *
	 * @return The plain JOSE object.
	 *
	 * @throws ParseException If the string couldn't be parsed to a valid 
	 *                        plaintext JOSE object.
	 */
	static PlainObject parse(final String s)
		throws ParseException {

		Base64URL[] parts = JOSEObject.split(s);

		if (! parts[2].toString().isEmpty()) {
			
			throw new ParseException("Unexpected third Base64URL part", 0);
		}

		return new PlainObject(parts[0], parts[1]);
	}

*/

}
