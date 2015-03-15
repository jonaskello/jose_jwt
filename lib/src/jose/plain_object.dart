part of jose_jwt.jose;

/**
 * Plaintext (unsecured) JOSE object. This class is thread-safe.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-08)
 */
class PlainObject extends JOSEObject {

  /**
   * The header.
   */
  final PlainHeader _header;

  /**
   * Creates a new plaintext JOSE object with a default
   * {@link PlainHeader} and the specified payload.
   *
   * @param payload The payload. Must not be {@code null}.
   */
  PlainObject.payloadOnly(final Payload payload)
  :  _header = new PlainHeader.minimal() {

    if (payload == null) {

      throw new ArgumentError.notNull("payload");
    }

    setPayload(payload);

  }

  /**
   * Creates a new plaintext JOSE object with the specified header and
   * payload.
   *
   * @param header  The plaintext header. Must not be {@code null}.
   * @param payload The payload. Must not be {@code null}.
   */
  PlainObject(final PlainHeader header, final Payload payload)
  : _header = header {

    if (_header == null) {
      throw new ArgumentError.notNull("header");
    }

    if (payload == null) {
      throw new ArgumentError.notNull("payload");
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
  PlainObject.fromParts(final Base64URL firstPart, final Base64URL secondPart)
  : _header = PlainHeader.parseBase64Url(firstPart) {

    if (firstPart == null) {
      throw new ArgumentError.notNull("firstPart");
    }

//    try {
//      _header = PlainHeader.parse(firstPart);
//
//    } catch (e) {
//      if (e is ParseError)
//        throw new ParseError("Invalid plain header: " + e.toString(), 0);
//    }

    if (secondPart == null) {
      throw new ArgumentError.notNull("secondPart");
    }

    setPayload(new Payload(secondPart));

    setParsedParts([firstPart, secondPart, null]);
  }

	@override
	PlainHeader getHeader() {
		return _header;
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

		StringBuffer sb = new StringBuffer(_header.toBase64URL().toString());
		sb.write('.');
		sb.write(getPayload().toBase64URL().toString());
		sb.write('.');
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
	static PlainObject parse(final String s) {

		List<Base64URL> parts = JOSEObject.split(s);

		if (! parts[2].toString().isEmpty) {
			
			throw new ParseError("Unexpected third Base64URL part", 0);
		}

		return new PlainObject.fromParts(parts[0], parts[1]);
	}

}
