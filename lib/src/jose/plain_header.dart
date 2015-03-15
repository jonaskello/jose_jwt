part of jose_jwt.jose;

/**
 * Plaintext (unsecured) JOSE header.
 *
 * <p>Supports all {@link #getRegisteredParameterNames registered header
 * parameters} of the plain specification:
 *
 * <ul>
 *     <li>alg (set to {@link Algorithm#NONE "none"}).
 *     <li>typ
 *     <li>cty
 *     <li>crit
 * </ul>
 *
 * <p>The header may also carry {@link #getCustomParams custom parameters};
 * these will be serialised and parsed along the registered ones.
 *
 * <p>Example:
 *
 * <pre>
 * {
 *   "alg" : "none"
 * }
 * </pre>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 */
//@Immutable
class PlainHeader extends Header {


/*

	/**
	 * The registered parameter names.
	 */
	private static final Set<String> REGISTERED_PARAMETER_NAMES;


	/**
	 * Initialises the registered parameter name set.
	 */
	static {
		Set<String> p = new HashSet<>();

		p.add("alg");
		p.add("typ");
		p.add("cty");
		p.add("crit");

		REGISTERED_PARAMETER_NAMES = Collections.unmodifiableSet(p);
	}


	/**
	 * Builder for constructing plain headers.
	 *
	 * <p>Example use:
	 *
	 * <pre>
	 * PlainHeader header = new PlainHeader.Builder().
	 *                      contentType("text/plain").
	 *                      customParam("exp", new Date().getTime()).
	 *                      build();
	 * </pre>
	 */
	static class Builder {


		/**
		 * The JOSE object type.
		 */
		private JOSEObjectType typ;


		/**
		 * The content type.
		 */
		private String cty;


		/**
		 * The critical headers.
		 */
		private Set<String> crit;


		/**
		 * Custom header parameters.
		 */
		private Map<String,Object> customParams;


		/**
		 * The parsed Base64URL.
		 */
		private Base64URL parsedBase64URL;


		/**
		 * Creates a new plain header builder.
		 */
		Builder() {

		}


		/**
		 * Creates a new plain header builder with the parameters from
		 * the specified header.
		 *
		 * @param plainHeader The plain header to use. Must not be
		 *                    {@code null}.
		 */
		Builder(final PlainHeader plainHeader) {

			typ = plainHeader.getType();
			cty = plainHeader.getContentType();
			crit = plainHeader.getCriticalParams();
			customParams = plainHeader.getCustomParams();
		}


		/**
		 * Sets the type ({@code typ}) parameter.
		 *
		 * @param typ The type parameter, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		Builder type(final JOSEObjectType typ) {

			this.typ = typ;
			return this;
		}


		/**
		 * Sets the content type ({@code cty}) parameter.
		 *
		 * @param cty The content type parameter, {@code null} if not
		 *            specified.
		 *
		 * @return This builder.
		 */
		Builder contentType(final String cty) {

			this.cty = cty;
			return this;
		}


		/**
		 * Sets the critical header parameters ({@code crit})
		 * parameter.
		 *
		 * @param crit The names of the critical header parameters,
		 *             empty set or {@code null} if none.
		 *
		 * @return This builder.
		 */
		Builder criticalParams(final Set<String> crit) {

			this.crit = crit;
			return this;
		}


		/**
		 * Sets a custom (non-registered) parameter.
		 *
		 * @param name  The name of the custom parameter. Must not
		 *              match a registered parameter name and must not
		 *              be {@code null}.
		 * @param value The value of the custom parameter, should map
		 *              to a valid JSON entity, {@code null} if not
		 *              specified.
		 *
		 * @return This builder.
		 *
		 * @throws IllegalArgumentException If the specified parameter
		 *                                  name matches a registered
		 *                                  parameter name.
		 */
		Builder customParam(final String name, final Object value) {

			if (getRegisteredParameterNames().contains(name)) {
				throw new IllegalArgumentException("The parameter name \"" + name + "\" matches a registered name");
			}

			if (customParams == null) {
				customParams = new HashMap<>();
			}

			customParams.put(name, value);

			return this;
		}


		/**
		 * Sets the custom (non-registered) parameters. The values must
		 * be serialisable to a JSON entity, otherwise will be ignored.
		 *
		 * @param customParameters The custom parameters, empty map or
		 *                         {@code null} if none.
		 *
		 * @return This builder.
		 */
		Builder customParams(final Map<String, Object> customParameters) {

			this.customParams = customParameters;
			return this;
		}


		/**
		 * Sets the parsed Base64URL.
		 *
		 * @param base64URL The parsed Base64URL, {@code null} if the
		 *                  header is created from scratch.
		 *
		 * @return This builder.
		 */
		Builder parsedBase64URL(final Base64URL base64URL) {

			this.parsedBase64URL = base64URL;
			return this;
		}


		/**
		 * Builds a new plain header.
		 *
		 * @return The plain header.
		 */
		PlainHeader build() {

			return new PlainHeader(typ, cty, crit, customParams, parsedBase64URL);
		}
	}


	/**
	 * Creates a new minimal plain header with algorithm
	 * {@link Algorithm#NONE none}.
	 */
	PlainHeader() {

		this(null, null, null, null, null);
	}


	/**
	 * Creates a new plain header with algorithm
	 * {@link Algorithm#NONE none}.
	 *
	 * @param typ             The type ({@code typ}) parameter,
	 *                        {@code null} if not specified.
	 * @param cty             The content type ({@code cty}) parameter,
	 *                        {@code null} if not specified.
	 * @param crit            The names of the critical header
	 *                        ({@code crit}) parameters, empty set or
	 *                        {@code null} if none.
	 * @param customParams    The custom parameters, empty map or
	 *                        {@code null} if none.
	 * @param parsedBase64URL The parsed Base64URL, {@code null} if the
	 *                        header is created from scratch.
	 */
	PlainHeader(final JOSEObjectType typ,
			   final String cty,
			   final Set<String> crit,
			   final Map<String, Object> customParams,
			   final Base64URL parsedBase64URL) {

		super(Algorithm.NONE, typ, cty, crit, customParams, parsedBase64URL);
	}


	/**
	 * Deep copy constructor.
	 *
	 * @param plainHeader The plain header to copy. Must not be
	 *                    {@code null}.
	 */
	PlainHeader(final PlainHeader plainHeader) {

		this(
			plainHeader.getType(),
			plainHeader.getContentType(),
			plainHeader.getCriticalParams(),
			plainHeader.getCustomParams(),
			plainHeader.getParsedBase64URL()
		);
	}


	/**
	 * Gets the registered parameter names for plain headers.
	 *
	 * @return The registered parameter names, as an unmodifiable set.
	 */
	static Set<String> getRegisteredParameterNames() {

		return REGISTERED_PARAMETER_NAMES;
	}


	/**
	 * Gets the algorithm ({@code alg}) parameter.
	 *
	 * @return {@link Algorithm#NONE}.
	 */
	@override
	Algorithm getAlgorithm() {

		return Algorithm.NONE;
	}


	/**
	 * Parses a plain header from the specified JSON object.
	 *
	 * @param jsonObject      The JSON object to parse. Must not be
	 *                        {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON object doesn't
	 *                        represent a valid plain header.
	 */
	static PlainHeader parse(final JSONObject jsonObject)
		throws ParseException {

		return parse(jsonObject, null);
	}


	/**
	 * Parses a plain header from the specified JSON object.
	 *
	 * @param jsonObject      The JSON object to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON object doesn't
	 *                        represent a valid plain header.
	 */
	static PlainHeader parse(final JSONObject jsonObject,
					final Base64URL parsedBase64URL)
		throws ParseException {

		// Get the "alg" parameter
		Algorithm alg = Header.parseAlgorithm(jsonObject);

		if (alg != Algorithm.NONE) {
			throw new ParseException("The algorithm \"alg\" header parameter must be \"none\"", 0);
		}

		PlainHeader.Builder header = new Builder().parsedBase64URL(parsedBase64URL);

		// Parse optional + custom parameters
		for(final String name: jsonObject.keySet()) {


			
			if("alg".equals(name)) {
				// skip
			} else if("typ".equals(name)) {
				header = header.type(new JOSEObjectType(JSONObjectUtils.getString(jsonObject, name)));
			} else if("cty".equals(name)) {
				header = header.contentType(JSONObjectUtils.getString(jsonObject, name));
			} else if("crit".equals(name)) {
				header = header.criticalParams(new HashSet<>(JSONObjectUtils.getStringList(jsonObject, name)));
			} else {
				header = header.customParam(name, jsonObject.get(name));
			}
		}

		return header.build();
	}


	/**
	 * Parses a plain header from the specified JSON string.
	 *
	 * @param jsonString The JSON string to parse. Must not be
	 *                   {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON string doesn't
	 *                        represent a valid plain header.
	 */
	static PlainHeader parse(final String jsonString)
		throws ParseException {

		return parse(jsonString, null);
	}


	/**
	 * Parses a plain header from the specified JSON string.
	 *
	 * @param jsonString      The JSON string to parse. Must not be
	 *                        {@code null}.
	 * @param parsedBase64URL The original parsed Base64URL, {@code null}
	 *                        if not applicable.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified JSON string doesn't 
	 *                        represent a valid plain header.
	 */
	static PlainHeader parse(final String jsonString,
					final Base64URL parsedBase64URL)
		throws ParseException {

		return parse(JSONObjectUtils.parseJSONObject(jsonString), parsedBase64URL);
	}


	/**
	 * Parses a plain header from the specified Base64URL.
	 *
	 * @param base64URL The Base64URL to parse. Must not be {@code null}.
	 *
	 * @return The plain header.
	 *
	 * @throws ParseException If the specified Base64URL doesn't represent
	 *                        a valid plain header.
	 */
	static PlainHeader parse(final Base64URL base64URL)
		throws ParseException {

		return parse(base64URL.decodeToString(), base64URL);
	}
	*/

}
