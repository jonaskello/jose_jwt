part of jose_jwt.jose;

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
class PlainHeaderBuilder {

  /**
   * The JOSE object type.
   */
  JOSEObjectType _typ;

  /**
   * The content type.
   */
  String _cty;

  /**
   * The critical headers.
   */
  Set<String> _crit;

  /**
   * Custom header parameters.
   */
  Map<String, Object> _customParams;

  /**
   * The parsed Base64URL.
   */
  Base64URL _parsedBase64URL;

  /**
   * Creates a new plain header builder.
   */
  PlainHeaderBuilder() {
  }

  /**
   * Creates a new plain header builder with the parameters from
   * the specified header.
   *
   * @param plainHeader The plain header to use. Must not be
   *                    {@code null}.
   */
  PlainHeaderBuilder.fromHeader(final PlainHeader plainHeader) {

    _typ = plainHeader.getType();
    _cty = plainHeader.getContentType();
    _crit = plainHeader.getCriticalParams();
    _customParams = plainHeader.getCustomParams();
  }

  /**
   * Sets the type ({@code typ}) parameter.
   *
   * @param typ The type parameter, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  PlainHeaderBuilder type(final JOSEObjectType typ) {
    _typ = typ;
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
  PlainHeaderBuilder contentType(final String cty) {
    _cty = cty;
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
  PlainHeaderBuilder criticalParams(final Set<String> crit) {
    _crit = crit;
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
  PlainHeaderBuilder customParam(final String name, final Object value) {

    if (PlainHeader.getRegisteredParameterNames().contains(name)) {
      throw new ArgumentError("The parameter name \"" + name + "\" matches a registered name");
    }

    if (_customParams == null) {
      _customParams = new Map();
    }

    _customParams[name] = value;

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
  PlainHeaderBuilder customParams(final Map<String, Object> customParameters) {

    _customParams = customParameters;
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
  PlainHeaderBuilder parsedBase64URL(final Base64URL base64URL) {

    _parsedBase64URL = base64URL;
    return this;
  }

  /**
   * Builds a new plain header.
   *
   * @return The plain header.
   */
  PlainHeader build() {

    return new PlainHeader(_typ, _cty, _crit, _customParams, _parsedBase64URL);
  }

}


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

  /**
   * The registered parameter names.
   */
  static final Set<String> _REGISTERED_PARAMETER_NAMES = new UnmodifiableSetView(new Set.from(
      [
          "alg",
          "typ",
          "cty",
          "crit",
      ]
  ));

//	/**
//	 * Initialises the registered parameter name set.
//	 */
//	static a() {
//		Set<String> p = ;
//
//		p.add("alg");
//		p.add("typ");
//		p.add("cty");
//		p.add("crit");
//
//		REGISTERED_PARAMETER_NAMES = new UnmodifiableSet(p);
//	}


  /**
   * Creates a new minimal plain header with algorithm
   * {@link Algorithm#NONE none}.
   */
  PlainHeader.minimal() : this(null, null, null, null, null);

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
              final Base64URL parsedBase64URL) : super(Algorithm.NONE, typ, cty, crit, customParams, parsedBase64URL);

  /**
   * Deep copy constructor.
   *
   * @param plainHeader The plain header to copy. Must not be
   *                    {@code null}.
   */
  PlainHeader.deepCopy(final PlainHeader plainHeader) :
  this(
      plainHeader.getType(),
      plainHeader.getContentType(),
      plainHeader.getCriticalParams(),
      plainHeader.getCustomParams(),
      plainHeader.getParsedBase64URL()
  );

  /**
   * Gets the registered parameter names for plain headers.
   *
   * @return The registered parameter names, as an unmodifiable set.
   */
  static Set<String> getRegisteredParameterNames() {

    return _REGISTERED_PARAMETER_NAMES;
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
  static PlainHeader parseJsonObject(final JSONObject jsonObject) {

    return parseJsonObjectAndUrl(jsonObject, null);
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
  static PlainHeader parseJsonObjectAndUrl(final JSONObject jsonObject,
                                           final Base64URL parsedBase64URL) {

    // Get the "alg" parameter
    Algorithm alg = Header.parseAlgorithm(jsonObject);

    if (alg != Algorithm.NONE) {
      throw new ParseError("The algorithm \"alg\" header parameter must be \"none\"", 0);
    }

    PlainHeaderBuilder header = new PlainHeaderBuilder().parsedBase64URL(parsedBase64URL);

    // Parse optional + custom parameters
    for (final String name in jsonObject.keySet()) {

      if ("alg" == name) {
        // skip
      } else if ("typ" == name) {
        header = header.type(new JOSEObjectType(JSONObjectUtils.getString(jsonObject, name)));
      } else if ("cty" == name) {
        header = header.contentType(JSONObjectUtils.getString(jsonObject, name));
      } else if ("crit" == name) {
        header = header.criticalParams(new Set.from(JSONObjectUtils.getStringList(jsonObject, name)));
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
	static PlainHeader parseJsonString(final String jsonString) {

		return parseJsonStringAndUrl(jsonString, null);
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
	static PlainHeader parseJsonStringAndUrl(final String jsonString,
					final Base64URL parsedBase64URL) {

		return parseJsonObjectAndUrl(JSONObjectUtils.parseJSONObject(jsonString), parsedBase64URL);
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
	static PlainHeader parseBase64Url(final Base64URL base64URL) {

		return parseJsonStringAndUrl(base64URL.decodeToString(), base64URL);
	}

}
