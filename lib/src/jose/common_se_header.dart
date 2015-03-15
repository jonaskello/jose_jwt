part of jose_jwt.jose;

/**
 * Common class for JWS and JWE headers.
 *
 * <p>Supports all registered header parameters shared by the JWS and JWE
 * specifications:
 *
 * <ul>
 *     <li>alg
 *     <li>jku
 *     <li>jwk
 *     <li>x5u
 *     <li>x5t
 *     <li>x5t#S256
 *     <li>x5c
 *     <li>kid
 *     <li>typ
 *     <li>cty
 *     <li>crit
 * </ul>
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-19)
 */
abstract class CommonSEHeader extends Header {

  /**
   * JWK Set URL, {@code null} if not specified.
   */
  final Uri _jku;

  /**
   * JWK, {@code null} if not specified.
   */
  final JWK _jwk;

  /**
   * X.509 certificate URL, {@code null} if not specified.
   */
  final Uri _x5u;

  /**
   * X.509 certificate SHA-1 thumbprint, {@code null} if not specified.
   */
  final Base64URL _x5t;

  /**
   * X.509 certificate SHA-256 thumbprint, {@code null} if not specified.
   */
  final Base64URL _x5t256;

  /**
   * The X.509 certificate chain corresponding to the key used to sign or
   * encrypt the JWS / JWE object, {@code null} if not specified.
   */
  final List<Base64> _x5c;

  /**
   * Key ID, {@code null} if not specified.
   */
  final String _kid;

  /**
   * Creates a new common JWS and JWE header.
   *
   * @param alg             The algorithm ({@code alg}) parameter. Must
   *                        not be {@code null}.
   * @param typ             The type ({@code typ}) parameter,
   *                        {@code null} if not specified.
   * @param cty             The content type ({@code cty}) parameter,
   *                        {@code null} if not specified.
   * @param crit            The names of the critical header
   *                        ({@code crit}) parameters, empty set or
   *                        {@code null} if none.
   * @param jku             The JSON Web Key (JWK) Set URL ({@code jku})
   *                        parameter, {@code null} if not specified.
   * @param jwk             The X.509 certificate URL ({@code jwk})
   *                        parameter, {@code null} if not specified.
   * @param x5u             The X.509 certificate URL parameter
   *                        ({@code x5u}), {@code null} if not specified.
   * @param x5t             The X.509 certificate SHA-1 thumbprint
   *                        ({@code x5t}) parameter, {@code null} if not
   *                        specified.
   * @param x5t256          The X.509 certificate SHA-256 thumbprint
   *                        ({@code x5t#S256}) parameter, {@code null} if
   *                        not specified.
   * @param x5c             The X.509 certificate chain ({@code x5c})
   *                        parameter, {@code null} if not specified.
   * @param kid             The key ID ({@code kid}) parameter,
   *                        {@code null} if not specified.
   * @param customParams    The custom parameters, empty map or
   *                        {@code null} if none.
   * @param parsedBase64URL The parsed Base64URL, {@code null} if the
   *                        header is created from scratch.
   */
  CommonSEHeader(final Algorithm alg,
                 final JOSEObjectType typ,
                 final String cty,
                 final Set<String> crit,
                 this._jku,
                 this._jwk,
                 this._x5u,
                 this._x5t,
                 this._x5t256,
                 final List<Base64> x5c,
                 this._kid,
                 final Map<String, Object> customParams,
                 final Base64URL parsedBase64URL)
  : super(alg, typ, cty, crit, customParams, parsedBase64URL),
  this._x5c = x5c != null ? new UnmodifiableListView([x5c]) : null {

//		this._jku = jku;
//		this._jwk = jwk;
//		this._x5u = x5u;
//		this._x5t = x5t;
//		this._x5t256 = x5t256;

//    if (x5c != null) {
//      // Copy and make unmodifiable
//      this._x5c = new UnmodifiableListView([x5c]);
//    } else {
//      this._x5c = null;
//    }

//    this.kid = kid;
  }

  /**
   * Gets the JSON Web Key (JWK) Set URL ({@code jku}) parameter.
   *
   * @return The JSON Web Key (JWK) Set URL parameter, {@code null} if
   *         not specified.
   */
  Uri getJWKURL() {

    return _jku;
  }

  /**
   * Gets the JSON Web Key (JWK) ({@code jwk}) parameter.
   *
   * @return The JSON Web Key (JWK) parameter, {@code null} if not
   *         specified.
   */
  JWK getJWK() {

    return _jwk;
  }

  /**
   * Gets the X.509 certificate URL ({@code x5u}) parameter.
   *
   * @return The X.509 certificate URL parameter, {@code null} if not
   *         specified.
   */
  Uri getX509CertURL() {

    return _x5u;
  }

  /**
   * Gets the X.509 certificate SHA-1 thumbprint ({@code x5t}) parameter.
   *
   * @return The X.509 certificate SHA-1 thumbprint parameter,
   *         {@code null} if not specified.
   */
  Base64URL getX509CertThumbprint() {

    return _x5t;
  }

  /**
   * Gets the X.509 certificate SHA-256 thumbprint ({@code x5t#S256})
   * parameter.
   *
   * @return The X.509 certificate SHA-256 thumbprint parameter,
   *         {@code null} if not specified.
   */
  Base64URL getX509CertSHA256Thumbprint() {

    return _x5t256;
  }

  /**
   * Gets the X.509 certificate chain ({@code x5c}) parameter
   * corresponding to the key used to sign or encrypt the JWS / JWE
   * object.
   *
   * @return The X.509 certificate chain parameter as a unmodifiable
   *         list, {@code null} if not specified.
   */
  List<Base64> getX509CertChain() {

    return _x5c;
  }

  /**
   * Gets the key ID ({@code kid}) parameter.
   *
   * @return The key ID parameter, {@code null} if not specified.
   */
  String getKeyID() {

    return _kid;
  }

  @override
  Set<String> getIncludedParams() {

    Set<String> includedParameters = super.getIncludedParams();

    if (_jku != null) {
      includedParameters.add("jku");
    }

    if (_jwk != null) {
      includedParameters.add("jwk");
    }

    if (_x5u != null) {
      includedParameters.add("x5u");
    }

    if (_x5t != null) {
      includedParameters.add("x5t");
    }

    if (_x5t256 != null) {
      includedParameters.add("x5t#S256");
    }

    if (_x5c != null && !_x5c.isEmpty) {
      includedParameters.add("x5c");
    }

    if (_kid != null) {
      includedParameters.add("kid");
    }

    return includedParameters;
  }


	@override
	JSONObject toJSONObject() {

		JSONObject o = super.toJSONObject();

		if (_jku != null) {
			o.put("jku", _jku.toString());
		}

		if (_jwk != null) {
			o.put("jwk", _jwk.toJSONObject());
		}

		if (_x5u != null) {
			o.put("x5u", _x5u.toString());
		}

		if (_x5t != null) {
			o.put("x5t", _x5t.toString());
		}

		if (_x5t256 != null) {
			o.put("x5t#S256", _x5t256.toString());
		}

		if (_x5c != null && ! _x5c.isEmpty) {
			o.put("x5c", _x5c);
		}

		if (_kid != null) {
			o.put("kid", _kid);
		}

		return o;
	}

}
