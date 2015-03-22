part of jose_jwt.jwk;


/**
 * Other Primes Info, represents the private {@code oth} parameter of a
 * RSA JWK. This class is immutable.
 */
//	@Immutable
class OtherPrimesInfo {

  /**
   * The prime factor.
   */
  final Base64URL _r;


  /**
   * The factor Chinese Remainder Theorem (CRT) exponent.
   */
  final Base64URL _d;


  /**
   * The factor Chinese Remainder Theorem (CRT) coefficient.
   */
  final Base64URL _t;


  /**
   * Creates a new JWK Other Primes Info with the specified
   * parameters.
   *
   * @param r The prime factor. Must not be {@code null}.
   * @param d The factor Chinese Remainder Theorem (CRT)
   *          exponent. Must not be {@code null}.
   * @param t The factor Chinese Remainder Theorem (CRT)
   *          coefficient. Must not be {@code null}.
   */
  OtherPrimesInfo(this._r, this._d, this._t) {

    if (_r == null) {
      throw new ArgumentError.notNull("r");
    }

    if (_d == null) {
      throw new ArgumentError.notNull("d");
    }

    if (_t == null) {
      throw new ArgumentError.notNull("t");
    }

  }

/*
  /**
   * Creates a new JWK Other Primes Info from the specified
   * {@code java.security.spec.RSAOtherPrimeInfo} instance.
   *
   * @param oth The RSA Other Primes Info instance. Must not be
   *            {@code null}.
   */
  OtherPrimesInfo.from(final RSAOtherPrimeInfo oth) :
  _r = Base64URL.encodeBytes(oth.getPrime()),
  _d = Base64URL.encodeBytes(oth.getExponent()),
  _t = Base64URL.encodeBytes(oth.getCrtCoefficient());

*/

  /**
   * Gets the prime factor ({@code r}).
   *
   * @return The prime factor.
   */
  Base64URL getPrimeFactor() {

    return _r;
  }

  /**
   * Gets factor Chinese Remainder Theorem (CRT) exponent
   * ({@code d}).
   *
   * @return The factor Chinese Remainder Theorem (CRT) exponent.
   */
  Base64URL getFactorCRTExponent() {

    return _d;
  }

  /**
   * The factor Chinese Remainder Theorem (CRT) coefficient
   * ({@code t}).
   *
   * @return The factor Chinese Remainder Theorem (CRT)
   *         coefficient.
   */
  Base64URL getFactorCRTCoefficient() {

    return _t;
  }


/*
  /**
   * Converts the specified array of
   * {@code java.security.spec.RSAOtherPrimeInfo} instances to a
   * list of JWK Other Prime Infos.
   *
   * @param othArray Array of RSA Other Primes Info instances.
   *                 May be be {@code null}.
   *
   * @return The corresponding list of JWK Other Prime Infos, or
   *         empty list of the array was {@code null}.
   */
  static List<OtherPrimesInfo> toList(final List<RSAOtherPrimeInfo> othArray) {

    List<OtherPrimesInfo> list = new List ();

    if (othArray == null) {
      // Return empty list
      return list;
    }

    for (RSAOtherPrimeInfo oth in othArray) {
      list.add(new OtherPrimesInfo.from(oth));
    }

    return list;
  }
*/

}


/**
 * Builder for constructing RSA JWKs.
 *
 * <p>Example use:
 *
 * <pre>
 * RSAKey key = new RSAKey.Builder(n, e).
 *              privateExponent(d).
 *              algorithm(JWSAlgorithm.RS512).
 *              keyID("456").
 *              build();
 * </pre>
 */
class RSAKeyBuilder {


  // Public RSA params

  /**
   * The modulus value for the RSA key.
   */
  final Base64URL _n;


  /**
   * The public exponent of the RSA key.
   */
  final Base64URL _e;


  // Private RSA params, 1st representation

  /**
   * The private exponent of the RSA key.
   */
  Base64URL _d;


  // Private RSA params, 2nd representation

  /**
   * The first prime factor of the private RSA key.
   */
  Base64URL _p;


  /**
   * The second prime factor of the private RSA key.
   */
  Base64URL _q;


  /**
   * The first factor Chinese Remainder Theorem exponent of the
   * private RSA key.
   */
  Base64URL _dp;


  /**
   * The second factor Chinese Remainder Theorem exponent of the
   * private RSA key.
   */
  Base64URL _dq;


  /**
   * The first Chinese Remainder Theorem coefficient of the private RSA
   * key.
   */
  Base64URL _qi;


  /**
   * The other primes information of the private RSA key, should
   * they exist. When only two primes have been used (the normal
   * case), this parameter MUST be omitted. When three or more
   * primes have been used, the number of array elements MUST be
   * the number of primes used minus two.
   */
  List<OtherPrimesInfo> _oth;


  /**
   * The key use, optional.
   */
  KeyUse _use;


  /**
   * The key operations, optional.
   */
  Set<KeyOperation> _ops;


  /**
   * The intended JOSE algorithm for the key, optional.
   */
  Algorithm _alg;


  /**
   * The key ID, optional.
   */
  String _kid;


  /**
   * X.509 certificate URL, optional.
   */
  Uri _x5u;


  /**
   * X.509 certificate thumbprint, optional.
   */
  Base64URL _x5t;


  /**
   * The X.509 certificate chain, optional.
   */
  List<Base64> _x5c;


  /**
   * Creates a new RSA JWK builder.
   *
   * @param n The the modulus value for the public RSA key. It is
   *          represented as the Base64URL encoding of value's
   *          big endian representation. Must not be
   *          {@code null}.
   * @param e The exponent value for the public RSA key. It is
   *          represented as the Base64URL encoding of value's
   *          big endian representation. Must not be
   *          {@code null}.
   */
  RSAKeyBuilder(this._n, this._e) {

    // Ensure the public params are defined

    if (_n == null) {
      throw new ArgumentError.notNull("n");
    }

//    _n = n;


    if (_e == null) {
      throw new ArgumentError.notNull("e");
    }

//    _e = e;
  }


  /**
   * Creates a new RSA JWK builder.
   *
   * @param pub The public RSA key to represent. Must not be
   *            {@code null}.
   */
  RSAKeyBuilder.publicKey(final RSAPublicKey pub) :
  _n = Base64URL.encodeBytes(pub.getModulus()),
  _e = Base64URL.encodeBytes(pub.getPublicExponent());


  /**
   * Sets the private exponent ({@code d}) of the RSA key.
   *
   * @param d The private RSA key exponent. It is represented as
   *          the Base64URL encoding of the value's big endian
   *          representation. {@code null} if not specified (for
   *          a public key or a private key using the second
   *          representation only).
   *
   * @return This builder.
   */
  RSAKeyBuilder privateExponent(final Base64URL d) {

    _d = d;
    return this;
  }


  /**
   * Sets the private RSA key, using the first representation.
   *
   * @param priv The private RSA key, used to obtain the private
   *             exponent ({@code d}). Must not be {@code null}.
   *
   * @return This builder.
   */
  RSAKeyBuilder privateKey(final RSAPrivateKey priv) {

    if (priv is RSAPrivateCrtKey) {
      return this.privateKey(priv as RSAPrivateCrtKey);
    } else if (priv is RSAMultiPrimePrivateCrtKey) {
      return this.privateKey(priv as RSAMultiPrimePrivateCrtKey);
    } else {
      _d = Base64URL.encodeBytes(priv.exponent.toByteArray());
      return this;
    }
  }


  /**
   * Sets the first prime factor ({@code p}) of the private RSA
   * key.
   *
   * @param p The RSA first prime factor. It is represented as
   *          the Base64URL encoding of the value's big endian
   *          representation. {@code null} if not specified (for
   *          a public key or a private key using the first
   *          representation only).
   *
   * @return This builder.
   */
  RSAKeyBuilder firstPrimeFactor(final Base64URL p) {

    _p = p;
    return this;
  }


  /**
   * Sets the second prime factor ({@code q}) of the private RSA
   * key.
   *
   * @param q The RSA second prime factor. It is represented as
   *          the Base64URL encoding of the value's big endian
   *          representation. {@code null} if not specified (for
   *          a public key or a private key using the first
   *          representation only).
   *
   * @return This builder.
   */
  RSAKeyBuilder secondPrimeFactor(final Base64URL q) {

    _q = q;
    return this;
  }


  /**
   * Sets the first factor Chinese Remainder Theorem (CRT)
   * exponent ({@code dp}) of the private RSA key.
   *
   * @param dp The RSA first factor CRT exponent. It is
   *           represented as the Base64URL encoding of the
   *           value's big endian representation. {@code null}
   *           if not specified (for a public key or a private
   *           key using the first representation only).
   *
   * @return This builder.
   */
  RSAKeyBuilder firstFactorCRTExponent(final Base64URL dp) {

    _dp = dp;
    return this;
  }


  /**
   * Sets the second factor Chinese Remainder Theorem (CRT)
   * exponent ({@code dq}) of the private RSA key.
   *
   * @param dq The RSA second factor CRT exponent. It is
   *           represented as the Base64URL encoding of the
   *           value's big endian representation. {@code null} if
   *           not specified (for a public key or a private key
   *           using the first representation only).
   *
   * @return This builder.
   */
  RSAKeyBuilder secondFactorCRTExponent(final Base64URL dq) {

    _dq = dq;
    return this;
  }


  /**
   * Sets the first Chinese Remainder Theorem (CRT) coefficient
   * ({@code qi})} of the private RSA key.
   *
   * @param qi The RSA first CRT coefficient. It is represented
   *           as the Base64URL encoding of the value's big
   *           endian representation. {@code null} if not
   *           specified (for a public key or a private key using
   *           the first representation only).
   *
   * @return This builder.
   */
  RSAKeyBuilder firstCRTCoefficient(final Base64URL qi) {

    _qi = qi;
    return this;
  }


  /**
   * Sets the other primes information ({@code oth}) for the
   * private RSA key, should they exist.
   *
   * @param oth The RSA other primes information, {@code null} or
   *            empty list if not specified.
   *
   * @return This builder.
   */
  RSAKeyBuilder otherPrimes(final List<OtherPrimesInfo> oth) {

    _oth = oth;
    return this;
  }


  /**
   * Sets the private RSA key, using the second representation
   * (see RFC 3447, section 3.2).
   *
   * @param priv The private RSA key, used to obtain the private
   *             exponent ({@code d}), the first prime factor
   *             ({@code p}), the second prime factor
   *             ({@code q}), the first factor CRT exponent
   *             ({@code dp}), the second factor CRT exponent
   *             ({@code dq}) and the first CRT coefficient
   *             ({@code qi}). Must not be {@code null}.
   *
   * @return This builder.
   */
  RSAKeyBuilder privateKey3(final RSAPrivateCrtKey priv) {

    _d = Base64URL.encodeBytes(priv.getPrivateExponent());
    _p = Base64URL.encodeBytes(priv.getPrimeP());
    _q = Base64URL.encodeBytes(priv.getPrimeQ());
    _dp = Base64URL.encodeBytes(priv.getPrimeExponentP());
    _dq = Base64URL.encodeBytes(priv.getPrimeExponentQ());
    _qi = Base64URL.encodeBytes(priv.getCrtCoefficient());

    return this;
  }


  /**
   * Sets the private RSA key, using the second representation,
   * with optional other primes info (see RFC 3447, section 3.2).
   *
   * @param priv The private RSA key, used to obtain the private
   *             exponent ({@code d}), the first prime factor
   *             ({@code p}), the second prime factor
   *             ({@code q}), the first factor CRT exponent
   *             ({@code dp}), the second factor CRT exponent
   *             ({@code dq}), the first CRT coefficient
   *             ({@code qi}) and the other primes info
   *             ({@code oth}). Must not be {@code null}.
   *
   * @return This builder.
   */
  RSAKeyBuilder privateKey2(final RSAMultiPrimePrivateCrtKey priv) {

    _d = Base64URL.encodeBytes(priv.getPrivateExponent());
    _p = Base64URL.encodeBytes(priv.getPrimeP());
    _q = Base64URL.encodeBytes(priv.getPrimeQ());
    _dp = Base64URL.encodeBytes(priv.getPrimeExponentP());
    _dq = Base64URL.encodeBytes(priv.getPrimeExponentQ());
    _qi = Base64URL.encodeBytes(priv.getCrtCoefficient());
    _oth = OtherPrimesInfo.toList(priv.getOtherPrimeInfo());

    return this;
  }


  /**
   * Sets the use ({@code use}) of the JWK.
   *
   * @param use The key use, {@code null} if not specified or if
   *            the key is intended for signing as well as
   *            encryption.
   *
   * @return This builder.
   */
  RSAKeyBuilder keyUse(final KeyUse use) {

    _use = use;
    return this;
  }


  /**
   * Sets the operations ({@code key_ops}) of the JWK (for a
   * non-public key).
   *
   * @param ops The key operations, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  RSAKeyBuilder keyOperations(final Set<KeyOperation> ops) {

    _ops = ops;
    return this;
  }


  /**
   * Sets the intended JOSE algorithm ({@code alg}) for the JWK.
   *
   * @param alg The intended JOSE algorithm, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  RSAKeyBuilder algorithm(final Algorithm alg) {

    _alg = alg;
    return this;
  }

  /**
   * Sets the ID ({@code kid}) of the JWK. The key ID can be used
   * to match a specific key. This can be used, for instance, to
   * choose a key within a {@link JWKSet} during key rollover.
   * The key ID may also correspond to a JWS/JWE {@code kid}
   * header parameter value.
   *
   * @param kid The key ID, {@code null} if not specified.
   *
   * @return This builder.
   */
  RSAKeyBuilder keyID(final String kid) {

    _kid = kid;
    return this;
  }


  /**
   * Sets the X.509 certificate URL ({@code x5u}) of the JWK.
   *
   * @param x5u The X.509 certificate URL, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  RSAKeyBuilder x509CertURL(final Uri x5u) {

    _x5u = x5u;
    return this;
  }


  /**
   * Sets the X.509 certificate thumbprint ({@code x5t}) of the
   * JWK.
   *
   * @param x5t The X.509 certificate thumbprint, {@code null} if
   *            not specified.
   *
   * @return This builder.
   */
  RSAKeyBuilder x509CertThumbprint(final Base64URL x5t) {

    _x5t = x5t;
    return this;
  }

  /**
   * Sets the X.509 certificate chain ({@code x5c}) of the JWK.
   *
   * @param x5c The X.509 certificate chain as a unmodifiable
   *            list, {@code null} if not specified.
   *
   * @return This builder.
   */
  RSAKeyBuilder x509CertChain(final List<Base64> x5c) {

    _x5c = x5c;
    return this;
  }

  /**
   * Builds a new RSA JWK.
   *
   * @return The RSA JWK.
   *
   * @throws IllegalStateException If the JWK parameters were
   *                               inconsistently specified.
   */
  RSAKey build() {

    try {
      // The full constructor
      return new RSAKey(_n, _e, _d, _p, _q, _dp, _dq, _qi, _oth,
      _use, _ops, _alg, _kid, _x5u, _x5t, _x5c);

    } catch (e) {
      if (e is ArgumentError)

        throw new StateError(e.toString());
      throw e;
    }
  }

/*
*/
}


/**
 * Public and private {@link KeyType#RSA RSA} JSON Web Key (JWK). This class is
 * immutable.
 *
 * <p>Provides RSA JWK import from / export to the following standard Java
 * interfaces and classes:
 *
 * <ul>
 *     <li>{@code java.security.interfaces.RSAPublicKey}
 *     <li>{@code java.security.interfaces.RSAPrivateKey}
 *         <ul>
 *             <li>{@code java.security.interfaces.RSAPrivateCrtKey}
 *             <li>{@code java.security.interfaces.RSAMultiPrimePrivateCrtKey}
 *         </ul>
 *     <li>{@code java.security.KeyPair}
 * </ul>
 *
 * <p>Example JSON object representation of a public RSA JWK:
 *
 * <pre>
 * {
 *   "kty" : "RSA",
 *   "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "e"   : "AQAB",
 *   "alg" : "RS256",
 *   "kid" : "2011-04-29"
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a public and private RSA JWK (with
 * both the first and the second private key representations):
 *
 * <pre>
 * {
 *   "kty" : "RSA",
 *   "n"   : "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx
 *            4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMs
 *            tn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2
 *            QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbI
 *            SD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqb
 *            w0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
 *   "e"   : "AQAB",
 *   "d"   : "X4cTteJY_gn4FYPsXB8rdXix5vwsg1FLN5E3EaG6RJoVH-HLLKD9
 *            M7dx5oo7GURknchnrRweUkC7hT5fJLM0WbFAKNLWY2vv7B6NqXSzUvxT0_YSfqij
 *            wp3RTzlBaCxWp4doFk5N2o8Gy_nHNKroADIkJ46pRUohsXywbReAdYaMwFs9tv8d
 *            _cPVY3i07a3t8MN6TNwm0dSawm9v47UiCl3Sk5ZiG7xojPLu4sbg1U2jx4IBTNBz
 *            nbJSzFHK66jT8bgkuqsk0GjskDJk19Z4qwjwbsnn4j2WBii3RL-Us2lGVkY8fkFz
 *            me1z0HbIkfz0Y6mqnOYtqc0X4jfcKoAC8Q",
 *   "p"   : "83i-7IvMGXoMXCskv73TKr8637FiO7Z27zv8oj6pbWUQyLPQBQxtPV
 *            nwD20R-60eTDmD2ujnMt5PoqMrm8RfmNhVWDtjjMmCMjOpSXicFHj7XOuVIYQyqV
 *            WlWEh6dN36GVZYk93N8Bc9vY41xy8B9RzzOGVQzXvNEvn7O0nVbfs",
 *   "q"   : "3dfOR9cuYq-0S-mkFLzgItgMEfFzB2q3hWehMuG0oCuqnb3vobLyum
 *            qjVZQO1dIrdwgTnCdpYzBcOfW5r370AFXjiWft_NGEiovonizhKpo9VVS78TzFgx
 *            kIdrecRezsZ-1kYd_s1qDbxtkDEgfAITAG9LUnADun4vIcb6yelxk",
 *   "dp"  : "G4sPXkc6Ya9y8oJW9_ILj4xuppu0lzi_H7VTkS8xj5SdX3coE0oim
 *            YwxIi2emTAue0UOa5dpgFGyBJ4c8tQ2VF402XRugKDTP8akYhFo5tAA77Qe_Nmtu
 *            YZc3C3m3I24G2GvR5sSDxUyAN2zq8Lfn9EUms6rY3Ob8YeiKkTiBj0",
 *   "dq"  : "s9lAH9fggBsoFR8Oac2R_E2gw282rT2kGOAhvIllETE1efrA6huUU
 *            vMfBcMpn8lqeW6vzznYY5SSQF7pMdC_agI3nG8Ibp1BUb0JUiraRNqUfLhcQb_d9
 *            GF4Dh7e74WbRsobRonujTYN1xCaP6TO61jvWrX-L18txXw494Q_cgk",
 *   "qi"  : "GyM_p6JrXySiz1toFgKbWV-JdI3jQ4ypu9rbMWx3rQJBfmt0FoYzg
 *            UIZEVFEcOqwemRN81zoDAaa-Bk0KWNGDjJHZDdDmFhW3AN7lI-puxk_mHZGJ11rx
 *            yR8O55XLSe3SPmRfKwZI6yU24ZxvQKFYItdldUKGzO6Ia6zTKhAVRU",
 *   "alg" : "RS256",
 *   "kid" : "2011-04-29"
 * }
 * </pre>
 *
 * <p>See RFC 3447.
 *
 * <p>See http://en.wikipedia.org/wiki/RSA_%28algorithm%29
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @author Cedric Staub
 * @version $version$ (2014-04-02)
 */
//@Immutable
class RSAKey extends JWK {

  // Public RSA params

  /**
   * The modulus value of the RSA key.
   */
  final Base64URL _n;


  /**
   * The public exponent of the RSA key.
   */
  final Base64URL _e;


  // Private RSA params, 1st representation

  /**
   * The private exponent of the RSA key.
   */
  final Base64URL _d;


  // Private RSA params, 2nd representation

  /**
   * The first prime factor of the private RSA key.
   */
  final Base64URL _p;


  /**
   * The second prime factor of the private RSA key.
   */
  final Base64URL _q;


  /**
   * The first factor Chinese Remainder Theorem exponent of the private
   * RSA key.
   */
  final Base64URL _dp;


  /**
   * The second factor Chinese Remainder Theorem exponent of the private
   * RSA key.
   */
  final Base64URL _dq;


  /**
   * The first Chinese Remainder Theorem coefficient of the private RSA
   * key.
   */
  final Base64URL _qi;

  /**
   * The other primes information of the private RSA key, should they
   * exist. When only two primes have been used (the normal case), this
   * parameter MUST be omitted. When three or more primes have been used,
   * the number of array elements MUST be the number of primes used minus
   * two.
   */
  final List<OtherPrimesInfo> _oth;


  /**
   * Creates a new public RSA JSON Web Key (JWK) with the specified
   * parameters.
   *
   * @param n   The the modulus value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param e   The exponent value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID. {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  factory RSAKey.publicKey(final Base64URL n, final Base64URL e,
                           final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                           final Uri x5u, final Base64URL x5t, final List<Base64> x5c) {

    // Call the full constructor, all private key parameters are null
    return new RSAKey(n, e, null, null, null, null, null, null, null, use, ops, alg, kid,
    x5u, x5t, x5c);
  }

  /**
   * Creates a new public / private RSA JSON Web Key (JWK) with the
   * specified parameters. The private RSA key is specified by its first
   * representation (see RFC 3447, section 3.2).
   *
   * @param n   The the modulus value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param e   The exponent value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param d   The private exponent. It is represented as the Base64URL
   *            encoding of the value's big endian representation. Must
   *            not be {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID. {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  factory RSAKey.firstRepresentation(final Base64URL n, final Base64URL e, final Base64URL d,
                                     final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                                     final Uri x5u, final Base64URL x5t, final List<Base64> x5c) {

    // Call the full constructor, the second private representation
    // parameters are all null
    var x = new RSAKey(n, e, d, null, null, null, null, null, null, use, ops, alg, kid,
    x5u, x5t, x5c);

    if (d == null) {
      throw new ArgumentError.notNull("d");
    }

    return x;
  }

  /**
   * Creates a new public / private RSA JSON Web Key (JWK) with the
   * specified parameters. The private RSA key is specified by its
   * second representation (see RFC 3447, section 3.2).
   *
   * @param n   The the modulus value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param e   The exponent value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param p   The first prime factor. It is represented as the
   *            Base64URL encoding of the value's big endian
   *            representation. Must not be {@code null}.
   * @param q   The second prime factor. It is represented as the
   *            Base64URL encoding of the value's big endian
   *            representation. Must not be {@code null}.
   * @param dp  The first factor Chinese Remainder Theorem exponent. It
   *            is represented as the Base64URL encoding of the value's
   *            big endian representation. Must not be {@code null}.
   * @param dq  The second factor Chinese Remainder Theorem exponent. It
   *            is represented as the Base64URL encoding of the value's
   *            big endian representation. Must not be {@code null}.
   * @param qi  The first Chinese Remainder Theorem coefficient. It is
   *            represented as the Base64URL encoding of the value's big
   *            endian representation. Must not be {@code null}.
   * @param oth The other primes information, should they exist,
   *            {@code null} or an empty list if not specified.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID. {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  factory RSAKey.secondRepresentation(final Base64URL n, final Base64URL e,
                                      final Base64URL p, final Base64URL q,
                                      final Base64URL dp, final Base64URL dq, final Base64URL qi,
                                      final List<OtherPrimesInfo> oth,
                                      final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                                      final Uri x5u, final Base64URL x5t, final List<Base64> x5c) {

    // Call the full constructor, the first private representation
    // d param is null
    var x = new RSAKey(n, e, null, p, q, dp, dq, qi, oth, use, ops, alg, kid,
    x5u, x5t, x5c);

    if (p == null) {
      throw new ArgumentError.notNull("p");
    }

    if (q == null) {
      throw new ArgumentError.notNull("q");
    }

    if (dp == null) {
      throw new ArgumentError.notNull("dp");
    }

    if (dq == null) {
      throw new ArgumentError.notNull("dq");
    }

    if (qi == null) {
      throw new ArgumentError.notNull("qi");
    }

    return x;
  }

  /**
   * Creates a new public / private RSA JSON Web Key (JWK) with the
   * specified parameters. The private RSA key is specified by both its
   * first and second representations (see RFC 3447, section 3.2).
   *
   * <p>A valid first private RSA key representation must specify the
   * {@code d} parameter.
   *
   * <p>A valid second private RSA key representation must specify all
   * required Chinese Remained Theorem (CRT) parameters - {@code p},
   * {@code q}, {@code dp}, {@code dq} and {@code qi}, else an
   * {@link java.lang.IllegalArgumentException} will be thrown.
   *
   * @param n   The the modulus value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param e   The exponent value for the public RSA key. It is
   *            represented as the Base64URL encoding of value's big
   *            endian representation. Must not be {@code null}.
   * @param d   The private exponent. It is represented as the Base64URL
   *            encoding of the value's big endian representation. May
   *            be {@code null}.
   * @param p   The first prime factor. It is represented as the
   *            Base64URL encoding of the value's big endian
   *            representation. May be {@code null}.
   * @param q   The second prime factor. It is represented as the
   *            Base64URL encoding of the value's big endian
   *            representation. May be {@code null}.
   * @param dp  The first factor Chinese Remainder Theorem exponent. It
   *            is represented as the Base64URL encoding of the value's
   *            big endian representation. May be {@code null}.
   * @param dq  The second factor Chinese Remainder Theorem exponent. It
   *            is represented as the Base64URL encoding of the value's
   *            big endian representation. May be {@code null}.
   * @param qi  The first Chinese Remainder Theorem coefficient. It is
   *            represented as the Base64URL encoding of the value's big
   *            endian representation. May be {@code null}.
   * @param oth The other primes information, should they exist,
   *            {@code null} or an empty list if not specified.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID. {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  factory RSAKey(final Base64URL n, final Base64URL e,
                 final Base64URL d,
                 final Base64URL p, final Base64URL q,
                 final Base64URL dp, final Base64URL dq, final Base64URL qi,
                 final List<OtherPrimesInfo> oth,
                 final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                 final Uri x5u, final Base64URL x5t, final List<Base64> x5c)
//  : super(KeyType.RSA, use, ops, alg, kid, x5u, x5t, x5c) {
  {
    // Ensure the public params are defined

    if (n == null) {
      throw new ArgumentError.notNull("n");
    }

//    _n = n;

    if (e == null) {
      throw new ArgumentError.notNull("e");
    }

//    _e = e;


    // Private params, 1st representation

//    _d = d;


    // Private params, 2nd representation, check for consistency

    if (p != null && q != null && dp != null && dq != null && qi != null) {

      // CRT params fully specified
//      _p = p;
//      _q = q;
//      _dp = dp;
//      _dq = dq;
//      _qi = qi;

      // Other RSA primes info optional, default to empty list
      List<OtherPrimesInfo> oth2;
      if (oth != null) {
        oth2 = new UnmodifiableListView(oth);
      } else {
        oth2 = const [];
      }

      return new RSAKey._(n, e, d, p, q, dp, dq, qi, oth2, use, ops, alg, kid, x5u, x5t, x5c);

    } else if (p == null && q == null && dp == null && dq == null && qi == null && oth == null) {

      // No CRT params
//      _p = null;
//      _q = null;
//      _dp = null;
//      _dq = null;
//      _qi = null;

      var oth2 = const [];

      return new RSAKey._(n, e, d, null, null, null, null, null, oth2, use, ops, alg, kid, x5u, x5t, x5c);

    } else {

      if (p == null) {
        throw new ArgumentError("Incomplete second private (CRT) representation: The first prime factor must not be null");
      } else if (q == null) {
        throw new ArgumentError("Incomplete second private (CRT) representation: The second prime factor must not be null");
      } else if (dp == null) {
        throw new ArgumentError("Incomplete second private (CRT) representation: The first factor CRT exponent must not be null");
      } else if (dq == null) {
        throw new ArgumentError("Incomplete second private (CRT) representation: The second factor CRT exponent must not be null");
      } else {
        // qi == null
        throw new ArgumentError("Incomplete second private (CRT) representation: The first CRT coefficient must not be null");
      }
    }
  }

  /// Internal constructor added to support overloading in Dart
  RSAKey._(this._n,
           this._e,
           this._d,
           this._p,
           this._q,
           this._dp,
           this._dq,
           this._qi,
           this._oth,
           final KeyUse use,
           final Set<KeyOperation> ops,
           final Algorithm alg,
           final String kid,
           final Uri x5u,
           final Base64URL x5t,
           final List<Base64> x5c)
  : super(KeyType.RSA, use, ops, alg, kid, x5u, x5t, x5c);

  /**
   * Creates a new public RSA JSON Web Key (JWK) with the specified
   * parameters.
   *
   * @param pub The public RSA key to represent. Must not be
   *            {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID. {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  factory RSAKey.publicKey2(final RSAPublicKey pub,
                            final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                            final Uri x5u, final Base64URL x5t, final List<Base64> x5c) {

    return new RSAKey.publicKey(Base64URL.encodeBytes(pub.modulus.toByteArray()),
//		Base64URL.encodeBytes(pub.getPublicExponent()),
    Base64URL.encodeBytes(pub.exponent.toByteArray()),
    use, ops, alg, kid,
    x5u, x5t, x5c);
  }

  /**
   * Creates a new public / private RSA JSON Web Key (JWK) with the
   * specified parameters. The private RSA key is specified by its first
   * representation (see RFC 3447, section 3.2).
   *
   * @param pub  The public RSA key to represent. Must not be
   *             {@code null}.
   * @param priv The private RSA key to represent. Must not be
   *             {@code null}.
   * @param use  The key use, {@code null} if not specified or if the key
   *             is intended for signing as well as encryption.
   * @param ops  The key operations, {@code null} if not specified.
   * @param alg  The intended JOSE algorithm for the key, {@code null} if
   *             not specified.
   * @param kid  The key ID. {@code null} if not specified.
   * @param x5u  The X.509 certificate URL, {@code null} if not
   *             specified.
   * @param x5t  The X.509 certificate thumbprint, {@code null} if not
   *             specified.
   * @param x5c  The X.509 certificate chain, {@code null} if not
   *             specified.
   */
  factory RSAKey.keyPair2(final RSAPublicKey pub, final RSAPrivateKey priv,
                          final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                          final Uri x5u, final Base64URL x5t, final List<Base64> x5c) {

    return new RSAKey.firstRepresentation(
//        Base64URL.encodeBytes(pub.getModulus()),
//        Base64URL.encodeBytes(pub.getPublicExponent()),
//        Base64URL.encodeBytes(priv.getPrivateExponent()),
        Base64URL.encodeBytes(pub.modulus.toByteArray()),
        Base64URL.encodeBytes(pub.exponent.toByteArray()),
        Base64URL.encodeBytes(priv.exponent.toByteArray()),
        use, ops, alg, kid,
        x5u, x5t, x5c);
  }

/*
  /**
   * Creates a new public / private RSA JSON Web Key (JWK) with the
   * specified parameters. The private RSA key is specified by its second
   * representation (see RFC 3447, section 3.2).
   *
   * @param pub  The public RSA key to represent. Must not be
   *             {@code null}.
   * @param priv The private RSA key to represent. Must not be
   *             {@code null}.
   * @param use  The key use, {@code null} if not specified or if the key
   *             is intended for signing as well as encryption.
   * @param ops  The key operations, {@code null} if not specified.
   * @param alg  The intended JOSE algorithm for the key, {@code null} if
   *             not specified.
   * @param kid  The key ID. {@code null} if not specified.
   * @param x5u  The X.509 certificate URL, {@code null} if not
   *             specified.
   * @param x5t  The X.509 certificate thumbprint, {@code null} if not
   *             specified.
   * @param x5c  The X.509 certificate chain, {@code null} if not
   *             specified.
   */
  factory RSAKey.keyPair3(final RSAPublicKey pub, final RSAPrivateCrtKey priv,
                          final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                          final Uri x5u, final Base64URL x5t, final List<Base64> x5c) {

    return new RSAKey(
//        Base64URL.encodeBytes(pub.getModulus()),
//        Base64URL.encodeBytes(pub.getPublicExponent()),
        Base64URL.encodeBytes(pub.modulus.toByteArray()),
        Base64URL.encodeBytes(pub.exponent.toByteArray()),
        Base64URL.encodeBytes(priv.getPrivateExponent()),
        Base64URL.encodeBytes(priv.getPrimeP()),
        Base64URL.encodeBytes(priv.getPrimeQ()),
        Base64URL.encodeBytes(priv.getPrimeExponentP()),
        Base64URL.encodeBytes(priv.getPrimeExponentQ()),
        Base64URL.encodeBytes(priv.getCrtCoefficient()),
        null,
        use, ops, alg, kid,
        x5u, x5t, x5c);
  }
*/


/*
  /**
   * Creates a new public / private RSA JSON Web Key (JWK) with the
   * specified parameters. The private RSA key is specified by its second
   * representation, with optional other primes info (see RFC 3447,
   * section 3.2).
   *
   * @param pub  The public RSA key to represent. Must not be
   *             {@code null}.
   * @param priv The private RSA key to represent. Must not be
   *             {@code null}.
   * @param use  The key use, {@code null} if not specified or if the key
   *             is intended for signing as well as encryption.
   * @param ops  The key operations, {@code null} if not specified.
   * @param alg  The intended JOSE algorithm for the key, {@code null} if
   *             not specified.
   * @param kid  The key ID. {@code null} if not specified.
   * @param x5u  The X.509 certificate URL, {@code null} if not
   *             specified.
   * @param x5t  The X.509 certificate thumbprint, {@code null} if not
   *             specified.
   * @param x5c  The X.509 certificate chain, {@code null} if not
   *             specified.
   */
  factory RSAKey.keyPair4(final RSAPublicKey pub, final RSAMultiPrimePrivateCrtKey priv,
                          final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                          final Uri x5u, final Base64URL x5t, final List<Base64> x5c) {

    return new RSAKey(
//        Base64URL.encodeBytes(pub.getModulus()),
//        Base64URL.encodeBytes(pub.getPublicExponent()),
				Base64URL.encodeBytes(pub.modulus.toByteArray()),
				Base64URL.encodeBytes(pub.exponent.toByteArray()),
        Base64URL.encodeBytes(priv.getPrivateExponent()),
        Base64URL.encodeBytes(priv.getPrimeP()),
        Base64URL.encodeBytes(priv.getPrimeQ()),
        Base64URL.encodeBytes(priv.getPrimeExponentP()),
        Base64URL.encodeBytes(priv.getPrimeExponentQ()),
        Base64URL.encodeBytes(priv.getCrtCoefficient()),
        OtherPrimesInfo.toList(priv.getOtherPrimeInfo()),
        use, ops, alg, kid,
        x5u, x5t, x5c);
  }
*/

  /**
   * Gets the modulus value ({@code n}) of the RSA key.
   *
   * @return The RSA key modulus. It is represented as the Base64URL
   *         encoding of the value's big endian representation.
   */
  Base64URL getModulus() {

    return _n;
  }


  /**
   * Gets the public exponent ({@code e}) of the RSA key.
   *
   * @return The public RSA key exponent. It is represented as the
   *         Base64URL encoding of the value's big endian representation.
   */
  Base64URL getPublicExponent() {

    return _e;
  }


  /**
   * Gets the private exponent ({@code d}) of the RSA key.
   *
   * @return The private RSA key exponent. It is represented as the
   *         Base64URL encoding of the value's big endian representation.
   *         {@code null} if not specified (for a public key or a private
   *         key using the second representation only).
   */
  Base64URL getPrivateExponent() {

    return _d;
  }


  /**
   * Gets the first prime factor ({@code p}) of the private RSA key.
   *
   * @return The RSA first prime factor. It is represented as the
   *         Base64URL encoding of the value's big endian representation.
   *         {@code null} if not specified (for a public key or a private
   *         key using the first representation only).
   */
  Base64URL getFirstPrimeFactor() {

    return _p;
  }

  /**
   * Gets the second prime factor ({@code q}) of the private RSA key.
   *
   * @return The RSA second prime factor. It is represented as the
   *         Base64URL encoding of the value's big endian representation.
   *         {@code null} if not specified (for a public key or a private
   *         key using the first representation only).
   */
  Base64URL getSecondPrimeFactor() {

    return _q;
  }


  /**
   * Gets the first factor Chinese Remainder Theorem (CRT) exponent
   * ({@code dp}) of the private RSA key.
   *
   * @return The RSA first factor CRT exponent. It is represented as the
   *         Base64URL encoding of the value's big endian representation.
   *         {@code null} if not specified (for a public key or a private
   *         key using the first representation only).
   */
  Base64URL getFirstFactorCRTExponent() {

    return _dp;
  }

  /**
   * Gets the second factor Chinese Remainder Theorem (CRT) exponent
   * ({@code dq}) of the private RSA key.
   *
   * @return The RSA second factor CRT exponent. It is represented as the
   *         Base64URL encoding of the value's big endian representation.
   *         {@code null} if not specified (for a public key or a private
   *         key using the first representation only).
   */
  Base64URL getSecondFactorCRTExponent() {

    return _dq;
  }

  /**
   * Gets the first Chinese Remainder Theorem (CRT) coefficient
   * ({@code qi})} of the private RSA key.
   *
   * @return The RSA first CRT coefficient. It is represented as the
   *         Base64URL encoding of the value's big endian representation.
   *         {@code null} if not specified (for a public key or a private
   *         key using the first representation only).
   */
  Base64URL getFirstCRTCoefficient() {

    return _qi;
  }

  /**
   * Gets the other primes information ({@code oth}) for the private RSA
   * key, should they exist.
   *
   * @return The RSA other primes information, {@code null} or empty list
   *         if not specified.
   */
  List<OtherPrimesInfo> getOtherPrimes() {

    return _oth;
  }

  /**
   * Returns a standard {@code java.security.interfaces.RSAPublicKey}
   * representation of this RSA JWK.
   *
   * @return The public RSA key.
   *
   * @throws NoSuchAlgorithmException If RSA is not supported by the
   *                                  underlying Java Cryptography (JCA)
   *                                  provider.
   * @throws InvalidKeySpecException  If the JWK key parameters are
   *                                  invalid for a public RSA key.
   */
  RSAPublicKey toRSAPublicKey() {

    BigInteger modulus = _n.decodeToBigInteger();
    BigInteger exponent = _e.decodeToBigInteger();

    return new RSAPublicKey(modulus, exponent);
//    RSAPublicKeySpec spec = new RSAPublicKeySpec(modulus, exponent);
//    KeyFactory factory = KeyFactory.getInstance("RSA");
//
//    return factory.generatePublic(spec) as RSAPublicKey;
  }

  /**
   * Returns a standard {@code java.security.interfaces.RSAPrivateKey}
   * representation of this RSA JWK.
   *
   * @return The private RSA key, {@code null} if not specified by this
   *         JWK.
   *
   * @throws NoSuchAlgorithmException If RSA is not supported by the
   *                                  underlying Java Cryptography (JCA)
   *                                  provider.
   * @throws InvalidKeySpecException  If the JWK key parameters are
   *                                  invalid for a private RSA key.
   */
  RSAPrivateKey toRSAPrivateKey() {

    throw new UnimplementedError();
    /*

    if (_d == null) {
      // no private key
      return null;
    }

    BigInteger modulus = _n.decodeToBigInteger();
    BigInteger privateExponent = _d.decodeToBigInteger();

    RSAPrivateKeySpec spec;

    if (_p == null) {
      // Use 1st representation
      spec = new RSAPrivateKeySpec(modulus, privateExponent);

    } else {
      // Use 2nd (CRT) representation
      BigInteger publicExponent = _e.decodeToBigInteger();
      BigInteger primeP = _p.decodeToBigInteger();
      BigInteger primeQ = _q.decodeToBigInteger();
      BigInteger primeExponentP = _dp.decodeToBigInteger();
      BigInteger primeExponentQ = _dq.decodeToBigInteger();
      BigInteger crtCoefficient = _qi.decodeToBigInteger();

      if (_oth != null && !_oth.isEmpty) {
        // Construct other info spec
        List<RSAOtherPrimeInfo> otherInfo = new List<RSAOtherPrimeInfo>(_oth.length);

        for (int i = 0; i < _oth.length; i++) {

          OtherPrimesInfo opi = _oth[i];

          BigInteger otherPrime = opi.getPrimeFactor().decodeToBigInteger();
          BigInteger otherPrimeExponent = opi.getFactorCRTExponent().decodeToBigInteger();
          BigInteger otherCrtCoefficient = opi.getFactorCRTCoefficient().decodeToBigInteger();

          otherInfo[i] = new RSAOtherPrimeInfo(otherPrime,
          otherPrimeExponent,
          otherCrtCoefficient);
        }

        spec = new RSAMultiPrimePrivateCrtKeySpec(modulus,
        publicExponent,
        privateExponent,
        primeP,
        primeQ,
        primeExponentP,
        primeExponentQ,
        crtCoefficient,
        otherInfo);
      } else {
        // Construct spec with no other info
        spec = new RSAPrivateCrtKeySpec(modulus,
        publicExponent,
        privateExponent,
        primeP,
        primeQ,
        primeExponentP,
        primeExponentQ,
        crtCoefficient);
      }
    }

    KeyFactory factory = KeyFactory.getInstance("RSA");

    return factory.generatePrivate(spec) as RSAPrivateKey;
*/
  }

  /**
   * Returns a standard {@code java.security.KeyPair} representation of
   * this RSA JWK.
   *
   * @return The RSA key pair. The private RSA key will be {@code null}
   *         if not specified.
   *
   * @throws NoSuchAlgorithmException If RSA is not supported by the
   *                                  underlying Java Cryptography (JCA)
   *                                  provider.
   * @throws InvalidKeySpecException  If the JWK key parameters are
   *                                  invalid for a public and / or
   *                                  private RSA key.
   */
//	KeyPair toKeyPair() {
  AsymmetricKeyPair toKeyPair() {

    return new AsymmetricKeyPair(toRSAPublicKey(), toRSAPrivateKey());
  }


  @override
  bool isPrivate() {

    // Check if 1st or 2nd form params are specified
    return _d != null || _p != null;
  }

  /**
   * Returns a copy of this RSA JWK with any private values removed.
   *
   * @return The copied public RSA JWK.
   */
  @override
  RSAKey toPublicJWK() {

    return new RSAKey.publicKey(getModulus(), getPublicExponent(),
    getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
    getX509CertURL(), getX509CertThumbprint(), getX509CertChain());
  }

  @override
  Map toJson() {

    Map o = super.toJson();

    // Append public RSA key specific attributes
    o["n"] = _n.toString();
    o["e"] = _e.toString();
    if (_d != null) {
      o["d"] = _d.toString();
    }
    if (_p != null) {
      o["p"] = _p.toString();
    }
    if (_q != null) {
      o["q"] = _q.toString();
    }
    if (_dp != null) {
      o["dp"] = _dp.toString();
    }
    if (_dq != null) {
      o["dq"] = _dq.toString();
    }
    if (_qi != null) {
      o["qi"] = _qi.toString();
    }
    if (_oth != null && !_oth.isEmpty) {

      List a = new List();

      for (OtherPrimesInfo other in _oth) {

        Map oo = new Map();
        oo["r"] = other._r.toString();
        oo["d"] = other._d.toString();
        oo["t"] = other._t.toString();

        a.add(oo);
      }

      o["oth"] = a;
    }

    return o;
  }

  /**
   * Parses a public / private RSA Curve JWK from the specified JSON
   * object string representation.
   *
   * @param s The JSON object string to parse. Must not be {@code null}.
   *
   * @return The public / private RSA JWK.
   *
   * @throws ParseException If the string couldn't be parsed to an RSA
   *                        JWK.
   */
  static RSAKey fromJsonString(final String s) {

    return fromJson(JSON.decode(s));
  }

  /**
   * Parses a public / private RSA JWK from the specified JSON object
   * representation.
   *
   * @param jsonObject The JSON object to parse. Must not be
   *                   @code null}.
   *
   * @return The public / private RSA Key.
   *
   * @throws ParseException If the JSON object couldn't be parsed to an
   *                        RSA JWK.
   */
  static RSAKey fromJson(final Map jsonObject) {

    // Parse the mandatory public key parameters first
    Base64URL n = new Base64URL(JSONUtils.getString(jsonObject, "n"));
    Base64URL e = new Base64URL(JSONUtils.getString(jsonObject, "e"));

    // Check key type
    KeyType kty = KeyType.parse(JSONUtils.getString(jsonObject, "kty"));
    if (kty != KeyType.RSA) {
      throw new ParseError("The key type \"kty\" must be RSA", 0);
    }

    // Parse the optional private key parameters

    // 1st private representation
    Base64URL d = null;
    if (jsonObject.containsKey("d")) {
      d = new Base64URL(JSONUtils.getString(jsonObject, "d"));
    }

    // 2nd private (CRT) representation
    Base64URL p = null;
    if (jsonObject.containsKey("p")) {
      p = new Base64URL(JSONUtils.getString(jsonObject, "p"));
    }
    Base64URL q = null;
    if (jsonObject.containsKey("q")) {
      q = new Base64URL(JSONUtils.getString(jsonObject, "q"));
    }
    Base64URL dp = null;
    if (jsonObject.containsKey("dp")) {
      dp = new Base64URL(JSONUtils.getString(jsonObject, "dp"));
    }
    Base64URL dq = null;
    if (jsonObject.containsKey("dq")) {
      dq = new Base64URL(JSONUtils.getString(jsonObject, "dq"));
    }
    Base64URL qi = null;
    if (jsonObject.containsKey("qi")) {
      qi = new Base64URL(JSONUtils.getString(jsonObject, "qi"));
    }

    List<OtherPrimesInfo> oth = null;
    if (jsonObject.containsKey("oth")) {

      List arr = JSONUtils.getJSONArray(jsonObject, "oth");
      oth = new List(arr.length);

      for (Object o in arr) {

        if (o is Map) {
          Map otherJson = o;

          Base64URL r = new Base64URL(JSONUtils.getString(otherJson, "r"));
          Base64URL odq = new Base64URL(JSONUtils.getString(otherJson, "dq"));
          Base64URL t = new Base64URL(JSONUtils.getString(otherJson, "t"));

          OtherPrimesInfo prime = new OtherPrimesInfo(r, odq, t);
          oth.add(prime);
        }
      }
    }

    // Get optional key use
    KeyUse use = null;

    if (jsonObject.containsKey("use")) {
      use = KeyUseParser.parse(JSONUtils.getString(jsonObject, "use"));
    }

    // Get optional key operations
    Set<KeyOperation> ops = null;

    if (jsonObject.containsKey("key_ops")) {
      ops = KeyOperationParser.parse(JSONUtils.getStringList(jsonObject, "key_ops"));
    }

    // Get optional intended algorithm
    Algorithm alg = null;

    if (jsonObject.containsKey("alg")) {
      alg = new Algorithm.withName(JSONUtils.getString(jsonObject, "alg"));
    }

    // Get optional key ID
    String kid = null;

    if (jsonObject.containsKey("kid")) {
      kid = JSONUtils.getString(jsonObject, "kid");
    }

    // Get optional X.509 cert URL
    Uri x5u = null;

    if (jsonObject.containsKey("x5u")) {
      x5u = JSONUtils.getURL(jsonObject, "x5u");
    }

    // Get optional X.509 cert thumbprint
    Base64URL x5t = null;

    if (jsonObject.containsKey("x5t")) {
      x5t = new Base64URL(JSONUtils.getString(jsonObject, "x5t"));
    }

    // Get optional X.509 cert chain
    List<Base64> x5c = null;

    if (jsonObject.containsKey("x5c")) {
      x5c = X509CertChainUtils.parseX509CertChain(JSONUtils.getJSONArray(jsonObject, "x5c"));
    }

    try {
      return new RSAKey(n, e, d, p, q, dp, dq, qi, oth, use, ops, alg, kid, x5u, x5t, x5c);

    } catch (ex) {
      if (ex is ArgumentError)
        // Inconsistent 2nd spec, conflicting 'use' and 'key_ops'
        throw new ParseError(ex.toString(), 0);
    }
  }

}
