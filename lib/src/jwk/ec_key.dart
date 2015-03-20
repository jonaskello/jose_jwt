part of jose_jwt.jwk;


/**
 * Cryptographic curve. This class is immutable.
 *
 * <p>Includes constants for the following standard cryptographic
 * curves:
 *
 * <ul>
 *     <li>{@link #P_256}
 *     <li>{@link #P_384}
 *     <li>{@link #P_521}
 * </ul>
 *
 * <p>See "Digital Signature Standard (DSS)", FIPS PUB 186-3, June
 * 2009, National Institute of Standards and Technology (NIST).
 */
//	@Immutable
class ECKeyCurve {

  /**
   * P-256 curve (secp256r1).
   */
  static final ECKeyCurve P_256 = new ECKeyCurve("P-256", "secp256r1");


  /**
   * P-384 curve (secp384r1).
   */
  static final ECKeyCurve P_384 = new ECKeyCurve("P-384", "secp384r1");


  /**
   * P-521 curve (secp521r1).
   */
  static final ECKeyCurve P_521 = new ECKeyCurve("P-521", "secp521r1");

  /**
   * The JOSE curve name.
   */
  final String _name;


  /**
   * The standard (JCA) curve name, {@code null} if not
   * specified.
   */
  final String _stdName;


  /**
   * Creates a new cryptographic curve with the specified name.
   * The standard (JCA) curve name is not unspecified.
   *
   * @param name The name of the cryptographic curve. Must not be
   *             {@code null}.
   */
  ECKeyCurve.nameOnly(final String name) : this(name, null);

  /**
   * Creates a new cryptographic curve with the specified name.
   *
   * @param name    The JOSE name of the cryptographic curve.
   *                Must not be {@code null}.
   * @param stdName The standard (JCA) name of the cryptographic
   *                curve, {@code null} if not specified.
   */
  ECKeyCurve(this._name, this._stdName) {

    if (_name == null) {
      throw new ArgumentError.notNull("name");
    }

  }

  /**
   * Gets the name of this cryptographic curve.
   *
   * @return The name.
   */
  String getName() {

    return _name;
  }

  /**
   * Gets the standard (JCA) name of this cryptographic curve.
   *
   * @return The standard (JCA) name.
   */
  String getStdName() {

    return _stdName;
  }

/*

		/**
		 * Gets the Elliptic Curve parameter specification for this
		 * cryptographic curve.
		 *
		 * @return The EC parameter specification, {@code null} if this
		 *         cryptographic curve has no standard (JCA) name
		 *         specified or if lookup of the EC parameters failed.
		 */
		ECParameterSpec toECParameterSpec() {

			if (stdName == null) {
				return null;
			}

			ECNamedCurveParameterSpec curveParams =
				ECNamedCurveTable.getParameterSpec(stdName);

			if (curveParams == null) {
				return null;
			}

			return new ECNamedCurveSpec(curveParams.getName(),
				                    curveParams.getCurve(),
				                    curveParams.getG(),
				                    curveParams.getN());
		}

*/
  /**
   * @see #getName
   */
  @override
  String toString() {

    return getName();
  }

  /**
   * Overrides {@code Object.equals()}.
   *
   * @param object The object to compare to.
   *
   * @return {@code true} if the objects have the same value,
   *         otherwise {@code false}.
   */
  @override
  bool operator ==(final Object object) =>
  object is ECKeyCurve &&
  this.toString() == object.toString();

  /**
   * Parses a cryptographic curve from the specified string.
   *
   * @param s The string to parse. Must not be {@code null} or
   *          empty.
   *
   * @return The cryptographic curve.
   */
  static ECKeyCurve parse(final String s) {

    if (s == null || s.trim().isEmpty) {
      throw new ArgumentError.notNull("s");
    }

    if (s == P_256.getName()) {
      return P_256;

    } else if (s == P_384.getName()) {
      return P_384;

    } else if (s == P_521.getName()) {
      return P_521;

    } else {
      return new ECKeyCurve.nameOnly(s);
    }
  }

  /**
   * Gets the cryptographic curve for the specified standard
   * (JCA) name.
   *
   * @param stdName The standard (JCA) name. Must not be
   *                {@code null}.
   *
   * @throws IllegalArgumentException If no matching JOSE curve
   *                                  constant could be found.
   */
  static ECKeyCurve forStdName(final String stdName) {
    if ("secp256r1" == stdName) {
      return P_256;
    } else if ("secp384r1" == stdName) {
      return P_384;
    } else if ("secp521r1" == stdName) {
      return P_521;
    } else {
      throw new ArgumentError("No matching curve constant for standard (JCA) name " + stdName);
    }
  }

}


/**
 * Builder for constructing Elliptic Curve JWKs.
 *
 * <p>Example use:
 *
 * <pre>
 * ECKey key = new ECKey.Builder(Curve.P521, x, y).
 *             d(d).
 *             algorithm(JWSAlgorithm.ES512).
 *             keyID("789").
 *             build();
 * </pre>
 */
class ECKeyBuilder {

  /**
   * The curve name.
   */
  final ECKeyCurve _crv;

  /**
   * The 'x' EC coordinate.
   */
  final Base64URL _x;

  /**
   * The 'y' EC coordinate.
   */
  final Base64URL _y;

  /**
   * The private 'd' EC coordinate, optional.
   */
  Base64URL _d;

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
   * Creates a new Elliptic Curve JWK builder.
   *
   * @param crv The cryptographic curve. Must not be
   *            {@code null}.
   * @param x   The 'x' coordinate for the elliptic curve
   *            point. It is represented as the Base64URL
   *            encoding of the coordinate's big endian
   *            representation. Must not be {@code null}.
   * @param y   The 'y' coordinate for the elliptic curve
   *            point. It is represented as the Base64URL
   *            encoding of the coordinate's big endian
   *            representation. Must not be {@code null}.
   */
  ECKeyBuilder(this._crv, this._x, this._y) {

    if (_crv == null) {
      throw new ArgumentError.notNull("crv");
    }

    if (_x == null) {
      throw new ArgumentError.notNull("x");
    }

    if (_y == null) {
      throw new ArgumentError.notNull("y");
    }

  }


  /**
   * Creates a new Elliptic Curve JWK builder.
   *
   * @param crv The cryptographic curve. Must not be
   *            {@code null}.
   * @param pub The EC key to represent. Must not be
   *            {@code null}.
   */
  ECKeyBuilder.pub(final ECKeyCurve crv, final ECPublicKey pub) :

  this(crv,
  ECKey.encodeCoordinate(pub.parameters.curve.fieldSize, pub.Q.x.toBigInteger()),
  ECKey.encodeCoordinate(pub.parameters.curve.fieldSize, pub.Q.y.toBigInteger()));


  /**
   * Sets the private 'd' coordinate for the elliptic curve
   * point. The alternative method is {@link #privateKey}.
   *
   * @param d The 'd' coordinate. It is represented as the
   *          Base64URL encoding of the coordinate's big endian
   *          representation. {@code null} if not specified (for
   *          a key).
   *
   * @return This builder.
   */
  ECKeyBuilder d(final Base64URL d) {

    _d = d;
    return this;
  }

  /**
   * Sets the private Elliptic Curve key. The alternative method
   * is {@link #d}.
   *
   * @param priv The private EC key, used to obtain the private
   *             'd' coordinate for the elliptic curve point.
   *             {@code null} if not specified (for a
   *             key).
   *
   * @return This builder.
   */
  ECKeyBuilder privateKey(final ECPrivateKey priv) {

    if (priv != null) {
      _d = ECKey.encodeCoordinate(priv.parameters.curve.fieldSize, priv.d);
    }

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
  ECKeyBuilder keyUse(final KeyUse use) {

    _use = use;
    return this;
  }

  /**
   * Sets the operations ({@code key_ops}) of the JWK.
   *
   * @param ops The key operations, {@code null} if not
   *            specified.
   *
   * @return This builder.
   */
  ECKeyBuilder keyOperations(final Set<KeyOperation> ops) {

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
  ECKeyBuilder algorithm(final Algorithm alg) {

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
  ECKeyBuilder keyID(final String kid) {

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
  ECKeyBuilder x509CertURL(final Uri x5u) {

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
  ECKeyBuilder x509CertThumbprint(final Base64URL x5t) {

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
  ECKeyBuilder x509CertChain(final List<Base64> x5c) {

    _x5c = x5c;
    return this;
  }

  /**
   * Builds a new octet sequence JWK.
   *
   * @return The octet sequence JWK.
   *
   * @throws IllegalStateException If the JWK parameters were
   *                               inconsistently specified.
   */
  ECKey build() {

//    try {
    if (d == null) {
      // key
      return new ECKey.key(_crv, _x, _y, _use, _ops, _alg, _kid, _x5u, _x5t, _x5c);
    }

    // Pair
    return new ECKey.keyPair(_crv, _x, _y, _d, _use, _ops, _alg, _kid, _x5u, _x5t, _x5c);

//    } catch (e) {
//      if (e is ArgumentError)
//
//        throw new StateError(e.toString(), e);
//      throw e;
//    }
  }


}


/**
 * and private {@link KeyType#EC Elliptic Curve} JSON Web Key (JWK).
 * Uses the BouncyCastle.org provider for EC key import and export. This class
 * is immutable.
 *
 * <p>Example JSON object representation of a EC JWK:
 *
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>Example JSON object representation of a and private EC JWK:
 *
 * <pre>
 * {
 *   "kty" : "EC",
 *   "crv" : "P-256",
 *   "x"   : "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
 *   "y"   : "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
 *   "d"   : "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE",
 *   "use" : "enc",
 *   "kid" : "1"
 * }
 * </pre>
 *
 * <p>See http://en.wikipedia.org/wiki/Elliptic_curve_cryptography
 *
 * @author Vladimir Dzhuvinov
 * @author Justin Richer
 * @version $version$ (2014-04-02)
 */
//@Immutable
class ECKey extends JWK {


  /**
   * Returns the Base64URL encoding of the specified elliptic curve 'x',
   * 'y' or 'd' coordinate, with leading zero padding up to the specified
   * field size in bits.
   *
   * @param fieldSize  The field size in bits.
   * @param coordinate The elliptic curve coordinate. Must not be
   *                   {@code null}.
   *
   * @return The Base64URL-encoded coordinate, with leading zero padding
   *         up to the curve's field size.
   */
  static Base64URL encodeCoordinate(final int fieldSize, final BigInteger coordinate) {

    Uint8List unpadded = BigIntegerUtils.toBytesUnsigned(coordinate);

    int bytesToOutput = (fieldSize + 7) ~/ 8;

    if (unpadded.length >= bytesToOutput) {
      // Greater-than check to prevent exception on malformed
      // key below
      return Base64URL.encodeBytes(unpadded);
    }

    Uint8List padded = new Uint8List(bytesToOutput);

//    System.arraycopy(unpadded, 0, padded, bytesToOutput - unpadded.length, unpadded.length);
    padded.replaceRange(bytesToOutput - unpadded.length, bytesToOutput - unpadded.length + unpadded.length, unpadded);

    return Base64URL.encodeBytes(padded);
  }

  /**
   * The curve name.
   */
  final ECKeyCurve _crv;


  /**
   * The 'x' EC coordinate.
   */
  final Base64URL _x;

  /**
   * The 'y' EC coordinate.
   */
  final Base64URL _y;

  /**
   * The private 'd' EC coordinate
   */
  final Base64URL _d;

  /**
   * Creates a new Elliptic Curve JSON Web Key (JWK) with the
   * specified parameters.
   *
   * @param crv The cryptographic curve. Must not be {@code null}.
   * @param x   The 'x' coordinate for the elliptic curve point.
   *            It is represented as the Base64URL encoding of the
   *            coordinate's big endian representation. Must not be
   *            {@code null}.
   * @param y   The 'y' coordinate for the elliptic curve point.
   *            It is represented as the Base64URL encoding of the
   *            coordinate's big endian representation. Must not be
   *            {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID, {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  ECKey.key(final ECKeyCurve crv, final Base64URL x, final Base64URL y,
            final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
            final Uri x5u, final Base64URL x5t, final List<Base64> x5c) :
  super(KeyType.EC, use, ops, alg, kid, x5u, x5t, x5c),
  _crv = crv,
  _x = x,
  _y = y,
  _d = null {

    if (_crv == null) {
      throw new ArgumentError.notNull("crv");
    }

    if (_x == null) {
      throw new ArgumentError.notNull("x");
    }

    if (_y == null) {
      throw new ArgumentError.notNull("y");
    }
  }

  /**
   * Creates a new / private Elliptic Curve JSON Web Key (JWK)
   * with the specified parameters.
   *
   * @param crv The cryptographic curve. Must not be {@code null}.
   * @param x   The 'x' coordinate for the elliptic curve point.
   *            It is represented as the Base64URL encoding of the
   *            coordinate's big endian representation. Must not be
   *            {@code null}.
   * @param y   The 'y' coordinate for the elliptic curve point.
   *            It is represented as the Base64URL encoding of the
   *            coordinate's big endian representation. Must not be
   *            {@code null}.
   * @param d   The private 'd' coordinate for the elliptic curve point.
   *            It is represented as the Base64URL encoding of the
   *            coordinate's big endian representation. Must not be
   *            {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID, {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  ECKey.keyPair(final ECKeyCurve crv, final Base64URL x, final Base64URL y, final Base64URL d,
                final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                final Uri x5u, final Base64URL x5t, final List<Base64> x5c)
  : super(KeyType.EC, use, ops, alg, kid, x5u, x5t, x5c),
  _crv = crv,
  _x = x,
  _y = y,
  _d = d
  {

    if (crv == null) {
      throw new ArgumentError.notNull("crv");
    }

    if (x == null) {
      throw new ArgumentError.notNull("x");
    }

    if (y == null) {
      throw new ArgumentError.notNull("y");
    }

    if (d == null) {
      throw new ArgumentError.notNull("d");
    }

  }

  /**
   * Creates a new Elliptic Curve JSON Web Key (JWK) with the
   * specified parameters.
   *
   * @param crv The cryptographic curve. Must not be {@code null}.
   * @param pub The EC key to represent. Must not be {@code null}.
   * @param use The key use, {@code null} if not specified or if the key
   *            is intended for signing as well as encryption.
   * @param ops The key operations, {@code null} if not specified.
   * @param alg The intended JOSE algorithm for the key, {@code null} if
   *            not specified.
   * @param kid The key ID, {@code null} if not specified.
   * @param x5u The X.509 certificate URL, {@code null} if not specified.
   * @param x5t The X.509 certificate thumbprint, {@code null} if not
   *            specified.
   * @param x5c The X.509 certificate chain, {@code null} if not
   *            specified.
   */
  ECKey.withOtherParams(final ECKeyCurve crv, final ECPublicKey pub,
                        final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                        final Uri x5u, final Base64URL x5t, final List<Base64> x5c) :

  this.key(crv,
//	encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
  encodeCoordinate(pub.parameters.curve.fieldSize, pub.Q.x.toBigInteger()),
//	encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()),
  encodeCoordinate(pub.parameters.curve.fieldSize, pub.Q.y.toBigInteger()),
  use, ops, alg, kid,
  x5u, x5t, x5c);

  /**
   * Creates a new / private Elliptic Curve JSON Web Key (JWK)
   * with the specified parameters.
   *
   * @param crv  The cryptographic curve. Must not be {@code null}.
   * @param pub  The EC key to represent. Must not be
   *             {@code null}.
   * @param priv The private EC key to represent. Must not be
   *             {@code null}.
   * @param use  The key use, {@code null} if not specified or if the key
   *             is intended for signing as well as encryption.
   * @param ops  The key operations, {@code null} if not specified.
   * @param alg  The intended JOSE algorithm for the key, {@code null} if
   *             not specified.
   * @param kid  The key ID, {@code null} if not specified.
   * @param x5u  The X.509 certificate URL, {@code null} if not
   *             specified.
   * @param x5t  The X.509 certificate thumbprint, {@code null} if not
   *             specified.
   * @param x5c  The X.509 certificate chain, {@code null} if not
   *             specified.
   */
  ECKey.withYetOtherParams(final ECKeyCurve crv, final ECPublicKey pub, final ECPrivateKey priv,
                           final KeyUse use, final Set<KeyOperation> ops, final Algorithm alg, final String kid,
                           final Uri x5u, final Base64URL x5t, final List<Base64> x5c) :

  this.keyPair(crv,
//  encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineX()),
//  encodeCoordinate(pub.getParams().getCurve().getField().getFieldSize(), pub.getW().getAffineY()),
//  encodeCoordinate(priv.getParams().getCurve().getField().getFieldSize(), priv.getS()),
  encodeCoordinate(pub.parameters.curve.fieldSize, pub.Q.x.toBigInteger()),
  encodeCoordinate(pub.parameters.curve.fieldSize, pub.Q.y.toBigInteger()),
  encodeCoordinate(pub.parameters.curve.fieldSize, priv.d),
  use, ops, alg, kid,
  x5u, x5t, x5c);

  /**
   * Gets the cryptographic curve.
   *
   * @return The cryptographic curve.
   */
  ECKeyCurve getCurve() {

    return _crv;
  }

  /**
   * Gets the 'x' coordinate for the elliptic curve point.
   *
   * @return The 'x' coordinate. It is represented as the Base64URL
   *         encoding of the coordinate's big endian representation.
   */
  Base64URL getX() {

    return _x;
  }


  /**
   * Gets the 'y' coordinate for the elliptic curve point.
   *
   * @return The 'y' coordinate. It is represented as the Base64URL
   *         encoding of the coordinate's big endian representation.
   */
  Base64URL getY() {

    return _y;
  }


  /**
   * Gets the private 'd' coordinate for the elliptic curve point. It is
   * represented as the Base64URL encoding of the coordinate's big endian
   * representation.
   *
   * @return The 'd' coordinate.  It is represented as the Base64URL
   *         encoding of the coordinate's big endian representation.
   *         {@code null} if not specified (for a key).
   */
  Base64URL getD() {

    return _d;
  }

/*

	/**
	 * Gets a new BouncyCastle.org EC key factory.
	 *
	 * @return The EC key factory.
	 *
	 * @throws NoSuchAlgorithmException If a JCA provider or algorithm 
	 *                                  exception was encountered.
	 */
	private static KeyFactory getECKeyFactory()
		throws NoSuchAlgorithmException {

		return KeyFactory.getInstance("EC", BouncyCastleProviderSingleton.getInstance());
	}
*/

  /**
   * Returns a standard {@code java.security.interfaces.ECPublicKey}
   * representation of this Elliptic Curve JWK.
   *
   * @return The Elliptic Curve key.
   *
   * @throws NoSuchAlgorithmException If EC is not supported by the
   *                                  underlying Java Cryptography (JCA)
   *                                  provider.
   * @throws InvalidKeySpecException  If the JWK key parameters are
   *                                  invalid for a EC key.
   */
  ECPublicKey toECPublicKey() {

    ECParameterSpec spec = _crv.toECParameterSpec();

    if (spec == null) {
      throw new NoSuchAlgorithmException("Couldn't get EC parameter spec for curve $_crv");
    }

    ECPoint w = new ECPoint(_x.decodeToBigInteger(), _y.decodeToBigInteger());

    ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(w, spec);

    KeyFactory keyFactory = getECKeyFactory();

    return keyFactory.generatePublic(publicKeySpec) as ECPublicKey;
  }

  /**
   * Returns a standard {@code java.security.interfaces.ECPrivateKey}
   * representation of this Elliptic Curve JWK.
   *
   * @return The private Elliptic Curve key, {@code null} if not
   *         specified by this JWK.
   *
   * @throws NoSuchAlgorithmException If EC is not supported by the
   *                                  underlying Java Cryptography (JCA)
   *                                  provider.
   * @throws InvalidKeySpecException  If the JWK key parameters are
   *                                  invalid for a private EC key.
   */
  ECPrivateKey toECPrivateKey() {

    if (_d == null) {
      // No private 'd' param
      return null;
    }

    throw new UnimplementedError();
/*
    ECParameterSpec spec = crv.toECParameterSpec();

    if (spec == null) {
      throw new NoSuchAlgorithmException("Couldn't get EC parameter spec for curve " + crv);
    }

    ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d.decodeToBigInteger(), spec);

    KeyFactory keyFactory = getECKeyFactory();

    return keyFactory.generatePrivate(privateKeySpec) as ECPrivateKey;
*/
  }


  /**
   * Returns a standard {@code java.security.KeyPair} representation of
   * this Elliptic Curve JWK.
   *
   * @return The Elliptic Curve key pair. The private Elliptic Curve key
   *         will be {@code null} if not specified.
   *
   * @throws NoSuchAlgorithmException If EC is not supported by the
   *                                  underlying Java Cryptography (JCA)
   *                                  provider.
   * @throws InvalidKeySpecException  If the JWK key parameters are
   *                                  invalid for a and / or
   *                                  private EC key.
   */
  AsymmetricKeyPair toKeyPair() {

    return new AsymmetricKeyPair(toECPublicKey(), toECPrivateKey());
  }


  @override
  bool isPrivate() {

    return _d != null;
  }

  /**
   * Returns a copy of this Elliptic Curve JWK with any private values
   * removed.
   *
   * @return The copied Elliptic Curve JWK.
   */
  @override
  ECKey toPublicJWK() {

    return new ECKey.key(getCurve(), getX(), getY(),
    getKeyUse(), getKeyOperations(), getAlgorithm(), getKeyID(),
    getX509CertURL(), getX509CertThumbprint(), getX509CertChain());
  }

  @override
  Map toJson() {

    Map o = super.toJson();

    // Append EC specific attributes
    o["crv"] = _crv.toString();
    o["x"] = _x.toString();
    o["y"] = _y.toString();

    if (_d != null) {
      o["d"] = _d.toString();
    }

    return o;
  }

  /**
   * Parses a / private Elliptic Curve JWK from the specified JSON
   * object string representation.
   *
   * @param s The JSON object string to parse. Must not be {@code null}.
   *
   * @return The / private Elliptic Curve JWK.
   *
   * @throws ParseException If the string couldn't be parsed to an
   *                        Elliptic Curve JWK.
   */
  static ECKey fromJsonString(final String s) {

    return fromJson(JSONObjectUtils.parseJSONObject(s));
  }

  /**
   * Parses a / private Elliptic Curve JWK from the specified JSON
   * object representation.
   *
   * @param jsonObject The JSON object to parse. Must not be
   *                   {@code null}.
   *
   * @return The / private Elliptic Curve JWK.
   *
   * @throws ParseException If the JSON object couldn't be parsed to an
   *                        Elliptic Curve JWK.
   */
  static ECKey fromJson(final Map jsonObject) {

    // Parse the mandatory parameters first
    ECKeyCurve crv = ECKeyCurve.parse(JSONUtils.getString(jsonObject, "crv"));
    Base64URL x = new Base64URL(JSONUtils.getString(jsonObject, "x"));
    Base64URL y = new Base64URL(JSONUtils.getString(jsonObject, "y"));

    // Check key type
    KeyType kty = KeyType.parse(JSONUtils.getString(jsonObject, "kty"));

    if (kty != KeyType.EC) {
      throw new ParseError("The key type \"kty\" must be EC", 0);
    }

    // Get optional private key
    Base64URL d = null;
    if (jsonObject["d"] != null) {
      d = new Base64URL(JSONUtils.getString(jsonObject, "d"));
    }

    // Get optional key use
    KeyUse use = null;

    if (jsonObject.containsKey("use")) {
      use = KeyUseParser.parse(JSONUtils.getString(jsonObject, "use"));
    }

    // Get optional key operations
    Set<KeyOperation> ops = null;

    if (jsonObject.containsKey("key_ops")) {
      ops = KeyOperation.parse(JSONUtils.getStringList(jsonObject, "key_ops"));
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
      if (d == null) {
        // key
        return new ECKey.key(crv, x, y, use, ops, alg, kid, x5u, x5t, x5c);

      } else {
        // Key pair
        return new ECKey.keyPair(crv, x, y, d, use, ops, alg, kid, x5u, x5t, x5c);
      }

    } catch (ex) {
      if (ex is ArgumentError)
        // Conflicting 'use' and 'key_ops'
//				throw new ParseError(ex.getMessage(), 0);
        throw new ParseError(ex.toString(), 0);
    }
  }

}
