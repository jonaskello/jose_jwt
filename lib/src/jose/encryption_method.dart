part of jose_jwt.jose;

/**
 * Encryption method name, represents the {@code enc} header parameter in JSON
 * Web Encryption (JWE) objects. This class is immutable.
 *
 * <p>Includes constants for the following standard encryption method names:
 *
 * <ul>
 *     <li>{@link #A128CBC_HS256 A128CBC-HS256}
 *     <li>{@link #A192CBC_HS384 A192CBC-HS384}
 *     <li>{@link #A256CBC_HS512 A256CBC-HS512}
 *     <li>{@link #A128GCM}
 *     <li>{@link #A192GCM}
 *     <li>{@link #A256GCM}
 *     <li>{@link #A128CBC_HS256_DEPRECATED A128CBC+HS256 (deprecated)}
 *     <li>{@link #A256CBC_HS512_DEPRECATED A256CBC+HS512 (deprecated)}
 * </ul>
 *
 * <p>Additional encryption method names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-05-23)
 */
//@Immutable
class EncryptionMethod extends Algorithm {


  /**
   * The Content Encryption Key (CEK) bit length, zero if not specified.
   */
  final int _cekBitLength;

  /**
   * AES_128_CBC_HMAC_SHA_256 authenticated encryption using a 256 bit
   * key (required).
   */
  static final EncryptionMethod A128CBC_HS256 =
  new EncryptionMethod("A128CBC-HS256", Requirement.REQUIRED, 256);


  /**
   * AES_192_CBC_HMAC_SHA_384 authenticated encryption using a 384 bit
   * key (optional).
   */
  static final EncryptionMethod A192CBC_HS384 =
  new EncryptionMethod("A192CBC-HS384", Requirement.OPTIONAL, 384);


  /**
   * AES_256_CBC_HMAC_SHA_512 authenticated encryption using a 512 bit
   * key (required).
   */
  static final EncryptionMethod A256CBC_HS512 =
  new EncryptionMethod("A256CBC-HS512", Requirement.REQUIRED, 512);


  /**
   * AES_128_CBC_HMAC_SHA_256 authenticated encryption using a 256 bit
   * key, deprecated in JOSE draft suite version 09.
   */
  static final EncryptionMethod A128CBC_HS256_DEPRECATED =
  new EncryptionMethod("A128CBC+HS256", Requirement.OPTIONAL, 256);


  /**
   * AES_256_CBC_HMAC_SHA_512 authenticated encryption using a 512 bit
   * key, deprecated in JOSE draft suite version 09.
   */
  static final EncryptionMethod A256CBC_HS512_DEPRECATED =
  new EncryptionMethod("A256CBC+HS512", Requirement.OPTIONAL, 512);


  /**
   * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 128 bit key
   * (recommended).
   */
  static final EncryptionMethod A128GCM =
  new EncryptionMethod("A128GCM", Requirement.RECOMMENDED, 128);


  /**
   * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 192 bit key
   * (optional).
   */
  static final EncryptionMethod A192GCM =
  new EncryptionMethod("A192GCM", Requirement.OPTIONAL, 192);


  /**
   * AES in Galois/Counter Mode (GCM) (NIST.800-38D) using a 256 bit key
   * (recommended).
   */
  static final EncryptionMethod A256GCM =
  new EncryptionMethod("A256GCM", Requirement.RECOMMENDED, 256);

  /**
   * Creates a new encryption method.
   *
   * @param name         The encryption method name. Must not be
   *                     {@code null}.
   * @param req          The implementation requirement, {@code null} if
   *                     not known.
   * @param cekBitLength The Content Encryption Key (CEK) bit length,
   *                     zero if not specified.
   */
  EncryptionMethod(final String name, final Requirement req, this._cekBitLength) : super(name, req) {
  }


  /**
   * Creates a new encryption method. The Content Encryption Key (CEK)
   * bit length is not specified.
   *
   * @param name The encryption method name. Must not be {@code null}.
   * @param req  The implementation requirement, {@code null} if not
   *             known.
   */
  EncryptionMethod.withRequirement(final String name, final Requirement req) : this(name, req, 0);


  /**
   * Creates a new encryption method. The implementation requirement and
   * the Content Encryption Key (CEK) bit length are not specified.
   *
   * @param name The encryption method name. Must not be {@code null}.
   */
  EncryptionMethod.nameOnly(String name) :this(name, null, 0);

  /**
   * Gets the length of the associated Content Encryption Key (CEK).
   *
   * @return The Content Encryption Key (CEK) bit length, zero if not
   *         specified.
   */
  int cekBitLength() {
    return _cekBitLength;
  }

  /**
   * Parses an encryption method from the specified string.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The encryption method  (matching standard algorithm
   *         constant, else a newly created algorithm).
   */
  static EncryptionMethod parse(final String s) {

    if (s == A128CBC_HS256.getName()) {

      return A128CBC_HS256;

    } else if (s == A192CBC_HS384.getName()) {

      return A192CBC_HS384;

    } else if (s == A256CBC_HS512.getName()) {

      return A256CBC_HS512;

    } else if (s == A128GCM.getName()) {

      return A128GCM;

    } else if (s == A192GCM.getName()) {

      return A192GCM;

    } else if (s == A256GCM.getName()) {

      return A256GCM;

    } else if (s == A128CBC_HS256_DEPRECATED.getName()) {

      return A128CBC_HS256_DEPRECATED;

    } else if (s == A256CBC_HS512_DEPRECATED.getName()) {

      return A256CBC_HS512_DEPRECATED;

    } else {

      return new EncryptionMethod(s);
    }
  }

}
