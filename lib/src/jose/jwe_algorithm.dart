part of jose_jwt.jose;

/**
 * JSON Web Encryption (JWE) algorithm name, represents the {@code alg} header
 * parameter in JWE objects. This class is immutable.
 *
 * <p>Includes constants for the following standard JWE algorithm names:
 *
 * <ul>
 *     <li>{@link #RSA1_5}
 *     <li>{@link #RSA_OAEP RSA-OAEP}
 *     <li>{@link #RSA_OAEP_256 RSA-OAEP-256}
 *     <li>{@link #A128KW}
 *     <li>{@link #A192KW}
 *     <li>{@link #A256KW}
 *     <li>{@link #DIR dir}
 *     <li>{@link #ECDH_ES ECDH-ES}
 *     <li>{@link #ECDH_ES_A128KW ESDH-ES+A128KW}
 *     <li>{@link #ECDH_ES_A128KW ESDH-ES+A192KW}
 *     <li>{@link #ECDH_ES_A256KW ESDH-ES+A256KW}
 *     <li>{@link #PBES2_HS256_A128KW PBES2-HS256+A128KW}
 *     <li>{@link #PBES2_HS256_A192KW PBES2-HS256+A192KW}
 *     <li>{@link #PBES2_HS256_A256KW PBES2-HS256+A256KW}
 * </ul>
 *
 * <p>Additional JWE algorithm names can be defined using the constructors.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2013-05-06)
 */
//@Immutable
class JWEAlgorithm extends Algorithm {

  /**
   * RSAES-PKCS1-V1_5 (RFC 3447) (required).
   */
  static final JWEAlgorithm RSA1_5 = new JWEAlgorithm("RSA1_5", Requirement.REQUIRED);

  /**
   * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
   * with the default parameters specified by RFC 3447 in section A.2.1
   * (recommended).
   */
  static final JWEAlgorithm RSA_OAEP = new JWEAlgorithm("RSA-OAEP", Requirement.OPTIONAL);


  /**
   * RSAES using Optimal Asymmetric Encryption Padding (OAEP) (RFC 3447),
   * with the SHA-256 hash function and the MGF1 with SHA-256 mask
   * generation function (recommended).
   */
  static final JWEAlgorithm RSA_OAEP_256 = new JWEAlgorithm("RSA-OAEP-256", Requirement.OPTIONAL);


  /**
   * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394)
   * using 128 bit keys (recommended).
   */
  static final JWEAlgorithm A128KW = new JWEAlgorithm("A128KW", Requirement.RECOMMENDED);


  /**
   * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394)
   * using 192 bit keys (optional).
   */
  static final JWEAlgorithm A192KW = new JWEAlgorithm("A192KW", Requirement.OPTIONAL);


  /**
   * Advanced Encryption Standard (AES) Key Wrap Algorithm (RFC 3394)
   * using 256 bit keys (recommended).
   */
  static final JWEAlgorithm A256KW = new JWEAlgorithm("A256KW", Requirement.RECOMMENDED);


  /**
   * Direct use of a shared symmetric key as the Content Encryption Key
   * (CEK) for the block encryption step (rather than using the symmetric
   * key to wrap the CEK) (recommended).
   */
  static final JWEAlgorithm DIR = new JWEAlgorithm("dir", Requirement.RECOMMENDED);


  /**
   * Elliptic Curve Diffie-Hellman Ephemeral Static (RFC 6090) key
   * agreement using the Concat KDF, as defined in section 5.8.1 of
   * NIST.800-56A, with the agreed-upon key being used directly as the
   * Content Encryption Key (CEK) (rather than being used to wrap the
   * CEK) (recommended).
   */
  static final JWEAlgorithm ECDH_ES = new JWEAlgorithm("ECDH-ES", Requirement.RECOMMENDED);


  /**
   * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
   * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
   * Encryption Key (CEK) with the "A128KW" function (rather than being
   * used directly as the CEK) (recommended).
   */
  static final JWEAlgorithm ECDH_ES_A128KW = new JWEAlgorithm("ECDH-ES+A128KW", Requirement.RECOMMENDED);


  /**
   * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
   * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
   * Encryption Key (CEK) with the "A192KW" function (rather than being
   * used directly as the CEK) (optional).
   */
  static final JWEAlgorithm ECDH_ES_A192KW = new JWEAlgorithm("ECDH-ES+A192KW", Requirement.OPTIONAL);


  /**
   * Elliptic Curve Diffie-Hellman Ephemeral Static key agreement per
   * "ECDH-ES", but where the agreed-upon key is used to wrap the Content
   * Encryption Key (CEK) with the "A256KW" function (rather than being
   * used directly as the CEK) (recommended).
   */
  static final JWEAlgorithm ECDH_ES_A256KW = new JWEAlgorithm("ECDH-ES+A256KW", Requirement.RECOMMENDED);


  /**
   * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 128 bit keys
   * (optional).
   */
  static final JWEAlgorithm A128GCMKW = new JWEAlgorithm("A128GCMKW", Requirement.OPTIONAL);


  /**
   * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 192 bit keys
   * (optional).
   */
  static final JWEAlgorithm A192GCMKW = new JWEAlgorithm("A192GCMKW", Requirement.OPTIONAL);


  /**
   * AES in Galois/Counter Mode (GCM) (NIST.800-38D) 256 bit keys
   * (optional).
   */
  static final JWEAlgorithm A256GCMKW = new JWEAlgorithm("A256GCMKW", Requirement.OPTIONAL);


  /**
   * PBES2 (RFC 2898) with HMAC SHA-256 as the PRF and AES Key Wrap
   * (RFC 3394) using 128 bit keys for the encryption scheme (optional).
   */
  static final JWEAlgorithm PBES2_HS256_A128KW = new JWEAlgorithm("PBES2-HS256+A128KW", Requirement.OPTIONAL);


  /**
   * PBES2 (RFC 2898) with HMAC SHA-256 as the PRF and AES Key Wrap
   * (RFC 3394) using 192 bit keys for the encryption scheme (optional).
   */
  static final JWEAlgorithm PBES2_HS256_A192KW = new JWEAlgorithm("PBES2-HS256+A192KW", Requirement.OPTIONAL);


  /**
   * PBES2 (RFC 2898) with HMAC SHA-256 as the PRF and AES Key Wrap
   * (RFC 3394) using 256 bit keys for the encryption scheme (optional).
   */
  static final JWEAlgorithm PBES2_HS256_A256KW = new JWEAlgorithm("PBES2-HS256+A256KW", Requirement.OPTIONAL);


  /**
   * Creates a new JSON Web Encryption (JWE) algorithm.
   *
   * @param name The algorithm name. Must not be {@code null}.
   * @param req  The implementation requirement, {@code null} if not
   *             known.
   */
  JWEAlgorithm(final String name, final Requirement req) :super(name, req);

  /**
   * Creates a new JSON Web Encryption (JWE) algorithm.
   *
   * @param name The algorithm name. Must not be {@code null}.
   */
  JWEAlgorithm.onlyName(String name) :super(name, null);

  /**
   * Parses a JWE algorithm from the specified string.
   *
   * @param s The string to parse. Must not be {@code null}.
   *
   * @return The JWE algorithm (matching standard algorithm constant, else
   *         a newly created algorithm).
   */
  static JWEAlgorithm parse(final String s) {

    if (s == RSA1_5.getName()) {
      return RSA1_5;
    } else if (s == RSA_OAEP.getName()) {
      return RSA_OAEP;
    } else if (s == A128KW.getName()) {
      return A128KW;
    } else if (s == A192KW.getName()) {
      return A192KW;
    } else if (s == A256KW.getName()) {
      return A256KW;
    } else if (s == DIR.getName()) {
      return DIR;
    } else if (s == ECDH_ES.getName()) {
      return ECDH_ES;
    } else if (s == ECDH_ES_A128KW.getName()) {
      return ECDH_ES_A128KW;
    } else if (s == ECDH_ES_A192KW.getName()) {
      return ECDH_ES_A192KW;
    } else if (s == ECDH_ES_A256KW.getName()) {
      return ECDH_ES_A256KW;
    } else if (s == A128GCMKW.getName()) {
      return A128GCMKW;
    } else if (s == A192GCMKW.getName()) {
      return A192GCMKW;
    } else if (s == A256GCMKW.getName()) {
      return A256GCMKW;
    } else if (s == PBES2_HS256_A128KW.getName()) {
      return PBES2_HS256_A128KW;
    } else if (s == PBES2_HS256_A192KW.getName()) {
      return PBES2_HS256_A192KW;
    } else if (s == PBES2_HS256_A256KW.getName()) {
      return PBES2_HS256_A256KW;
    } else {
      return new JWEAlgorithm.onlyName(s);
    }
  }

}
