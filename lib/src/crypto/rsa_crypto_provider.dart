part of jose_jwt.crypto;

/**
 * The base abstract class for RSA encrypters and decrypters of
 * {@link com.nimbusds.jose.JWEObject JWE objects}.
 *
 * <p>Supports the following JSON Web Algorithms (JWAs):
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA1_5}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP}
 *     <li>{@link com.nimbusds.jose.JWEAlgorithm#RSA_OAEP_256}
 * </ul>
 *
 * <p>Supports the following encryption methods:
 *
 * <ul>
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192CBC_HS384}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A192GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256GCM}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A128CBC_HS256_DEPRECATED}
 *     <li>{@link com.nimbusds.jose.EncryptionMethod#A256CBC_HS512_DEPRECATED}
 * </ul>
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-05-23)
 */
abstract class RSACryptoProvider extends BaseJWEProvider {

  /**   * The supported JWE algorithms.
   */
  static final Set<JWEAlgorithm> SUPPORTED_ALGORITHMS = new UnmodifiableSetView(new Set.from([
      JWEAlgorithm.RSA1_5,
      JWEAlgorithm.RSA_OAEP,
      JWEAlgorithm.RSA_OAEP_256
  ]));


  /**
   * The supported encryption methods.
   */
  static final Set<EncryptionMethod> SUPPORTED_ENCRYPTION_METHODS = new UnmodifiableSetView(new Set.from([
      EncryptionMethod.A128CBC_HS256,
      EncryptionMethod.A192CBC_HS384,
      EncryptionMethod.A256CBC_HS512,
      EncryptionMethod.A128GCM,
      EncryptionMethod.A192GCM,
      EncryptionMethod.A256GCM,
      EncryptionMethod.A128CBC_HS256_DEPRECATED,
      EncryptionMethod.A256CBC_HS512_DEPRECATED
  ]));


//  /**
//   * Initialises the supported algorithms and encryption methods.
//   */
//  static init() {
//
//    Set<JWEAlgorithm> algs = new Set();
//    algs.add(JWEAlgorithm.RSA1_5);
//    algs.add(JWEAlgorithm.RSA_OAEP);
//    algs.add(JWEAlgorithm.RSA_OAEP_256);
//    SUPPORTED_ALGORITHMS = new UnmodifiableSetView(algs);
//
//    Set<EncryptionMethod> methods = new Set();
//    methods.add(EncryptionMethod.A128CBC_HS256);
//    methods.add(EncryptionMethod.A192CBC_HS384);
//    methods.add(EncryptionMethod.A256CBC_HS512);
//    methods.add(EncryptionMethod.A128GCM);
//    methods.add(EncryptionMethod.A192GCM);
//    methods.add(EncryptionMethod.A256GCM);
//    methods.add(EncryptionMethod.A128CBC_HS256_DEPRECATED);
//    methods.add(EncryptionMethod.A256CBC_HS512_DEPRECATED);
//    SUPPORTED_ENCRYPTION_METHODS = new UnmodifiableSetView(methods);
//  }

  /**
   * Creates a new RSA encryption / decryption provider.
   */
  RSACryptoProvider() :super(SUPPORTED_ALGORITHMS, SUPPORTED_ENCRYPTION_METHODS);

}

