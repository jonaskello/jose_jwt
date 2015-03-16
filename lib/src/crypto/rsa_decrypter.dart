part of jose_jwt.crypto;

/**
 * RSA decrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
 * is thread-safe.
 *
 * <p>Supports the following JWE algorithms:
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
 * <p>Accepts all {@link com.nimbusds.jose.JWEHeader#getRegisteredParameterNames
 * registered JWE header parameters}. Use {@link #setAcceptedAlgorithms} and
 * {@link #setAcceptedEncryptionMethods} to restrict the acceptable JWE
 * algorithms and encryption methods.
 *
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 *
 */
//@ThreadSafe
class RSADecrypter extends RSACryptoProvider implements JWEDecrypter {

  /**
   * The accepted JWE algorithms.
   */
  Set<JWEAlgorithm> _acceptedAlgs; // = new Set.from(supportedAlgorithms());


  /**
   * The accepted encryption methods.
   */
  Set<EncryptionMethod> _acceptedEncs; // = new Set.from(supportedEncryptionMethods());


  /**
   * The critical header parameter checker.
   */
  final CriticalHeaderParameterChecker _critParamChecker = new CriticalHeaderParameterChecker();


  /**
   * The private RSA key.
   */
  final RSAPrivateKey _privateKey;

  /**
   * Creates a new RSA decrypter.
   *
   * @param privateKey The private RSA key. Must not be {@code null}.
   */
  RSADecrypter(this._privateKey) {

    if (_privateKey == null) {
      throw new ArgumentError.notNull("privateKey");
    }

    _acceptedAlgs = new Set.from(supportedAlgorithms());
    _acceptedEncs = new Set.from(supportedEncryptionMethods());

  }

  /**
   * Gets the private RSA key.
   *
   * @return The private RSA key.
   */
  RSAPrivateKey getPrivateKey() {

    return _privateKey;
  }

  @override
  Set<JWEAlgorithm> getAcceptedAlgorithms() {

    return _acceptedAlgs;
  }

  @override
  void setAcceptedAlgorithms(Set<JWEAlgorithm> acceptedAlgs) {

    if (acceptedAlgs == null) {
      throw new ArgumentError.notNull("acceptedAlgs");
    }

    if (!supportedAlgorithms().containsAll(acceptedAlgs)) {
      throw new ArgumentError("Unsupported JWE algorithm(s)");
    }

  }

  @override
  Set<EncryptionMethod> getAcceptedEncryptionMethods() {

    return _acceptedEncs;
  }

  @override
  void setAcceptedEncryptionMethods(final Set<EncryptionMethod> acceptedEncs) {

    if (acceptedEncs == null)
      throw new ArgumentError("The accepted encryption methods must not be null");

    if (!supportedEncryptionMethods().containsAll(acceptedEncs)) {
      throw new ArgumentError("Unsupported encryption method(s)");
    }

    _acceptedEncs = acceptedEncs;
  }

  @override
  Set<String> getIgnoredCriticalHeaderParameters() {

    return _critParamChecker.getIgnoredCriticalHeaders();
  }

  @override
  void setIgnoredCriticalHeaderParameters(final Set<String> headers) {

    _critParamChecker.setIgnoredCriticalHeaders(headers);
  }

  @override
  Uint8List decrypt(final JWEHeader header,
                    final Base64URL encryptedKey,
                    final Base64URL iv,
                    final Base64URL cipherText,
                    final Base64URL authTag) {

    throw new UnimplementedError();
/*
    // Validate required JWE parts
    if (encryptedKey == null) {

      throw new JOSEException("The encrypted key must not be null");
    }

    if (iv == null) {

      throw new JOSEException("The initialization vector (IV) must not be null");
    }

    if (authTag == null) {

      throw new JOSEException("The authentication tag must not be null");
    }

    if (!_critParamChecker.headerPasses(header)) {

      throw new JOSEException("Unsupported critical header parameter");
    }

    // Derive the content encryption key
    JWEAlgorithm alg = header.getAlgorithm();

    SecretKey cek;

    if (alg == JWEAlgorithm.RSA1_5) {

      int keyLength = header.getEncryptionMethod().cekBitLength();

      // Protect against MMA attack by generating random CEK on failure,
      // see http://www.ietf.org/mail-archive/web/jose/current/msg01832.html
      SecureRandom randomGen = getSecureRandom();
      SecretKey randomCEK = AES.generateKey(keyLength, randomGen);

      try {
        cek = RSA1_5.decryptCEK(privateKey, encryptedKey.decode(), keyLength, keyEncryptionProvider);

        if (cek == null) {
          // CEK length mismatch, signalled by null instead of
          // exception to prevent MMA attack
          cek = randomCEK;
        }

      } catch (e) {
        // continue
        cek = randomCEK;
      }

    } else if (alg == JWEAlgorithm.RSA_OAEP) {

      cek = RSA_OAEP.decryptCEK(_privateKey, encryptedKey.decode(), keyEncryptionProvider);

    } else if (alg == JWEAlgorithm.RSA_OAEP_256) {

      cek = RSA_OAEP_256.decryptCEK(_privateKey, encryptedKey.decode(), keyEncryptionProvider);

    } else {

      throw new JOSEException("Unsupported JWE algorithm, must be RSA1_5 or RSA_OAEP");
    }

    // Compose the AAD
    Uint8List aad = StringUtils.toByteArray(header.toBase64URL().toString());

    // Decrypt the cipher text according to the JWE enc
    EncryptionMethod enc = header.getEncryptionMethod();

    Uint8List plainText;

    if (enc == EncryptionMethod.A128CBC_HS256 ||
    enc == EncryptionMethod.A192CBC_HS384 ||
    enc == EncryptionMethod.A256CBC_HS512) {

      plainText = AESCBC.decryptAuthenticated(
          cek,
          iv.decode(),
          cipherText.decode(),
          aad,
          authTag.decode(),
          contentEncryptionProvider,
          macProvider);

    } else if (enc == EncryptionMethod.A128GCM ||
    enc == EncryptionMethod.A192GCM ||
    enc == EncryptionMethod.A256GCM) {

      plainText = AESGCM.decrypt(
          cek,
          iv.decode(),
          cipherText.decode(),
          aad,
          authTag.decode(),
          contentEncryptionProvider);

    } else if (enc == EncryptionMethod.A128CBC_HS256_DEPRECATED ||
    enc == EncryptionMethod.A256CBC_HS512_DEPRECATED) {

      plainText = AESCBC.decryptWithConcatKDF(
          header,
          cek,
          encryptedKey,
          iv,
          cipherText,
          authTag,
          contentEncryptionProvider,
          macProvider);

    } else {

      throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
    }

    // Apply decompression if requested
    return DeflateHelper.applyDecompression(header, plainText);
*/
  }

}

