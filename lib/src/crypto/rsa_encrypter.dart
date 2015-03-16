part of jose_jwt.crypto;

/**
 * RSA encrypter of {@link com.nimbusds.jose.JWEObject JWE objects}. This class
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
 * @author David Ortiz
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-08-20)
 */
//@ThreadSafe
class RSAEncrypter extends RSACryptoProvider implements JWEEncrypter {


  /**
   * The public RSA key.
   */
  final RSAPublicKey _publicKey;


  /**
   * Creates a new RSA encrypter.
   *
   * @param publicKey The public RSA key. Must not be {@code null}.
   */
  RSAEncrypter(this._publicKey) {

    if (_publicKey == null) {
      throw new ArgumentError.notNull("publicKey");
    }

  }

  /**
   * Gets the public RSA key.
   *
   * @return The public RSA key.
   */
  RSAPublicKey getPublicKey() {

    return _publicKey;
  }

  @override
  JWECryptoParts encrypt(final JWEHeader header, final Uint8List bytes) {

    final JWEAlgorithm alg = header.getAlgorithm();
    final EncryptionMethod enc = header.getEncryptionMethod();

    // Generate and encrypt the CEK according to the enc method
    final SecureRandom randomGen = getSecureRandom();
    final SecretKey cek = AES.generateKey(enc.cekBitLength(), randomGen);

    Base64URL encryptedKey; // The second JWE part

    if (alg == JWEAlgorithm.RSA1_5) {

      encryptedKey = Base64URL.encodeBytes(RSA1_5.encryptCEK(_publicKey, cek, keyEncryptionProvider));

    } else if (alg == JWEAlgorithm.RSA_OAEP) {

      encryptedKey = Base64URL.encodeBytes(RSA_OAEP.encryptCEK(_publicKey, cek, keyEncryptionProvider));

    } else if (alg == JWEAlgorithm.RSA_OAEP_256) {

      encryptedKey = Base64URL.encodeBytes(RSA_OAEP_256.encryptCEK(_publicKey, cek, keyEncryptionProvider));

    } else {

      throw new JOSEException("Unsupported JWE algorithm, must be RSA1_5, RSA-OAEP, or RSA-OAEP-256");
    }


    // Apply compression if instructed
    Uint8List plainText = DeflateHelper.applyCompression(header, bytes);

    // Compose the AAD
    Uint8List aad = StringUtils.toByteArray(header.toBase64URL().toString());

    // Encrypt the plain text according to the JWE enc
    Uint8List iv;
    AuthenticatedCipherText authCipherText;

    if (enc == EncryptionMethod.A128CBC_HS256 ||
    enc == EncryptionMethod.A192CBC_HS384 ||
    enc == EncryptionMethod.A256CBC_HS512) {

      iv = AESCBC.generateIV(randomGen);

      authCipherText = AESCBC.encryptAuthenticated(
          cek, iv, plainText, aad,
          contentEncryptionProvider, macProvider);

    } else if (enc == EncryptionMethod.A128GCM ||
    enc == EncryptionMethod.A192GCM ||
    enc == EncryptionMethod.A256GCM) {

      iv = AESGCM.generateIV(randomGen);

      authCipherText = AESGCM.encrypt(
          cek, iv, plainText, aad,
          contentEncryptionProvider);

    } else if (enc == EncryptionMethod.A128CBC_HS256_DEPRECATED ||
    enc == EncryptionMethod.A256CBC_HS512_DEPRECATED) {

      iv = AESCBC.generateIV(randomGen);

      authCipherText = AESCBC.encryptWithConcatKDF(
          header, cek, encryptedKey, iv, plainText,
          contentEncryptionProvider, macProvider);

    } else {

      throw new JOSEException("Unsupported encryption method, must be A128CBC_HS256, A192CBC_HS384, A256CBC_HS512, A128GCM, A192GCM or A256GCM");
    }

    return new JWECryptoParts.noKey(encryptedKey,
    Base64URL.encodeBytes(iv),
    Base64URL.encodeBytes(authCipherText.getCipherText()),
    Base64URL.encodeBytes(authCipherText.getAuthenticationTag()));

  }

}
