part of jose_jwt.jose;

/**
 * Interface for encrypting JSON Web Encryption (JWE) objects.
 *
 * <p>Callers can query the encrypter to determine its algorithm capabilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2012-10-04)
 */
abstract class JWEEncrypter extends JWEAlgorithmProvider {


  /**
   * Encrypts the specified clear text of a {@link JWEObject JWE object}.
   *
   * @param header    The JSON Web Encryption (JWE) header. Must specify a
   *                  supported JWE algorithm and must not be
   *                  {@code null}.
   * @param clearText The clear text to encrypt. Must not be {@code null}.
   *
   * @return The resulting JWE crypto parts.
   *
   * @throws JOSEException If the JWE algorithm is not supported or if
   *                       encryption failed for some other reason.
   */
  JWECryptoParts encrypt(final JWEHeader header, final Uint8List clearText);

}

