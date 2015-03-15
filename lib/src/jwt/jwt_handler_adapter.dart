part of jose_jwt.jwt;

/**
 * JWT handler adapter. Intended to be extended by classes that need to handle
 * only a subset of the JWT types.
 *
 * @author Vladimir Dzhuvinov
 * @since 3.4
 * @version $version$ (2014-11-18)
 */
class JWTHandlerAdapter<T> implements JWTHandler<T> {


  @override
  T onPlainJWT(final PlainJWT plainJWT) {
    return null;
  }


  @override
  T onSignedJWT(final SignedJWT signedJWT) {
    return null;
  }


  @override
  T onEncryptedJWT(final EncryptedJWT encryptedJWT) {
    return null;
  }
}
