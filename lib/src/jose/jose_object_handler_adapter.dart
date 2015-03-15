part of jose_jwt.jose;

/**
 * JOSE object handler adapter.  Intended to be extended by classes that need
 * to handle only a subset of the JOSE object types.
 *
 * @author Vladimir Dzhuvinov
 * @since 3.4
 * @version $version$ (2014-11-18)
 */
class JOSEObjectHandlerAdapter<T> implements JOSEObjectHandler<T> {


  @override
  T onPlainObject(final PlainObject plainObject) {
    return null;
  }


  @override
  T onJWSObject(final JWSObject jwsObject) {
    return null;
  }


  @override
  T onJWEObject(final JWEObject jweObject) {
    return null;
  }

}
