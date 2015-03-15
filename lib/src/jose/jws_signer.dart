part of jose_jwt.jose;

/**
 * Interface for signing JSON Web Signature (JWS) objects.
 *
 * <p>Callers can query the signer to determine its algorithm capabilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
abstract class JWSSigner extends JWSAlgorithmProvider {

	/**
	 * Signs the specified {@link JWSObject#getSigningInput input} of a 
	 * {@link JWSObject JWS object}.
	 *
	 * @param header       The JSON Web Signature (JWS) header. Must 
	 *                     specify a supported JWS algorithm and must not 
	 *                     be {@code null}.
	 * @param signingInput The input to sign. Must not be {@code null}.
	 *
	 * @return The resulting signature part (third part) of the JWS object.
	 *
	 * @throws JOSEException If the JWS algorithm is not supported or if
	 *                       signing failed for some other reason.
	 */
	Base64URL sign(final JWSHeader header, final Uint8List signingInput);

}
