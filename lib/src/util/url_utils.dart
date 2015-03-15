part of jose_jwt.util;

/**
 * URL utilities.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-12-14)
 */
class URLUtils {

/*

	/**
	 * Reads the content of the specified URL.
	 *
	 * @param url            The URL content. Must not be {@code null}.
	 * @param connectTimeout The URL connection timeout, in milliseconds.
	 *                       If zero no (infinite) timeout.
	 * @param readTimeout    The URL read timeout, in milliseconds. If zero
	 *                       no (infinite) timeout.
	 * @param sizeLimit      The read size limit, in bytes. If negative no
	 *                       limit.
	 *
	 * @return The content.
	 *
	 * @throws IOException If the URL content couldn't be read.
	 */
	public static String read(final URL url,
				  final int connectTimeout,
				  final int readTimeout,
				  final int sizeLimit)
		throws IOException {

		URLConnection conn = url.openConnection();

		conn.setConnectTimeout(connectTimeout);
		conn.setReadTimeout(readTimeout);

		InputStream inputStream = conn.getInputStream();

		if (sizeLimit > 0) {
			inputStream = new BoundedInputStream(inputStream, sizeLimit);
		}

		try {
			return IOUtils.toString(inputStream);

		} finally {

			IOUtils.closeQuietly(inputStream);
		}
	}
*/

}
