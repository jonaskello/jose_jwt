part of jose_jwt.crypto;

/**
 * Critical header parameter checker.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-07-08)
 */
class CriticalHeaderParameterChecker {


	/**
	 * The critical header parameters to ignore.
	 */
	Set<String> _ignoredCritParams = new Set();

	/**
	 * Gets the names of the critical header parameters to ignore.
	 *
	 * @return The names of the critical parameters to ignore. Empty or
	 *         {@code null} if none.
	 */
	Set<String> getIgnoredCriticalHeaders() {

		return _ignoredCritParams;
	}

	/**
	 * Sets the names of the critical header parameters to ignore.
	 *
	 * @param headers The names of the critical parameter to ignore. Empty
	 *                or {@code null} if none.
	 */
	void setIgnoredCriticalHeaders(final Set<String> headers) {

		_ignoredCritParams = headers;
	}

	/**
	 * Returns {@code true} if the specified header passes the critical
	 * parameters check.
	 *
	 * @param header The JWS or JWE header to check. Must not be
	 *               {@code null}.
	 *
	 * @return {@code true} if the header passes, {@code false} if the
	 *         header contains one or more critical header parameters which
	 *         must not be ignored.
	 */
	bool headerPasses(final Header header) {

		Set<String> crit = header.getCriticalParams();

		if (crit == null || crit.isEmpty) {
			return true; // OK
		}

		return _ignoredCritParams != null && _ignoredCritParams.containsAll(crit);
	}

}

