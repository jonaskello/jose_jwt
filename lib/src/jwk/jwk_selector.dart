part of jose_jwt.jwk;

/**
 * Utility for selecting one or more JSON Web Keys (JWKs) from a JWK set.
 *
 * <p>Supports key selection by:
 *
 * <ul>
 *     <li>Any, unspecified, one or more key types (typ).
 *     <li>Any, unspecified, one or more key uses (use).
 *     <li>Any, unspecified, one or more key operations (key_ops).
 *     <li>Any, unspecified, one or more key algorithms (alg).
 *     <li>Any, unspecified, one or more key identifiers (kid).
 *     <li>Private only key.
 *     <li>Public only key.
 * </ul>
 *
 * <p>Selection by X.509 certificate URL, thumbprint and chain is not
 * supported.
 *
 * @author Vladimir Dzhuvinov
 * @version $version$ (2014-04-03)
 */
class JWKSelector {

/*

	/**
	 * The selected key types.
	 */
	private Set<KeyType> types;


	/**
	 * The selected public key uses.
	 */
	private Set<KeyUse> uses;


	/**
	 * The selected key operations.
	 */
	private Set<KeyOperation> ops;


	/**
	 * The selected algorithms.
	 */
	private Set<Algorithm> algs;


	/**
	 * The selected key IDs.
	 */
	private Set<String> ids;


	/**
	 * If {@code true} only private keys are matched.
	 */
	private boolean privateOnly = false;


	/**
	 * If {@code true} only public keys are matched.
	 */
	private boolean publicOnly = false;


	/**
	 * Gets the selected key types.
	 *
	 * @return The key types, {@code null} if not specified.
	 */
	public Set<KeyType> getKeyTypes() {

		return types;
	}


	/**
	 * Sets a single selected key type.
	 *
	 * @param kty The key type, {@code null} if not specified.
	 */
	public void setKeyType(final KeyType kty) {

		if (kty == null) {
			types = null;
		} else {
			types = new HashSet<>(Arrays.asList(kty));
		}
	}


	/**
	 * Sets the selected key types.
	 *
	 * @param types The key types.
	 */
	public void setKeyTypes(final KeyType ... types) {

		setKeyTypes(new HashSet<>(Arrays.asList(types)));
	}


	/**
	 * Sets the selected key types.
	 *
	 * @param types The key types, {@code null} if not specified.
	 */
	public void setKeyTypes(final Set<KeyType> types) {

		this.types = types;
	}


	/**
	 * Gets the selected public key uses.
	 *
	 * @return The public key uses, {@code null} if not specified.
	 */
	public Set<KeyUse> getKeyUses() {

		return uses;
	}


	/**
	 * Sets a single selected public key use.
	 *
	 * @param use The public key use, {@code null} if not specified.
	 */
	public void setKeyUse(final KeyUse use) {

		if (use == null) {
			uses = null;
		} else {
			uses = new HashSet<>(Arrays.asList(use));
		}
	}


	/**
	 * Sets the selected public key uses.
	 *
	 * @param uses The public key uses.
	 */
	public void setKeyUses(final KeyUse... uses) {

		setKeyUses(new HashSet<>(Arrays.asList(uses)));
	}


	/**
	 * Sets the selected public key uses.
	 *
	 * @param uses The public key uses, {@code null} if not specified.
	 */
	public void setKeyUses(final Set<KeyUse> uses) {

		this.uses = uses;
	}


	/**
	 * Gets the selected key operations.
	 *
	 * @return The key operations, {@code null} if not specified.
	 */
	public Set<KeyOperation> getKeyOperations() {

		return ops;
	}


	/**
	 * Sets a single selected key operation.
	 *
	 * @param op The key operation, {@code null} if not specified.
	 */
	public void setKeyOperation(final KeyOperation op) {

		if (op == null) {
			ops = null;
		} else {
			ops = new HashSet<>(Arrays.asList(op));
		}
	}


	/**
	 * Sets the selected key operations.
	 *
	 * @param ops The key operations.
	 */
	public void setKeyOperations(final KeyOperation... ops) {

		setKeyOperations(new HashSet<>(Arrays.asList(ops)));
	}


	/**
	 * Sets the selected key operations.
	 *
	 * @param ops The key operations, {@code null} if not specified.
	 */
	public void setKeyOperations(final Set<KeyOperation> ops) {

		this.ops = ops;
	}


	/**
	 * Gets the selected JOSE algorithms.
	 *
	 * @return The JOSE algorithms, {@code null} if not specified.
	 */
	public Set<Algorithm> getAlgorithms() {

		return algs;
	}


	/**
	 * Sets a singled selected JOSE algorithm.
	 *
	 * @param alg The JOSE algorithm, {@code null} if not specified.
	 */
	public void setAlgorithm(final Algorithm alg) {

		if (alg == null) {
			algs = null;
		} else {
			algs = new HashSet<>(Arrays.asList(alg));
		}
	}


	/**
	 * Sets the selected JOSE algorithms.
	 *
	 * @param algs The JOSE algorithms.
	 */
	public void setAlgorithms(final Algorithm ... algs) {

		setAlgorithms(new HashSet<>(Arrays.asList(algs)));
	}


	/**
	 * Sets the selected JOSE algorithms.
	 *
	 * @param algs The JOSE algorithms, {@code null} if not specified.
	 */
	public void setAlgorithms(final Set<Algorithm> algs) {

		this.algs = algs;
	}


	/**
	 * Gets the selected key IDs.
	 *
	 * @return The key IDs, {@code null} if not specified.
	 */
	public Set<String> getKeyIDs() {

		return ids;
	}


	/**
	 * Sets the selected key IDs.
	 *
	 * @param ids The key IDs.
	 */
	public void setKeyIDs(final String ... ids) {

		setKeyIDs(new HashSet<>(Arrays.asList(ids)));
	}


	/**
	 * Sets the selected key IDs.
	 *
	 * @param ids The key IDs, {@code null} if not specified.
	 */
	public void setKeyIDs(final Set<String> ids) {

		this.ids = ids;
	}


	/**
	 * Sets a single selected key ID.
	 *
	 * @param id The key ID, {@code null} if not specified.
	 */
	public void setKeyID(final String id) {

		if (id == null) {
			ids = null;
		} else {
			ids = new HashSet<>(Arrays.asList(id));
		}
	}


	/**
	 * Gets the selection of private keys.
	 *
	 * @return If {@code true} only private keys are selected.
	 */
	public boolean isPrivateOnly() {

		return privateOnly;
	}


	/**
	 * Sets the selection of private keys.
	 *
	 * @param privateOnly If {@code true} only private keys are selected.
	 */
	public void setPrivateOnly(final boolean privateOnly) {

		this.privateOnly = privateOnly;
	}


	/**
	 * Gets the selection of public keys.
	 *
	 * @return  If {@code true} only public keys are selected.
	 */
	public boolean isPublicOnly() {

		return publicOnly;
	}


	/**
	 * Sets the selection of public keys.
	 *
	 * @param publicOnly  If {@code true} only public keys are selected.
	 */
	public void setPublicOnly(final boolean publicOnly) {

		this.publicOnly = publicOnly;
	}


	/**
	 * Selects the keys from the specified JWK set that match the
	 * configured criteria.
	 *
	 * @param jwkSet The JWK set. May be {@code null}.
	 *
	 * @return The selected keys, ordered by their position in the JWK set,
	 *         empty list if none were matched or the JWK is {@code null}.
	 *
	 */
	public List<JWK> select(final JWKSet jwkSet) {

		List<JWK> matches = new LinkedList<>();

		if (jwkSet == null)
			return matches;

		for (JWK key: jwkSet.getKeys()) {

			if (privateOnly && ! key.isPrivate())
				continue;

			if (publicOnly && key.isPrivate())
				continue;

			if (types != null && ! types.contains(key.getKeyType()))
				continue;

			if (uses != null && ! uses.contains(key.getKeyUse()))
				continue;

			if (ops != null) {

				if (ops.contains(null) && key.getKeyOperations() == null) {
					// pass
				} else if (key.getKeyOperations() != null && ops.containsAll(key.getKeyOperations())) {
					// pass
				} else {
					continue;
				}
			}

			if (algs != null && ! algs.contains(key.getAlgorithm()))
				continue;

			if (ids != null && ! ids.contains(key.getKeyID()))
				continue;

			matches.add(key);
		}

		return matches;
	}
*/

}
