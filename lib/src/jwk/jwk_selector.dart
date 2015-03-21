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


  /**
   * The selected key types.
   */
  Set<KeyType> _types;


  /**
   * The selected key uses.
   */
  Set<KeyUse> _uses;


  /**
   * The selected key operations.
   */
  Set<KeyOperation> _ops;


  /**
   * The selected algorithms.
   */
  Set<Algorithm> _algs;


  /**
   * The selected key IDs.
   */
  Set<String> _ids;


  /**
   * If {@code true} only private keys are matched.
   */
  bool _privateOnly = false;


  /**
   * If {@code true} only keys are matched.
   */
  bool _publicOnly = false;


  /**
   * Gets the selected key types.
   *
   * @return The key types, {@code null} if not specified.
   */
  Set<KeyType> getKeyTypes() {

    return _types;
  }


  /**
   * Sets a single selected key type.
   *
   * @param kty The key type, {@code null} if not specified.
   */
  void setKeyType(final KeyType kty) {

    if (kty == null) {
      _types = null;
    } else {
      _types = new Set.from([kty]);
    }
  }


//  /**
//   * Sets the selected key types.
//   *
//   * @param types The key types.
//   */
//  void setKeyTypesFromList(final List<KeyType> types) {
//
//    setKeyTypes(new Set.from([types]));
//  }


  /**
   * Sets the selected key types.
   *
   * @param types The key types, {@code null} if not specified.
   */
  void setKeyTypes(final Set<KeyType> types) {

    _types = types;
  }


  /**
   * Gets the selected key uses.
   *
   * @return The key uses, {@code null} if not specified.
   */
  Set<KeyUse> getKeyUses() {

    return _uses;
  }


//	/**
//	 * Sets a single selected key use.
//	 *
//	 * @param use The key use, {@code null} if not specified.
//	 */
//	void setKeyUse(final KeyUse use) {
//
//		if (use == null) {
//			uses = null;
//		} else {
//			uses = new Set(Arrays.asList(use));
//		}
//	}


//  /**
//   * Sets the selected key uses.
//   *
//   * @param uses The key uses.
//   */
//  void setKeyUsesFromList(final List<KeyUse> uses) {
//
//    setKeyUses(new Set.from([uses]));
//  }


  /**
   * Sets the selected key uses.
   *
   * @param uses The key uses, {@code null} if not specified.
   */
  void setKeyUses(final Set<KeyUse> uses) {

    _uses = uses;
  }


  /**
   * Gets the selected key operations.
   *
   * @return The key operations, {@code null} if not specified.
   */
  Set<KeyOperation> getKeyOperations() {

    return _ops;
  }


  /**
   * Sets a single selected key operation.
   *
   * @param op The key operation, {@code null} if not specified.
   */
  void setKeyOperation(final KeyOperation op) {

    if (op == null) {
      _ops = null;
    } else {
      _ops = new Set.from([op]);
    }
  }


//  /**
//   * Sets the selected key operations.
//   *
//   * @param ops The key operations.
//   */
//  void setKeyOperationsFromList(final List<KeyOperation> ops) {
//
//    setKeyOperations(new Set.from(ops));
//  }


  /**
   * Sets the selected key operations.
   *
   * @param ops The key operations, {@code null} if not specified.
   */
  void setKeyOperations(final Set<KeyOperation> ops) {

    _ops = ops;
  }


  /**
   * Gets the selected JOSE algorithms.
   *
   * @return The JOSE algorithms, {@code null} if not specified.
   */
  Set<Algorithm> getAlgorithms() {

    return _algs;
  }


  /**
   * Sets a singled selected JOSE algorithm.
   *
   * @param alg The JOSE algorithm, {@code null} if not specified.
   */
  void setAlgorithm(final Algorithm alg) {

    if (alg == null) {
      _algs = null;
    } else {
      _algs = new Set.from([alg]);
    }
  }


//	/**
//	 * Sets the selected JOSE algorithms.
//	 *
//	 * @param algs The JOSE algorithms.
//	 */
//	void setAlgorithmsFromList(final List<Algorithm> algs) {
//
//		setAlgorithms(new Set.from(algs));
//	}


  /**
   * Sets the selected JOSE algorithms.
   *
   * @param algs The JOSE algorithms, {@code null} if not specified.
   */
  void setAlgorithms(final Set<Algorithm> algs) {

    _algs = algs;
  }


  /**
   * Gets the selected key IDs.
   *
   * @return The key IDs, {@code null} if not specified.
   */
  Set<String> getKeyIDs() {

    return _ids;
  }


//	/**
//	 * Sets the selected key IDs.
//	 *
//	 * @param ids The key IDs.
//	 */
//	void setKeyIDsFromList(final List<String> ids) {
//
//		setKeyIDs(new Set.from(ids));
//	}


  /**
   * Sets the selected key IDs.
   *
   * @param ids The key IDs, {@code null} if not specified.
   */
  void setKeyIDs(final Set<String> ids) {

    _ids = ids;
  }


  /**
   * Sets a single selected key ID.
   *
   * @param id The key ID, {@code null} if not specified.
   */
  void setKeyID(final String id) {

    if (id == null) {
      _ids = null;
    } else {
      _ids = new Set.from([id]);
    }
  }


  /**
   * Gets the selection of private keys.
   *
   * @return If {@code true} only private keys are selected.
   */
  bool isPrivateOnly() {

    return _privateOnly;
  }


  /**
   * Sets the selection of private keys.
   *
   * @param privateOnly If {@code true} only private keys are selected.
   */
  void setPrivateOnly(final bool privateOnly) {

    _privateOnly = privateOnly;
  }


  /**
   * Gets the selection of keys.
   *
   * @return  If {@code true} only keys are selected.
   */
  bool isPublicOnly() {

    return _publicOnly;
  }


  /**
   * Sets the selection of keys.
   *
   * @param publicOnly  If {@code true} only keys are selected.
   */
  void setPublicOnly(final bool publicOnly) {

    _publicOnly = publicOnly;
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
  List<JWK> select(final JWKSet jwkSet) {

    List<JWK> matches = new List();

    if (jwkSet == null)
      return matches;

    for (JWK key in jwkSet.getKeys()) {

      if (_privateOnly && !key.isPrivate())
        continue;

      if (_publicOnly && key.isPrivate())
        continue;

      if (_types != null && !_types.contains(key.getKeyType()))
        continue;

      if (_uses != null && !_uses.contains(key.getKeyUse()))
        continue;

      if (_ops != null) {

        if (_ops.contains(null) && key.getKeyOperations() == null) {
          // pass
        } else if (key.getKeyOperations() != null && _ops.containsAll(key.getKeyOperations())) {
          // pass
        } else {
          continue;
        }
      }

      if (_algs != null && !_algs.contains(key.getAlgorithm()))
        continue;

      if (_ids != null && !_ids.contains(key.getKeyID()))
        continue;

      matches.add(key);
    }

    return matches;
  }

}
