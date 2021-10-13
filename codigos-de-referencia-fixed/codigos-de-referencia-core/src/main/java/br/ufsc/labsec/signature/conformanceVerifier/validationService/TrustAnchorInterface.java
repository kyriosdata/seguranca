package br.ufsc.labsec.signature.conformanceVerifier.validationService;

import java.security.cert.TrustAnchor;
import java.util.Set;

/**
 * Esta interface representa uma âncora de confiança
 */
public interface TrustAnchorInterface {

    /**
     * Retorna o conjunto de âncoras de confiança
     * @return O conjunto de âncoras de confiança
     */
    public Set<TrustAnchor> getTrustAnchorSet();

}
