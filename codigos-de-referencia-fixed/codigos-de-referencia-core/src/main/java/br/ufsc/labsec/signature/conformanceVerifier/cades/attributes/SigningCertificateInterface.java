/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes;

import java.security.cert.CertSelector;
import java.util.List;

import org.bouncycastle.asn1.ess.ESSCertID;

/**
 * Usada pelas classes {@link br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate} e
 * {@link br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2}.
 */
public interface SigningCertificateInterface extends SignatureAttribute, CertSelector {

    /**
     * Obtém todos os certificados que foram guardados no atributo
     * @return A lista dos certificados do atributo
     */
    List<ESSCertID> getESSCertID();
}
