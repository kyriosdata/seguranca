/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes;

import java.security.cert.CertSelector;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SigningCertificate;

/**
 * Usada pelas classes {@link IdAaSigningCertificate}
 * {@link IdAaSigningCertificateV2} e {@link SigningCertificate}.
 */
public interface SigningCertificateInterface extends SignatureAttribute, CertSelector {
}
