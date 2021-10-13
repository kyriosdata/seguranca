/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;

///**
// * PolicyConstraints ::= SEQUENCE {
// requireExplicitPolicy    [0] SkipCerts OPTIONAL,
// inhibitPolicyMapping     [1] SkipCerts OPTIONAL }
// */

/**
 * Este atributo pode restringir a construção do caminho de certificação de duas
 * maneiras: pode ser usado para proibir mapeamento de políticas, ou exigir que
 * cada certificado do caminho de certificação contenha um identificador de
 * política aceitável. Ou seja, se presente, este atributo especifica os
 * requerimentos para a política de certificado, ou as restrições para a
 * política de mapeamento.
 */
public class PolicyConstraints {

    /**
     * Indica que é obrigatório que cada certificado do caminho de certificação
     * contenha um identificador de política aceitável
     */
    private ASN1Integer requireExplicitPolicy;
    /**
     * Indica se o mapeamento de políticas é proibido
     */
    private ASN1Integer inhibitPolicyMapping;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param policyConstraints codificação ASN1 do atributo
     *            {@link PolicyConstraints}.
     */
    public PolicyConstraints(ASN1Sequence policyConstraints) {

        this.requireExplicitPolicy = null;
        this.inhibitPolicyMapping = null;

        for (int i = 1; i < policyConstraints.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) policyConstraints.getObjectAt(i);

            switch (taggetObj.getTagNo()) {
                case 0:
                    this.requireExplicitPolicy = (ASN1Integer) taggetObj.getObject();
                    break;

                case 1:
                    this.inhibitPolicyMapping = (ASN1Integer) taggetObj.getObject();
                    break;
            }
        }
    }

    /**
     * Retorna o atributo <code>RequireExplicitPolicy</code>.
     * @return O valor do atributo
     */
    public ASN1Integer getRequireExplicitPolicy() {
        return requireExplicitPolicy;
    }

    /**
     * Retorna o atributo <code>InhibitPolicyMapping</code>.
     * @return O valor do atributo
     */
    public ASN1Integer getInhibitPolicyMapping() {
        return inhibitPolicyMapping;
    }

    /**
     * Verifica se existe o atributo <code>RequireExplicitPolicy</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasRequireExplicitPolicy() {
        return this.requireExplicitPolicy != null;
    }

    /**
     * Verifica se existe o atributo <code>InhibitPolicyMapping</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasInhibitPolicyMapping() {
        return this.inhibitPolicyMapping != null;
    }

}
