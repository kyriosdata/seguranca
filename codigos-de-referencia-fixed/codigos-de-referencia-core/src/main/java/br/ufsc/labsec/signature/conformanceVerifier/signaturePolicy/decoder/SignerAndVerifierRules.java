/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;
import org.w3c.dom.Node;

///**
// * SignerAndVerifierRules ::= SEQUENCE {
// signerRules      SignerRules,
// verifierRules    VerifierRules }
// * **/

///**
// * <xsd:complexType name="SignerAndVerifierRulesType">
// <xsd:sequence>
// <xsd:element name="SignerRules" type="SignerRulesType"/>
// <xsd:element name="VerifierRules" type="VerifierRulesType"/>
// </xsd:sequence>
// </xsd:complexType>
// */

/**
 * Esta classe define as regras do assinante e as regras de verificação.
 */
public class SignerAndVerifierRules {
    /**
     * Regras do assinante
     */
    private SignerRules signerRules;
    /**
     * Regras da verificação
     */
    private VerifierRules verifierRules;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param signerAndVerifierRules codificação ASN1 do atributo
     *            {@link SignerAndVerifierRules}.
     */
    public SignerAndVerifierRules(ASN1Sequence signerAndVerifierRules) {

        this.signerRules = new SignerRules((ASN1Sequence) signerAndVerifierRules.getObjectAt(0));
        this.verifierRules = new VerifierRules((ASN1Sequence) signerAndVerifierRules.getObjectAt(1));
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param element elemento XML que representa o atributo
     *            {@link SignerAndVerifierRules}.
     */
    public SignerAndVerifierRules(Node element) {

        this.signerRules = new SignerRules(element.getChildNodes().item(0));
        this.verifierRules = new VerifierRules(element.getChildNodes().item(1));
    }

    /**
     * Retorna as regras do assinante
     * @return As regras do assinante
     */
    public SignerRules getSignerRules() {
        return this.signerRules;
    }

    /**
     * Retorna as regras de verificação
     * @return As regras de verificação
     */
    public VerifierRules getVerifierRules() {
        return this.verifierRules;
    }
}
