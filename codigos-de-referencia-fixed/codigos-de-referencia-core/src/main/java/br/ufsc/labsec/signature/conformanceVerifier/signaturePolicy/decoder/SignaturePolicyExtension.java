/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.w3c.dom.Node;

///**
// * SignPolExtn ::= SEQUENCE {
// extnID      OBJECT IDENTIFIER,
// extnValue   OCTET STRING }
// */

/**
 * Esta classe especifica as regras adicionais da Política de Assinatura.
 */
public class SignaturePolicyExtension {

    /**
     * Identificados da regra
     */
    private String extnID;
    /**
     * Valor da regra
     */
    private DEROctetString extnValue;
    /**
     * Nodo que contém as regras
     */
    private Node policyExtension;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN.1
     * @param extension codificação ASN1 do atributo
     *            {@link SignaturePolicyExtension}.
     */
    public SignaturePolicyExtension(ASN1Sequence extension) {
        this.extnID = ((ASN1ObjectIdentifier) extension.getObjectAt(0)).toString();
        this.extnValue = (DEROctetString) extension.getObjectAt(1);
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML
     * @param extension elemento XML que representa o atributo
     *            {@link SignaturePolicyExtension}.
     */
    public SignaturePolicyExtension(Node extension) {

        this.policyExtension = extension;
    }

    /**
     * Obtém o atributo <code>SignaturePolicyExtension</code> codificado para
     * XML.
     * @return O nodo XML do atributo
     */
    public Node getPolicyExtension() {
        return policyExtension;
    }

    /**
     * Retorna o atributo <code>ExtnID</code>.
     * @return O valor do atributo
     */
    public String getExtnID() {
        return this.extnID;
    }

    /**
     * Retorna o atributo <code>ExtnValue</code>.
     * @return O valor do atributo
     */
    public DEROctetString getExtnValue() {
        return this.extnValue;
    }

    /**
     * Verifica se a Política de Assinatura é XML
     * @return Indica se a Política de Assinatura é XML
     */
    public boolean isXML() {
        return this.policyExtension != null;
    }
}
