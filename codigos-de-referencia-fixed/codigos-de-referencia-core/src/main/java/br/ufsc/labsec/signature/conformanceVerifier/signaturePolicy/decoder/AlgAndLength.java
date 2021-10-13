/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.math.BigInteger;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyExtension;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.w3c.dom.Node;

///**
// * AlgAndLength ::= SEQUENCE {
// algID           OBJECT IDENTIFIER,
// minKeyLength    INTEGER     OPTIONAL, -- Minimum key length in bits
// other       SignPolExtensions OPTIONAL
// }
// */
///**
// <xsd:complexType name="AlgAndLengthType">
// <xsd:sequence>
// <xsd:element name="AlgId" type="xsd:anyUri"/>
// <xsd:element name="MinKeyLength" type="xsd:integer" minOccurs="0"/>
// <xsd:element name="Other" type="SignPolExtensionsListType"
// minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
// */

/**
 * Este classe define um atributo representa uma restrição da Política de Assinatura
 */
public class AlgAndLength {

    /**
     * Identificador do atributo
     */
    protected String algID;
    /**
     * Tamanho mínimo da chave
     */
    protected Integer minKeyLength;
    /**
     * Uma restrição adicional
     */
    protected SignaturePolicyExtension other;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN.1
     * @param algAndLength codificação ASN1 do atributo {@link AlgAndLength}.
     */
    public AlgAndLength(ASN1Sequence algAndLength) {

        this.algID = ((ASN1ObjectIdentifier) algAndLength.getObjectAt(0)).toString();
        this.minKeyLength = null;
        this.other = null;

        if (algAndLength.size() > 1) {

            if (algAndLength.size() == 2) {
                ASN1Encodable derInteger = algAndLength.getObjectAt(1);
                if (derInteger instanceof ASN1Integer) {
                    ASN1Integer keyLength = (ASN1Integer) algAndLength.getObjectAt(1);
                    BigInteger bigInteger = keyLength.getValue();
                    this.minKeyLength = bigInteger.intValue();
                } else {
                    this.other = new SignaturePolicyExtension((ASN1Sequence) algAndLength.getObjectAt(1));
                }
            } else {
                ASN1Integer keyLength = (ASN1Integer) algAndLength.getObjectAt(1);
                BigInteger bigInteger = keyLength.getValue();
                this.minKeyLength = bigInteger.intValue();
                this.other = new SignaturePolicyExtension((ASN1Sequence) algAndLength.getObjectAt(2));
            }
        }

    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML
     * @param element elemento XML que representa o atributo
     *            {@link AlgAndLength}.
     */
    public AlgAndLength(Node element) {
        for (int i = 0; i < element.getChildNodes().getLength(); i++) {
            Node node = element.getChildNodes().item(i);
            if (node.getLocalName().equals("AlgId")) {
                this.algID = node.getTextContent();
            } else if (node.getLocalName().equals("MinKeyLength")) {
                this.minKeyLength = Integer.parseInt(node.getTextContent());
            } else if (node.equals("Other")) {
                // TODO implementar (Fazer uma política que contenha esse campo
                // para ser possível testar)
            }
        }
    }

    /**
     * Retorna o identificador do atributo. Esse identificador pode ser uma URL,
     * no caso do XAdES, ou um OID, no caso do CAdES. Este atributo é
     * obrigatório
     * @return O identificador do atributo
     */
    public String getAlgID() {
        return algID;
    }

    /**
     * Retorna o número mínimo de bits da chave do signatário. Este atributo é
     * opcional.
     * @return O número mínimo de bits da chave do signatário
     */
    public Integer getMinKeyLength() {
        return this.minKeyLength;
    }

    /**
     * Retorna alguma regra adicional da Política de Assinatura.
     * @return A regra adicional, ou nulo caso não exista
     */
    public SignaturePolicyExtension getOther() {
        return other;
    }

    /**
     * Verifica se a restrição tem um tamanho mínimo de chave.
     * @return Indica se a restrição existe
     */
    public boolean hasMinKeyLength() {
        return minKeyLength != null;
    }

    /**
     * Verifica se há alguma regra adicional da Política de Assinatura.
     * @return Indica se a existe mais alguma restrição
     */
    public boolean hasOther() {
        return other != null;
    }

}
