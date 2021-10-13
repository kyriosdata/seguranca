/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.crmf.AttributeTypeAndValue;

///**
// * AttributeConstraints ::= SEQUENCE {
// attributeTypeConstraints    [0] AttributeTypeConstraints OPTIONAL,
// attributeValueConstraints   [1] AttributeValueConstraints OPTIONAL }
// */

/**
 * Esta classe define um atributo que especifica as restrições de atributo
 */
public class AttributeConstraints {

    /**
     * Restrições de tipo de atributo
     */
    private String[] attributeTypeConstraints;
    /**
     * Restrições de valor de atributo
     */
    private AttributeTypeAndValue[] attributeValueConstraints;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN.1
     * @param attributeConstraints codificação ASN1 do atributo
     *            {@link AttributeConstraints}.
     */
    public AttributeConstraints(ASN1Sequence attributeConstraints) {

        this.attributeTypeConstraints = null;
        this.attributeValueConstraints = null;

        for (int i = 0; i < attributeConstraints.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) attributeConstraints.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    this.attributeTypeConstraints = readObjectIdentifiers((ASN1Sequence) taggetObj.getObject());
                    break;

                case 1:
                    this.attributeValueConstraints = getAttributeTypesAndValues((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Retorna a lista de identificadores dos objetos presentes na sequência ASN.1 dada
     * @param seq A sequência ASN.1
     * @return A lista de identificadores
     */
    private String[] readObjectIdentifiers(ASN1Sequence seq) {

        String[] ret = null;

        if (seq.size() > 0) {
            ret = new String[seq.size()];
            for (int i = 0; i < seq.size(); i++) {
                ret[i] = ((ASN1ObjectIdentifier) seq.getObjectAt(i)).toString();
            }
        }
        return ret;
    }

    /**
     * Retorna os tipos e valores dos atributos na sequência dada
     * @param attrType A sequência ASN.1
     * @return Array dos tipos e valores dos atributos
     */
    private AttributeTypeAndValue[] getAttributeTypesAndValues(ASN1Sequence attrType) {

        AttributeTypeAndValue[] ret = null;

        if (attrType.size() > 0) {
            ret = new AttributeTypeAndValue[attrType.size()];
            for (int i = 0; i < attrType.size(); i++) {
                ret[i] = AttributeTypeAndValue.getInstance(attrType);
            }
        }
        return ret;
    }

    /**
     * Retorna o atributo <code>AttributeTypeConstraints</code>.
     * @return O valor do atributo <code>AttributeTypeConstraints</code>.
     */
    public String[] getAttributeTypeConstraints() {
        return attributeTypeConstraints;
    }

    /**
     * Retorna o atributo <code>AttributeValueConstraints</code>.
     * @return O valor do atributo {@link AttributeTypeAndValue}.
     */
    public AttributeTypeAndValue[] getAttributeValueConstraints() {
        return attributeValueConstraints;
    }

    /**
     * Verifica se o atributo AttributeTypeConstraints existe
     * @return Indica se o atributo não é nulo
     */
    public boolean hasAttributeTypeConstraints() {
        return this.attributeTypeConstraints != null;
    }

    /**
     * Verifica se o atributo AttributeValueConstraints existe
     * @return Indica se o atributo não é nulo
     */
    public boolean hasAttributeValueConstraints() {
        return this.attributeValueConstraints != null;
    }
}
