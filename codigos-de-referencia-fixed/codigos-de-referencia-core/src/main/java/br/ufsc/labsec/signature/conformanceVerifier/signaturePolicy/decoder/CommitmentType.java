/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.DERUTF8String;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

///**
// * CommitmentType ::= SEQUENCE {
// identifier          CommitmentTypeIdentifier,
// fieldOfApplication [0] FieldOfApplication OPTIONAL,
// semantics           [1] DirectoryString OPTIONAL }
// */
//
///**
// *  <complexType name="CommitmentType">
// <complexContent>
// <restriction base="{http://www.w3.org/2001/XMLSchema}anyType">
// <sequence>
// <element name="CommitmentIdentifier" type="XAdES:ObjectIdentifierType"/>
// <element name="FieldOfApplication" type="xsd:string" minOccurs="0"/>
// <element name="Semantics" type="xsd:string" minOccurs="0"/>
// </sequence>
// </restriction>
// </complexContent>
// </complexType>
// */

/**
 * Este atributo indica o tipo de compromisso da Política de Assinatura.
 */
public class CommitmentType {

    /**
     * Identificador do atributo
     */
    private String identifier;
    /**
     * O atributo <code>FieldOfApplication</code>
     */
    private String fieldOfApplication;
    /**
     * O atributo <code>Semantics</code>
     */
    private String semantics;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN.1
     * @param commitmentType codificação ASN1 do atributo {@link CommitmentType}
     */
    public CommitmentType(ASN1Sequence commitmentType) {

        this.identifier = ((ASN1ObjectIdentifier) commitmentType.getObjectAt(0)).toString();
        this.fieldOfApplication = null;
        this.semantics = null;

        for (int i = 1; i < commitmentType.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) commitmentType.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    this.fieldOfApplication = ((DERUTF8String) taggetObj.getObject()).getString();
                    break;

                case 1:
                    this.semantics = ((DERUTF8String) taggetObj.getObject()).getString();
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param commitmentType elemento XML que representa o atributo
     *            {@link CommitmentType}.
     */
    public CommitmentType(Node commitmentType) {
        this.identifier = commitmentType.getChildNodes().item(0).getTextContent();
        this.fieldOfApplication = null;
        this.semantics = null;

        NodeList node = commitmentType.getChildNodes();
        for (int i = 0; i < node.getLength(); i++) {
            Element element = (Element) node.item(i);
            String tagName = element.getTagName();

            if (tagName.equals("pa:SignerAndVerifierRules")) {
                this.fieldOfApplication = commitmentType.getChildNodes().item(1).getTextContent();
            } else if (tagName.equals("pa:SigningCertTrustCondition")) {
                this.semantics = commitmentType.getChildNodes().item(2).getTextContent();
            }
        }
    }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    public String getIdentifier() {
        return identifier;
    }

    /**
     * Retorna o atributo <code>FieldOfApplication</code>
     * @return O atributo <code>FieldOfApplication</code>
     */
    public String getFieldOfApplication() {
        return fieldOfApplication;
    }

    /**
     * Retorna o atributo <code>Semantics</code>
     * @return O atributo <code>Semantics</code>
     */
    public String getSemantics() {
        return semantics;
    }

    /**
     * Verifica se o atributo <code>FieldOfApplication</code> existe
     * @return Indica se o atributo não é nulo
     */
    public boolean hasFieldOfApplication() {
        return this.fieldOfApplication != null;
    }

    /**
     * Verifica se o atributo <code>Semantics</code> existe
     * @return Indica se o atributo não é nulo
     */
    public boolean hasSemantics() {
        return this.semantics != null;
    }
}
