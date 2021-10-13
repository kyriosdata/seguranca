/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

///**
// * AlgorithmIdentifier ::= SEQUENCE {
// algorithm OBJECT IDENTIFIER,
// parameters ANY DEFINED BY algorithm OPTIONAL }
// */

///**
// * <complexType name="DigestMethodType" mixed="true">
// <sequence>
// <any namespace="##other" processContents="lax" minOccurs="0" maxOccurs="unbounded"/>
// </sequence>
// <attribute name="Algorithm" type="anyURI" use="required"/>
// </complexType>
// */
/**
 * Esta classe representa um atributo que representa o identificador único do algoritmo e seus
 * parâmetros, que são opcionais.
 */
public class AlgorithmIdentifier {

    /**
     * O nome do algoritmo
     */
    private String algorithm;
    /**
     * Os parâmetros codificado em ASN.1
     */
    private ASN1Encodable parametersASN1;
    /**
     * Os parâmetros codificados em nodos XML
     */
    private NodeList parametersXML;
    /**
     * O identificador do algoritmo, codificado em ASN.1
     */
    private ASN1Sequence algorithmSequence;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param algorithmIdentifier codificação ASN1 do atributo
     *            {@link AlgorithmIdentifier}.
     */
    public AlgorithmIdentifier(ASN1Sequence algorithmIdentifier) {

        this.algorithmSequence = algorithmIdentifier;
        this.parametersASN1 = null;
        this.algorithm = ((ASN1ObjectIdentifier) algorithmIdentifier.getObjectAt(0)).toString();
        if (algorithmIdentifier.size() > 1) {
            this.parametersASN1 = (ASN1Encodable) algorithmIdentifier.getObjectAt(1);
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML
     * @param algorithmIdentifier elemento XML que representa o atributo
     *            {@link AlgorithmIdentifier}.
     */
    public AlgorithmIdentifier(Node algorithmIdentifier) {

        this.parametersXML = null;
        this.algorithm = algorithmIdentifier.getAttributes().getNamedItem("Algorithm").getTextContent();
        if (algorithmIdentifier.hasChildNodes()) {
            this.parametersXML = algorithmIdentifier.getChildNodes();
        }
    }

    /**
     * Retorna o nome do algoritmo
     * @return O nome do algoritmo
     */
    public String getAlgorithm() {
        return algorithm;
    }

    /**
     * Retorna os parâmetros em ASN.1
     * @return Os parâmetros em ASN.1
     */
    public ASN1Encodable getParametersASN1() {
        return parametersASN1;
    }

    /**
     * Retorna os parâmetros em XML
     * @return Os parâmetros em XML
     */
    public NodeList getParametersXML() {
        return parametersXML;
    }

    /**
     * Retorna o identificador do algoritmo em ASN.1
     * @return O identificador do algoritmo
     */
    public ASN1Sequence getAlgorithmSequence() {
        return this.algorithmSequence;
    }

    /**
     * Informa se esta política é codificada em XML
     * @return Indica se esta política é XML
     */
    public boolean isXML() {
        return this.parametersXML != null;
    }
}
