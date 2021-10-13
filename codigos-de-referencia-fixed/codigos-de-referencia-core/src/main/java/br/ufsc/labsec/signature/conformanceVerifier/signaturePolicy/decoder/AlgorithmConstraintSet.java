/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.w3c.dom.Node;

///**
// * AlgorithmConstraintSet ::= SEQUENCE {   -- Algorithm constrains on:
// signerAlgorithmConstraints [0]      AlgorithmConstraints OPTIONAL, -- signer
// eeCertAlgorithmConstraints [1]      AlgorithmConstraints OPTIONAL, -- issuer of end entity certs.
// caCertAlgorithmConstraints [2]      AlgorithmConstraints OPTIONAL, -- issuer of CA certificates
// aaCertAlgorithmConstraints [3]      AlgorithmConstraints OPTIONAL, -- Attribute Authority
// tsaCertAlgorithmConstraints [4]     AlgorithmConstraints OPTIONAL --  TimeStamping Authority
// }
// */
//
///**
// <xsd:element name="AlgorithmConstraintSet"
// type="AlgorithmConstraintSetType"/>
// <xsd:complexType name="AlgorithmConstraintSetType">
// <xsd:sequence>
// <xsd:element name="SignerAlgConstraints"
// type="AlgConstraintsListType" minOccurs="0"/>
// <xsd:element name="EeCertAlgConstraints"
// type="AlgConstraintsListType" minOccurs="0"/>
// <xsd:element name="CACertAlgConstraints"
// type="AlgConstraintsListType" minOccurs="0"/>
// <xsd:element name="AaCertAlgConstraints"
// type="AlgConstraintsListType" minOccurs="0"/>
// <xsd:element name="TSACertAlgConstraints"
// type="AlgConstraintsListType" minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
// <xsd:complexType name="AlgConstraintsListType">
// <xsd:sequence maxOccurs="unbounded">
// <xsd:element name="AlgAndLength" type="AlgAndLengthType"/>
// </xsd:sequence>
// </xsd:complexType>
// */
/**
 * Este atributo, se presente, identifica os algoritmos de assinatura que podem
 * ser usados para propósitos específicos e tamanhos mínimos de chaves que podem
 * ser usados.
 */
public class AlgorithmConstraintSet {

    /**
     * Restrições de algoritmos do assinante
     */
    private AlgAndLength[] signerAlgorithmConstraints;
    /**
     * Restrições de algoritmos de certificados de emissores de
     * certificados de entidade final
     */
    private AlgAndLength[] eeCertAlgorithmConstraints;
    /**
     * Restrições de algoritmo da Autoridade Certificadora
     */
    private AlgAndLength[] caCertAlgorithmConstraints;
    /**
     * Restrições de algoritmo da Autoridade de Atributo
     */
    private AlgAndLength[] aaCertAlgorithmConstraints;
    /**
     * Restrições de algoritmo da Autoridade de Carimbo do Tempo
     */
    private AlgAndLength[] tsaCertAlgorithmConstraints;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param algorithmConstraintSet codificação ASN1 do atributo
     *            {@link AlgorithmConstraintSet}.
     */
    public AlgorithmConstraintSet(ASN1Sequence algorithmConstraintSet) {

        this.signerAlgorithmConstraints = null;
        this.eeCertAlgorithmConstraints = null;
        this.caCertAlgorithmConstraints = null;
        this.aaCertAlgorithmConstraints = null;
        this.tsaCertAlgorithmConstraints = null;

        for (int i = 0; i < algorithmConstraintSet.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) algorithmConstraintSet.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    this.signerAlgorithmConstraints = this.readAlgConstraints((ASN1Sequence) taggetObj.getObject());
                    break;

                case 1:
                    this.eeCertAlgorithmConstraints = this.readAlgConstraints((ASN1Sequence) taggetObj.getObject());
                    break;

                case 2:
                    this.caCertAlgorithmConstraints = this.readAlgConstraints((ASN1Sequence) taggetObj.getObject());
                    break;

                case 3:
                    this.aaCertAlgorithmConstraints = this.readAlgConstraints((ASN1Sequence) taggetObj.getObject());
                    break;

                case 4:
                    this.tsaCertAlgorithmConstraints = this.readAlgConstraints((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param element elemento XML que representa o atributo
     *            {@link AlgorithmConstraintSet}.
     */
    public AlgorithmConstraintSet(Node element) {
        Node node;
        int elementSize = element.getChildNodes().getLength();
        for (int i = 0; i < elementSize; i++) {
            node = element.getChildNodes().item(i);
            if (node.getLocalName().equals("SignerAlgConstraints")) {
                this.signerAlgorithmConstraints = new AlgAndLength[node.getChildNodes().getLength()];
                for (int j = 0; j < node.getChildNodes().getLength(); j++) {
                    this.signerAlgorithmConstraints[j] = new AlgAndLength(node.getChildNodes().item(j));
                }
            }
            // TODO implementar os outros tipos (AlgorithmConstraintSet)
        }
    }

    /**
     * Retorna as restrições de algoritmo presentes na sequência ASN.1 dada
     * @param algConstraints A sequência ASN.1
     * @return As restrições de algoritmo
     */
    private AlgAndLength[] readAlgConstraints(ASN1Sequence algConstraints) {

        AlgAndLength[] algAndLength = null;

        if (algConstraints.size() > 0) {
            algAndLength = new AlgAndLength[algConstraints.size()];
            for (int i = 0; i < algAndLength.length; i++) {

                algAndLength[i] = new AlgAndLength((ASN1Sequence) algConstraints.getObjectAt(i));
            }
        }
        return algAndLength;
    }

    /**
     * Retorna as restrições de algoritmo do assinante
     * @return As restrições de algoritmo do assinante
     */
    public AlgAndLength[] getSignerAlgorithmConstraints() {
        return signerAlgorithmConstraints;
    }

    /**
     * Retorna o atributo <code>eeCertAlgorithmConstraints</code>
     * @return O valor atributo
     * @throws Exception Exceção pelo método não ser implementado
     */
    public AlgAndLength[] getEeCertAlgorithmConstraints() throws Exception {
        // TODO implementar getEeCertAlgorithmConstraints
        throw new Exception("Método não implementado");
    }

    /**
     * Retorna o atributo <code>caCertAlgorithmConstraints</code>
     * @return O valor atributo
     * @throws Exception Exceção pelo método não ser implementado
     */
    public AlgAndLength[] getCaCertAlgorithmConstraints() throws Exception {
        // TODO implementar getCaCertAlgorithmConstraints
        throw new Exception("Método não implementado");
    }

    /**
     * Retorna o atributo <code>aaCertAlgorithmConstraints</code>
     * @return O valor atributo
     * @throws Exception Exceção pelo método não ser implementado
     */
    public AlgAndLength[] getAaCertAlgorithmConstraints() throws Exception {
        // TODO implementar getAaCertAlgorithmConstraints
        throw new Exception("Método não implementado");
    }

    /**
     * Retorna o atributo <code>tsaCertAlgorithmConstraints</code>
     * @return O valor atributo
     * @throws Exception Exceção pelo método não ser implementado
     */
    public AlgAndLength[] getTsaCertAlgorithmConstraints() throws Exception {
        // TODO implementar getTsaCertAlgorithmConstraints
        throw new Exception("Método não implementado");
    }

    /**
     * Verifica as restrições de algoritmo do assinante.
     * @return Indica se as restrições de algoritmo do assinante
     *         existem.
     */
    public boolean hasSignerAlgorithmConstraints() {
        return signerAlgorithmConstraints != null;
    }

    /**
     * Verifica as restrições de algoritmo de emissores de certificados de
     * entidade final.
     * @return Indica se as restrições de algoritmo de emissores de
     *         certificados de entidade final existem.
     */
    public boolean hasEeCertAlgorithmConstraints() {
        return eeCertAlgorithmConstraints != null;
    }

    /**
     * Verifica as restrições de algoritmo da Autoridade Certificadora.
     * @return Indica se as restrições de algoritmo da Autoridade
     *         Certificadora existem.
     */
    public boolean hasCaCertAlgorithmConstraints() {
        return caCertAlgorithmConstraints != null;
    }

    /**
     * Verifica as restrições de algoritmo da Autoridade de Atributo.
     * @return Indica se as restrições de algoritmo da Autoridade de
     *         Atributo existem.
     */
    public boolean hasAaCertAlgorithmConstraints() {
        return aaCertAlgorithmConstraints != null;
    }

    /**
     * Verifica as restrições de algoritmo da Autoridade de Carimbo do Tempo.
     * @return Indica se as restrições de algoritmo da Autoridade de
     *         Carimbo do Tempo existem.
     */
    public boolean hasTsaCertAlgorithmConstraints() {
        return tsaCertAlgorithmConstraints != null;
    }

}
