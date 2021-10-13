/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.GeneralSubtree;
import org.w3c.dom.Node;

///**
// * NameConstraints ::= SEQUENCE {
// permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
// excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
// */
///**
// <xsd:complexType name="NameConstraintsType">
// <xsd:sequence>
// <xsd:element name="PermittedSubtrees"
// type="GeneralSubTreesListType" minOccurs="0"/>
// <xsd:element name="ExcludedSubtrees"
// type="GeneralSubTreesListType" minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
// */

/**
 * Este atributo especifica o espaço de nome dentro do qual todos os nomes de
 * signatário dos certificados do caminho de certificação devem ser alocados.
 */
public class NameConstraints {

    /**
     * Espaços permitidos
     */
    private GeneralSubtree[] permittedSubtrees;
    /**
     * Espaços desconsiderados
     */
    private GeneralSubtree[] excludedSubtrees;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param nameConstraints codificação ASN1 do atributo
     *            {@link NameConstraints}.
     */
    public NameConstraints(ASN1Sequence nameConstraints) {

        this.permittedSubtrees = null;
        this.excludedSubtrees = null;

        for (int i = 1; i < nameConstraints.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) nameConstraints.getObjectAt(i);

            switch (taggetObj.getTagNo()) {
                case 0:
                    this.permittedSubtrees = readGeneralSubtrees((ASN1Sequence) taggetObj.getObject());
                    break;

                case 1:
                    this.excludedSubtrees = readGeneralSubtrees((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param node elemento XML que representa o atributo
     *            {@link NameConstraints}.
     */
    public NameConstraints(Node node) {
        for (int i = 0; i < node.getChildNodes().getLength(); i++) {
            if (node.getChildNodes().item(i).getLocalName().equals("PermittedSubtrees")) {
                // this.permittedSubtrees =
            } else if (node.getChildNodes().item(i).getLocalName().equals("ExcludedSubtrees")) {

            }
        }
    }

    /**
     * Cria o array de espaços a partir da sequência ASN.1 dada
     * @param subtrees A sequência ASN.1
     * @return O array de espaços
     */
    private GeneralSubtree[] readGeneralSubtrees(ASN1Sequence subtrees) {

        GeneralSubtree[] generalSubtrees = null;
        if (subtrees.size() > 0) {
            generalSubtrees = new GeneralSubtree[subtrees.size()];
            for (int i = 0; i < generalSubtrees.length; i++) {
                generalSubtrees[i] = GeneralSubtree.getInstance((ASN1Sequence) subtrees.getObjectAt(i));
            }
        }
        return generalSubtrees;
    }

    /**
     * Retorna os espaços permitidos
     * @return Os espaços permitidos
     */
    public GeneralSubtree[] getPermittedSubtrees() {
        return permittedSubtrees;
    }

    /**
     * Retorna os espaços desconsiderados
     * @return Os espaços desconsiderados
     */
    public GeneralSubtree[] getExcludedSubtrees() {
        return excludedSubtrees;
    }

    /**
     * Verifica se existe o atributo <code>PermittedSubtrees</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasPermittedSubtrees() {
        return this.permittedSubtrees != null;
    }

    /**
     * Verifica se existe o atributo <code>ExcludedSubtrees</code>.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasExcludedSubtrees() {
        return this.excludedSubtrees != null;
    }

}
