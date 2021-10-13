/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.x509.GeneralSubtree;

/**
 * NameConstraints ::= SEQUENCE {
 permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
 excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
 */
/**
 * Este atributo especifica o espaço de nome dentro do qual todos os nomes de
 * signatário dos certificados do caminho de certificação devem ser alocados.
 */
public class NameConstraints {

    /**
     * O atributo 'permittedSubtrees' em ASN.1
     */
    private GeneralSubtree[] permittedSubtrees;
    /**
     * O atributo 'excludedSubtrees' em ASN.1
     */
    private GeneralSubtree[] excludedSubtrees;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param nameConstraints A codificação ASN1 do atributo
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
     * Lê uma subtree em ASN.1 e tranforma em um objeto {@link GeneralSubtree[]}
     * @param subtrees O atributo codificado em ASN.1
     * @return
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

}
