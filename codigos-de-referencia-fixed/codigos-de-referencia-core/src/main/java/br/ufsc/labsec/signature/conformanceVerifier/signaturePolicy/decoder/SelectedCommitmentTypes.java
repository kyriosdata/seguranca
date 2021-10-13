/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERNull;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

///**
// * SelectedCommitmentTypes ::= SEQUENCE OF CHOICE {
// * empty NULL,
// * recognizedCommitmentType CommitmentType }
// */
///**
// * <xsd:complexType name="SelectedCommitmentTypeListType">
// * <xsd:sequence maxOccurs="unbounded">
// * <xsd:element name="SelCommitmentType" type="SelectedCommitmentType"/>
// * </xsd:sequence>
// * </xsd:complexType>
// */
/**
 * Este atributo é usado para indicar o compromisso assumido por um determinado
 * agente no âmbito da Política de Assinatura sendo especificada.
 */
public class SelectedCommitmentTypes {

    /**
     * O compromisso
     */
    private CommitmentType[] recognizedCommitmentType;
    /**
     * O valor do atributo empty
     */
    private boolean empty;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param selectedCommitmentTypes codificação ASN1 do atributo
     *            {@link SelectedCommitmentTypes}.
     */
    // FIXME verificar se o sequence vai ter mais de 1 CommitmentType
    public SelectedCommitmentTypes(ASN1Sequence selectedCommitmentTypes) {
        this.recognizedCommitmentType = null;
        this.empty = false;
        if (!(selectedCommitmentTypes.getObjectAt(0) instanceof DERNull)) {
            this.recognizedCommitmentType = readASN1Commitment((ASN1Sequence) selectedCommitmentTypes.getObjectAt(0));
        } else {
            this.empty = true;
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param selectedCommitmentTypes elemento XML que representa o atributo
     *            {@link SelectedCommitmentTypes}.
     */
    public SelectedCommitmentTypes(Node selectedCommitmentTypes) {
        this.recognizedCommitmentType = null;
        this.empty = false;
        Element element = (Element) selectedCommitmentTypes.getChildNodes().item(0).getFirstChild();
        if (element.getTagName().equals("pa:Empty")) {
            this.empty = true;
        } else {
            this.empty = false;
            this.recognizedCommitmentType = readXMLCommitment(selectedCommitmentTypes.getChildNodes().item(0));
        }
    }

    /**
     * Decodifica o atributo codificado em ASN.1
     * @param commitments O atributo em ASN.1
     * @return O compromisso na política
     */
    private CommitmentType[] readASN1Commitment(ASN1Sequence commitments) {
        List<CommitmentType> commitmentTypeList = new ArrayList<CommitmentType>();
        for (int i = 0; i < commitments.size(); i++) {
            if (!(commitments.getObjectAt(i) instanceof DERNull)) {
                commitmentTypeList.add(new CommitmentType((ASN1Sequence) commitments.getObjectAt(i)));
            }
        }
        return commitmentTypeList.toArray(new CommitmentType[0]);
    }

    /**
     * Decodifica o atributo codificado em XML
     * @param commitments O atributo em XML
     * @return O compromisso na política
     */
    private CommitmentType[] readXMLCommitment(Node commitments) {
        CommitmentType[] commitmentType = new CommitmentType[commitments.getChildNodes().getLength()];
        for (int i = 0; i < commitments.getChildNodes().getLength(); i++) {
            commitmentType[i] = new CommitmentType(commitments.getChildNodes().item(i));
        }
        return commitmentType;
    }

    /**
     * Retorna o atributo RecognizedCommitmentType.
     * @return O valor do compromisso
     */
    public CommitmentType[] getRecognizedCommitmentType() {
        return this.recognizedCommitmentType;
    }

    /**
     * Verifica se existe o atributo RecognizedCommitmentType.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasRecognizedCommitmentType() {
        return this.recognizedCommitmentType != null;
    }

    /**
     * Verifica se o atributo <code>Empty</code> é <code>true</code>.
     * @return O valor <code>boolean</code> do atributo <code>Empty</code>.
     */
    public boolean isEmpty() {
        return empty;
    }
}
