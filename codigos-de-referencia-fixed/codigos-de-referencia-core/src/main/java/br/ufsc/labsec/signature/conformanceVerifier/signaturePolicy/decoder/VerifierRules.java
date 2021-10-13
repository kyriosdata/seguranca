/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyExtension;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.w3c.dom.Node;

import java.util.Arrays;
import java.util.Iterator;

///**
// * VerifierRules ::= SEQUENCE {
// mandatedUnsignedAttr    MandatedUnsignedAttr,
// signPolExtensions       SignPolExtensions       OPTIONAL
// }
// */
///**
// <xsd:element name="VerifierRules"
// type="VerifierRulesType"/>
// <xsd:complexType name="VerifierRulesType">
// <xsd:sequence>
// <xsd:element name="MandatedQUnsignedProperties"
// type="QPropertiesListType"/>
// <xsd:element name="SignPolicyExtensions"
// type="SignPolExtensionsListType" minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
//
// */
/**
 * Este atributo identifica os atributos não assinados que devem estar presentes
 * nesta Política de Assinatura e que devem ser adicionados pelo verificador,
 * caso não tenha sido adicionado pelo signatário.
 */
public class VerifierRules {

    /**
     * Array de atributos obrigatórios não-assinados
     */
    private String[] mandatedUnsignedAttr;
    /**
     * Regras adicionais da política
     */
    private SignaturePolicyExtension[] signPolExtensions;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param verifierRules codificação ASN1 do atributo {@link VerifierRules}.
     */
    public VerifierRules(ASN1Sequence verifierRules) {

        this.signPolExtensions = null;
        this.mandatedUnsignedAttr = this.readObjectIdentifiers((ASN1Sequence) verifierRules.getObjectAt(0));

        if (verifierRules.size() == 2) {
            this.signPolExtensions = this.readExtensions((ASN1Sequence) verifierRules.getObjectAt(1));
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param item elemento XML que representa o atributo
     *            {@link SignerAndVerifierRules}.
     */
    public VerifierRules(Node item) {
        Node node = (Node) item.getFirstChild().getChildNodes();
        int elementSize = node.getChildNodes().getLength();
        this.mandatedUnsignedAttr = new String[elementSize];
        for (int i = 0; i < elementSize; i++) {
            this.mandatedUnsignedAttr[i] = node.getChildNodes().item(i).getTextContent();
        }
    }

    /**
     * Retorna a lista de identificadores dos objetos presentes na sequência ASN.1 dada
     * @param seq A sequência ASN.1
     * @return A lista de identificadores
     */
    private String[] readObjectIdentifiers(ASN1Sequence seq) {
        String[] ret = new String[seq.size()];

        for (int i = 0; i < seq.size(); i++) {
            ret[i] = ((ASN1ObjectIdentifier) seq.getObjectAt(i)).toString();
        }
        return ret;
    }

    /**
     * Retorna as regras adicionais da política presentes na sequência ASN.1
     * @param extensions A sequência ASN.1
     * @return As regras adicionais da política
     */
    private SignaturePolicyExtension[] readExtensions(ASN1Sequence extensions) {
        SignaturePolicyExtension[] ret = null;

        if (extensions.size() > 0) {
            ret = new SignaturePolicyExtension[extensions.size()];
            for (int i = 0; i < extensions.size(); i++) {
                ret[i] = new SignaturePolicyExtension((ASN1Sequence) extensions.getObjectAt(i));
            }
        }
        return ret;
    }

    /**
     * Retorna a extensão de assinatura brExtMandatedPdfSigDicEntries
     * @return A extensão
     */
    public BrExtDss getBrExtDss(){

        Iterator<SignaturePolicyExtension> it = Arrays.asList(this.getSignPolExtensions()).iterator();
        BrExtDss brExtDss = null;

        while(it.hasNext() && brExtDss == null){
            SignaturePolicyExtension extension = it.next();

            if(extension.getExtnID().equals(BrExtDss.IDENTIFIER)){
                brExtDss = new BrExtDss(extension.getExtnValue());
            }
        }
        return brExtDss;
    }

    /**
     * Retorna os atributos obrigatórios não assinados.
     * @return Array de atributos obrigatórios não-assinados
     */
    public String[] getMandatedUnsignedAttr() {
        return mandatedUnsignedAttr;
    }

    /**
     * Retorna as regras adicionais da Política de Assinatura.
     * @return As regras adicionais da política
     */
    public SignaturePolicyExtension[] getSignPolExtensions() {
        if (this.signPolExtensions == null) {
            return new SignaturePolicyExtension[0];
        }
        return this.signPolExtensions;
    }

    /**
     * Verifica se existem regras adicionais da Política de Assinatura.
     * @return Indica se o atributo <code>SignPolExtensions</code>
     *         não é nulo.
     */
    public boolean hasSignPolExtensions() {
        return this.signPolExtensions != null;
    }

    public BrExtMandatedDocTSEntries getBrExtMandatedDocTSEntries() {
        Iterator<SignaturePolicyExtension> it = Arrays.asList(this.getSignPolExtensions()).iterator();
        BrExtMandatedDocTSEntries brExtMandatedDocTSEntries = null;

        while(it.hasNext() || brExtMandatedDocTSEntries == null){
            SignaturePolicyExtension extension = it.next();

            if(extension.getExtnID().equals(BrExtMandatedDocTSEntries.IDENTIFIER)){
                brExtMandatedDocTSEntries = new BrExtMandatedDocTSEntries(extension.getExtnValue());
            }
        }
        return brExtMandatedDocTSEntries;
    }

}
