/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyExtension;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

///**
// * CommitmentRule ::= SEQUENCE {
// selCommitmentTypes                  SelectedCommitmentTypes,
// signerAndVeriferRules          [0]  SignerAndVerifierRules    OPTIONAL,
// signingCertTrustCondition      [1]  SigningCertTrustCondition OPTIONAL,
// timeStampTrustCondition        [2]  TimestampTrustCondition   OPTIONAL,
// attributeTrustCondition        [3]  AttributeTrustCondition   OPTIONAL,
// algorithmConstraintSet         [4]  AlgorithmConstraintSet    OPTIONAL,
// signPolExtensions              [5]  SignPolExtensions         OPTIONAL
// }
// */
///**
// * <xsd:complexType name="CommitmentRuleType">
// <xsd:sequence>
// <xsd:element name="SelCommitmentTypes" type="SelectedCommitmentTypeListType"/>
// <xsd:element name="SignerAndVerifierRules" type="SignerAndVerifierRulesType" minOccurs="0"/>
// <xsd:element name="SigningCertTrustCondition" type="SigningCertTrustConditionType" minOccurs="0"/>
// <xsd:element name="TimeStampTrustCondition" type="TimeStampTrustConditionType" minOccurs="0"/>
// <xsd:element name="RoleTrustCondition" type="RoleTrustConditionType" minOccurs="0"/>
// <xsd:element name="AlgorithmConstraintSet" type="AlgorithmConstraintSetType" minOccurs="0"/>
// <xsd:element name="SignPolExtensions" type="SignPolExtensionsListType" minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
// */

/**
 * Este atributo representa as condições de confiança para certficados, carimbo
 * de tempo e atributos, juntamente com quaisquer restrições em atributos que
 * possam ser incluídas na assinatura.
 */
public class CommitmentRule {

    /**
     * Compromissos assumidos
     */
    private SelectedCommitmentTypes selCommitmentTypes;
    /**
     * Regras do assinante e verificador
     */
    private SignerAndVerifierRules signerAndVeriferRules;
    /**
     * Regras de condições de confiança do certificado do assinante
     */
    private SigningCertTrustCondition signingCertTrustCondition;
    /**
     * Regras de condições de confiança de carimbos de tempo
     */
    private TimeStampTrustCondition timeStampTrustCondition;
    /**
     * Regras de condições de confiança de atributos
     */
    private AttributeTrustCondition attributeTrustCondition;
    /**
     * Regras de algoritmos
     */
    private AlgorithmConstraintSet algorithmConstraintSet;
    /**
     * Regra adicional da política
     */
    private SignaturePolicyExtension signPolExtensions;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param commitmentRules codificação ASN1 do atributo
     *            {@link CommitmentRule}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public CommitmentRule(ASN1Sequence commitmentRules) throws CertificateException, IOException, NoSuchAlgorithmException {

        this.selCommitmentTypes = new SelectedCommitmentTypes((ASN1Sequence) commitmentRules.getObjectAt(0));
        this.signerAndVeriferRules = null;
        this.signingCertTrustCondition = null;
        this.timeStampTrustCondition = null;
        this.attributeTrustCondition = null;
        this.algorithmConstraintSet = null;
        this.signPolExtensions = null;

        for (int i = 1; i < commitmentRules.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) commitmentRules.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    this.signerAndVeriferRules = new SignerAndVerifierRules((ASN1Sequence) taggetObj.getObject());
                    break;

                case 1:
                    this.signingCertTrustCondition = new SigningCertTrustCondition((ASN1Sequence) taggetObj.getObject());
                    break;

                case 2:
                    this.timeStampTrustCondition = new TimeStampTrustCondition((ASN1Sequence) taggetObj.getObject());
                    break;

                case 3:
                    this.attributeTrustCondition = new AttributeTrustCondition((ASN1Sequence) taggetObj.getObject());
                    break;

                case 4:
                    this.algorithmConstraintSet = new AlgorithmConstraintSet((ASN1Sequence) taggetObj.getObject());
                    break;

                case 5:
                    this.signPolExtensions = new SignaturePolicyExtension((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML
     * @param commitmentRules elemento XML que representa o atributo
     *            {@link CommitmentRule}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws DOMException Exceção em caso de erro no elemento XML
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public CommitmentRule(Node commitmentRules) throws CertificateException, IOException, DOMException, NoSuchAlgorithmException {

        this.selCommitmentTypes = new SelectedCommitmentTypes(commitmentRules.getChildNodes().item(0));
        this.signerAndVeriferRules = null;
        this.signingCertTrustCondition = null;
        this.timeStampTrustCondition = null;
        this.attributeTrustCondition = null;
        this.algorithmConstraintSet = null;
        this.signPolExtensions = null;

        NodeList node = commitmentRules.getChildNodes();
        for (int i = 1; i < node.getLength(); i++) {
            Element element = (Element) node.item(i);
            String tagName = element.getTagName();

            switch (tagName) {
                case "pa:SignerAndVerifierRules":
                    this.signerAndVeriferRules = new SignerAndVerifierRules(element);
                    break;
                case "pa:SigningCertTrustCondition":
                    this.signingCertTrustCondition = new SigningCertTrustCondition(element);
                    break;
                case "pa:TimeStampTrustCondition":
                    this.timeStampTrustCondition = new TimeStampTrustCondition(element);
                    break;
                case "pa:RoleTrustCondition":
                    this.attributeTrustCondition = new AttributeTrustCondition(element);
                    break;
                case "pa:AlgorithmConstraintSet":
                    this.algorithmConstraintSet = new AlgorithmConstraintSet(element);
                    break;
                case "pa:SignPolExtensions":
                    this.signPolExtensions = new SignaturePolicyExtension(element);
                    break;
            }
        }
    }

    /**
     * Retorna o atributo <code>SelCommitmentTypes</code>.
     * @return O valor do atributo
     */
    public SelectedCommitmentTypes getSelCommitmentTypes() {
        return selCommitmentTypes;
    }

    /**
     * Retorna o atributo <code>SigningCertTrustCondition</code>.
     * @return O valor do atributo
     */
    public SigningCertTrustCondition getSigningCertTrustCondition() {
        return signingCertTrustCondition;
    }

    /**
     * Retorna o atributo <code>SignerAndVerifierRules</code>.
     * @return O valor do atributo
     */
    public SignerAndVerifierRules getSignerAndVerifierRules() {
        return signerAndVeriferRules;
    }

    /**
     * Retorna o atributo <code>TimeStampTrustCondition</code>.
     * @return O valor do atributo
     */
    public TimeStampTrustCondition getTimeStampTrustCondition() {
        return timeStampTrustCondition;
    }

    /**
     * Retorna o atributo <code>AttributeTrustCondition</code>.
     * @return O valor do atributo
     */
    public AttributeTrustCondition getAttributeTrustCondition() {
        return attributeTrustCondition;
    }

    /**
     * Retorna o atributo <code>AlgorithmConstraintSet</code>.
     * @return O valor do atributo
     */
    public AlgorithmConstraintSet getAlgorithmConstraintSet() {
        return algorithmConstraintSet;
    }

    /**
     * Retorna o atributo <code>SignPolExtensions</code>.
     * @return O valor do atributo
     */
    public SignaturePolicyExtension getSignPolExtensions() {
        return signPolExtensions;
    }

    /**
     * Verifica se o atributo <code>SigningCertTrustCondition</code> existe.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasSigningCertTrustCondition() {
        return this.signingCertTrustCondition != null;
    }

    /**
     * Verifica se o atributo <code>SignerAndVerifierRules</code> existe.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasSignerAndVerifierRules() {
        return this.signerAndVeriferRules != null;
    }

    /**
     * Verifica se o atributo <code>TimeStampTrustCondition</code> existe.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasTimeStampTrustCondition() {
        return this.timeStampTrustCondition != null;
    }

    /**
     * Verifica se o atributo <code>AttributeTrustCondition</code> existe.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasAttributeTrustCondition() {
        return this.attributeTrustCondition != null;
    }

    /**
     * Verifica se o atributo <code>AlgorithmConstraintSet</code> existe.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasAlgorithmConstraintSet() {
        return this.algorithmConstraintSet != null;
    }

    /**
     * Verifica se o atributo <code>SignaturePolicyExtension</code> existe.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasSignaturePolicyExtension() {
        return this.signPolExtensions != null;
    }
}
