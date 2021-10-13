/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.ParseException;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyExtension;
import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

///**
// * SignatureValidationPolicy ::= SEQUENCE {
// * signingPeriod SigningPeriod,
// * commonRules CommonRules,
// * commitmentRules CommitmentRules,
// * signPolExtensions SignPolExtensions OPTIONAL }
// **/
///**
// * <xsd:complexType name="SignatureValidationPolicyType">
// * <xsd:sequence>
// * <xsd:element name="SigningPeriod" type="TimePeriodType"/>
// * <xsd:element name="CommonRules" type="CommonRulesType"/>
// * <xsd:element name="CommitmentRules" type="CommitmentRulesListType"/>
// * <xsd:element name="SignPolicyExtensions" type="SignPolExtensionsListType" minOccurs="0"/>
// * </xsd:sequence>
// */
/**
 * Este atributo define algumas regras que devem ser usadas pelo assinante
 * quando produzir a assinatura, e pelo verificador, quando verificar a
 * assinatura.
 */
public class SignatureValidationPolicy {

    /**
     * Período de validade da política
     */
    private SigningPeriod signingPeriod;
    /**
     * Regras comuns para todos os compromissos
     */
    private CommonRules commonRules;
    /**
     * Regras de condições de confiança
     */
    private CommitmentRule[] commitmentRules;
    /**
     * Regras adicionais da política
     */
    private SignaturePolicyExtension[] signPolExtensionsASN1;
    /**
     * Nodo XML com as regras adicionais da política
     */
    private NodeList signPolExtensionsXML;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param signatureValidationPolicy codificação ASN1 do atributo
     *            {@link SignatureValidationPolicy}.
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SignatureValidationPolicy(ASN1Sequence signatureValidationPolicy) throws ParseException, CertificateException, IOException,
            NoSuchAlgorithmException {
        this.signingPeriod = new SigningPeriod((ASN1Sequence) signatureValidationPolicy.getObjectAt(0));
        this.commonRules = new CommonRules((ASN1Sequence) signatureValidationPolicy.getObjectAt(1));
        this.commitmentRules = readASN1CommitmentRules((ASN1Sequence) signatureValidationPolicy.getObjectAt(2));
        this.signPolExtensionsASN1 = null;
        if (signatureValidationPolicy.size() == 4) {
            this.signPolExtensionsASN1 = this.readExtensions((ASN1Sequence) signatureValidationPolicy.getObjectAt(3));
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param signatureValidationPolicy elemento XML que representa o atributo
     *            {@link SignatureValidationPolicy}.
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws DOMException Exceção em caso de erro no elemento XML
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SignatureValidationPolicy(Node signatureValidationPolicy) throws ParseException, CertificateException, IOException,
            DOMException, NoSuchAlgorithmException {
        this.signingPeriod = new SigningPeriod(signatureValidationPolicy.getChildNodes().item(0));
        this.commonRules = new CommonRules(signatureValidationPolicy.getChildNodes().item(1));
        this.commitmentRules = readXMLCommitmentRules(signatureValidationPolicy.getChildNodes().item(2));
        this.signPolExtensionsXML = null;
        if (signatureValidationPolicy.getChildNodes().getLength() > 3) {
            this.signPolExtensionsXML = signatureValidationPolicy.getChildNodes().item(3).getChildNodes();
        }
    }

    /**
     * Retorna as condições de confiança da política presentes no nodo XML
     * @param rules O nodo XML
     * @return As condições de confiança
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws DOMException Exceção em caso de erro no elemento XML
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    private CommitmentRule[] readXMLCommitmentRules(Node rules) throws CertificateException, IOException, DOMException,
        NoSuchAlgorithmException {
        int extensionsSize = rules.getChildNodes().getLength();
        CommitmentRule[] ret = new CommitmentRule[extensionsSize];
        for (int i = 0; i < extensionsSize; i++) {
            ret[i] = new CommitmentRule(rules.getChildNodes().item(i));
        }
        return ret;
    }

    /**
     * Retorna as condições de confiança da política presentes na sequência ASN.1
     * @param rules A sequência ASN.1
     * @return As condições de confiança
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    private CommitmentRule[] readASN1CommitmentRules(ASN1Sequence rules) throws CertificateException, IOException, NoSuchAlgorithmException {
        CommitmentRule[] commitmentRules = new CommitmentRule[rules.size()];
        for (int i = 0; i < rules.size(); i++) {
            ASN1EncodableVector commitmentRuleVector = new ASN1EncodableVector();
            commitmentRuleVector.add(rules.getObjectAt(i));
            commitmentRules[i] = new CommitmentRule(new DERSequence(commitmentRuleVector));
        }
        return commitmentRules;
    }

    /**
     * Retorna as regras adicionais da política presentes na sequência ASN.1
     * @param extensions A sequência ASN.1
     * @return As regras adicionais da política
     */
    // TODO testar
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
     * Retorna o atributo <code>SigningPeriod</code>.
     * @return O valor do atributo
     */
    public SigningPeriod getSigningPeriod() {
        return this.signingPeriod;
    }

    /**
     * Retorna o atributo <code>CommonRules</code>.
     * @return O valor do atributo
     */
    public CommonRules getCommonRules() {
        return this.commonRules;
    }

    /**
     * Retorna o atributo <code>CommitmentRules</code>.
     * @return O valor do atributo
     */
    public CommitmentRule[] getCommitmentRules() {
        return this.commitmentRules;
    }

    /**
     * Retorna o atributo <code>SignPolExtensions</code>.
     * @return O valor do atributo
     */
    public SignaturePolicyExtension[] getSignPolExtensions() {
        return this.signPolExtensionsASN1;
    }

    /**
     * Verifica se existe o atributo <code>SignPolExtension</code> no ASN1.
     * @return Indica se o atributo não é nulo.
     */
    public boolean hasSignPolExtension() {
        return this.signPolExtensionsASN1 != null;
    }

    /**
     * Verifica se existe o atributo <code>SignPolExtension</code> no XML.
     * @return Indica se o atributo não é nulo.
     */
    public NodeList getSignPolExtensionsXML() {
        return signPolExtensionsXML;
    }
}
