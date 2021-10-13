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
// * CommonRules ::= SEQUENCE {
// signerAndVeriferRules 		[0] SignerAndVerifierRules OPTIONAL,
// signingCertTrustCondition	[1] SigningCertTrustCondition OPTIONAL,
// timeStampTrustCondition 	[2] TimestampTrustCondition OPTIONAL,
// attributeTrustCondition 	[3] AttributeTrustCondition OPTIONAL,
// algorithmConstraintSet 		[4] AlgorithmConstraintSet OPTIONAL,
// signPolExtensions 			[5] SignPolExtensions OPTIONAL }
// *
// * **/
///**
// * <xsd:complexType name="CommonRulesType">
// <xsd:sequence>
// <xsd:element name="SignerAndVerifierRules" type="SignerAndVerifierRulesType" minOccurs="0"/>
// <xsd:element name="SigningCertTrustCondition" type="SigningCertTrustConditionType" minOccurs="0"/>
// <xsd:element name="TimeStampTrustCondition" type="TimeStampTrustConditionType" minOccurs="0"/>
// <xsd:element name="RoleTrustCondition" type="RoleTrustConditionType" minOccurs="0"/>
// <xsd:element name="AlgorithmConstraintSet" type="AlgorithmConstraintSetType" minOccurs="0"/>
// <xsd:element name="SIgnPolExtensions" type="SignPolExtensionsListType" minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
// */
/**
 * Esta classe define as regras que são comuns para todos os tipos de
 * compromissos.
 */
public class CommonRules {

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
     * Regras adicionais da política
     */
    private SignaturePolicyExtension[] signPolExtensions;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param commonRules codificação ASN1 do atributo {@link CommonRules}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public CommonRules(ASN1Sequence commonRules) throws CertificateException, IOException, NoSuchAlgorithmException {
        this.signerAndVeriferRules = null;
        this.signingCertTrustCondition = null;
        this.timeStampTrustCondition = null;
        this.attributeTrustCondition = null;
        this.algorithmConstraintSet = null;
        this.signPolExtensions = null;

        for (int i = 0; i < commonRules.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) commonRules.getObjectAt(i);
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
                    this.signPolExtensions = this.readASN1Extensions((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param commonRules elemento XML que representa o atributo
     *            {@link CommonRules}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws DOMException Exceção em caso de erro no elemento XML
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public CommonRules(Node commonRules) throws CertificateException, IOException, DOMException, NoSuchAlgorithmException {
        this.signerAndVeriferRules = null;
        this.signingCertTrustCondition = null;
        this.timeStampTrustCondition = null;
        this.attributeTrustCondition = null;
        this.algorithmConstraintSet = null;
        this.signPolExtensions = null;

        NodeList node = commonRules.getChildNodes();
        for (int i = 0; i < node.getLength(); i++) {
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
                    this.signPolExtensions = readXMLExtensions(element);
                    break;
            }
        }
    }

    /**
     * Retorna as regras adicionais da política presentes na sequência ASN.1
     * @param extensions A sequência ASN.1
     * @return As regras adicionais da política
     */
    // TODO testar
    private SignaturePolicyExtension[] readASN1Extensions(ASN1Sequence extensions) {
        SignaturePolicyExtension[] ret = null;
        int extensionsSize = extensions.size();

        if (extensionsSize > 0) {
            ret = new SignaturePolicyExtension[extensionsSize];
            for (int i = 0; i < extensionsSize; i++) {
                ret[i] = new SignaturePolicyExtension((ASN1Sequence) extensions.getObjectAt(i));
            }
        }
        return ret;
    }

    /**
     * Retorna as regras adicionais da política presentes no nodo XML
     * @param extensions O nodo XML
     * @return As regras adicionais da política
     */
    private SignaturePolicyExtension[] readXMLExtensions(Node extensions) {
        SignaturePolicyExtension[] ret = null;
        int extensionsSize = extensions.getChildNodes().getLength();

        if (extensionsSize > 0) {
            ret = new SignaturePolicyExtension[extensionsSize];
            for (int i = 0; i < extensionsSize; i++) {
                ret[i] = new SignaturePolicyExtension(extensions.getChildNodes().item(i));
            }
        }
        return ret;
    }

    /**
     * Retorna as regras do assinante e do verificador
     * @return As regras do assinante e do verificador
     */
    public SignerAndVerifierRules getSignerAndVeriferRules() {
        return this.signerAndVeriferRules;
    }

    /**
     * Retorna as condições de confiança para o certificado
     * @return As condições de confiança para o certificado
     */
    public SigningCertTrustCondition getSigningCertTrustCondition() {
        return this.signingCertTrustCondition;
    }

    /**
     * Retorna as condições de confiança para o carimbo do tempo
     * @return As condições de confiança para o carimbo do tempo
     */
    public TimeStampTrustCondition getTimeStampTrustCondition() {
        return this.timeStampTrustCondition;
    }

    /**
     * Retorna as condições de confiança para os papéis (roles).
     * @return As condições de confiança para os papéis
     */
    public AttributeTrustCondition getAttributeTrustCondition() {
        return this.attributeTrustCondition;
    }

    /**
     * Retorna as restrições dos algoritmos
     * @return As restrições dos algoritmos
     */
    public AlgorithmConstraintSet getAlgorithmConstraintSet() {
        return this.algorithmConstraintSet;
    }

    /**
     * Retorna o conjunto de regras adicionais da Política de Assinatura.
     * @return Conjunto de regras adicionais da política
     */
    public SignaturePolicyExtension[] getSignPolExtensions() {
        return this.signPolExtensions;
    }

    /**
     * Verifica se existem as regras do assinante e do verificador.
     * @return Indica se o atributo
     *         <code>SignerAndVerifierRules</code> não é nulo.
     */
    public boolean hasSignerAndVerifierRules() {
        return this.signerAndVeriferRules != null;
    }

    /**
     * Verifica se existem as condições de confiança para o certificado.
     * @return Indica se o atributo
     *         <code>SigningCertTrustCondition</code> não é nulo.
     */
    public boolean hasSigningCertTrustCondition() {
        return this.signingCertTrustCondition != null;
    }

    /**
     * Verifica se existem as condições de confiança para o carimbo do tempo.
     * @return Indica se o atributo
     *         <code>TimeStampTrustCondition</code> não é nulo.
     */
    public boolean hasTimeStampTrustCondition() {
        return this.timeStampTrustCondition != null;
    }

    /**
     * Verifica se existem as condições de confiança para os papéis (roles).
     * @return Indica se o atributo
     *         <code>AttributeTrustCondition</code> não é nulo.
     */
    public boolean hasAttributeTrustCondition() {
        return this.attributeTrustCondition != null;
    }

    /**
     * Verifica se existem as restrições dos algoritmos.
     * @return Indica se o atributo
     *         <code>AlgorithmConstraintSet</code> não é nulo.
     */
    public boolean hasAlgorithmConstraintSet() {
        return this.algorithmConstraintSet != null;
    }

    /**
     * Verifica se existe o conjunto de regras adicionais da Política de
     * Assinatura.
     * @return Indica se o atributo
     *         <code>SignaturePolicyExtensions</code> não é nulo.
     */
    public boolean hasSignaturePolicyExtensions() {
        return this.signPolExtensions != null;
    }
}
