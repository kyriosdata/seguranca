/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.sql.Time;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyExtension;
import org.bouncycastle.asn1.ASN1GeneralizedTime;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

///**
// * SignPolicyInfo ::= SEQUENCE {
// * signPolicyIdentifier SignPolicyId,
// * dateOfIssue GeneralizedTime,
// * policyIssuerName PolicyIssuerName,
// * fieldOfApplication FieldOfApplication,
// * signatureValidationPolicy SignatureValidationPolicy,
// * signPolExtensions SignPolExtensions OPTIONAL }
// * */
///**
// * <xsd:complexType name="SignaturePolicyInfoType">
// * <xsd:sequence>
// * <xsd:element name="SignPolicyIdentifier" type="XAdES:ObjectIdentifierType"/>
// * <xsd:element name="DateOfIssue" type="xsd:dateTime"/>
// * <xsd:element name="PolicyIssuerName" type="xsd:string"/>
// * <xsd:element name="FieldOfApplication" type="xsd:string"/>
// * <xsd:element name="SignatureValidationPolicy" type="SignatureValidationPolicyType"/>
// * <xsd:element name="SignPolExtensions" type="SignPolExtensionsListType" minOccurs="0"/>
// * </xsd:sequence>
// * </xsd:complexType>
// */
/**
 * Este atributo contém informações da Política de Assinatura, como: O ID da PA;
 * a data de emissão da PA; o nome do responsável por emitir a PA; o contexto de
 * onde a PA vai ser utilizada e o propósito de aplicação na assinatura; algumas
 * regras que devem ser seguidas pelo assinante, quando produzir a assinatura e
 * o verificador, quando verificar a assinatura; e extensões em aberto.
 */
public class SignaturePolicyInfo {

    /**
     * Indentificador da política
     */
    private String signPolicyIdentifier;
    // private ASN1GeneralizedTime dateOfIssue;
    /**
     * Data de emissão da política
     */
    private Time dateOfIssue;
    // private GeneralNames policyIssuerName;
    /**
     * Emissor da política
     */
    private String policyIssuerName;
    // private DirectoryString fieldOfApplication;
    /**
     * Descrição da aplicação da política
     */
    private String fieldOfApplication;
    /**
     * Regras de validação de assinatura
     */
    private SignatureValidationPolicy signatureValidationPolicy;
    /**
     * Regras adicionais da política
     */
    private SignaturePolicyExtension[] signPolExtensionsASN1;
    /**
     * Nodo XML que contém as regras adicionais da política
     */
    private NodeList signPolExtensionsXML;
    /**
     * Objeto ASN.1 que contém informações da política
     */
    private ASN1Sequence signPolicyInfoAsn1Object;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param signaturePolicyInfo codificação ASN1 do atributo
     *            {@link SignaturePolicyInfo}.
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SignaturePolicyInfo(ASN1Sequence signaturePolicyInfo) throws ParseException, CertificateException, IOException,
            NoSuchAlgorithmException {
        this.signPolicyInfoAsn1Object = signaturePolicyInfo;
        this.signPolicyIdentifier = ((ASN1ObjectIdentifier) signaturePolicyInfo.getObjectAt(0)).toString();
        this.dateOfIssue = new Time(((ASN1GeneralizedTime) signaturePolicyInfo.getObjectAt(1)).getDate().getTime());
        GeneralNames names = GeneralNames.getInstance((ASN1Sequence) signaturePolicyInfo.getObjectAt(2));
        this.policyIssuerName = this.getPolicyIssuerName(names);
        this.fieldOfApplication = ((DERUTF8String) signaturePolicyInfo.getObjectAt(3)).getString();
        this.signatureValidationPolicy = new SignatureValidationPolicy((ASN1Sequence) signaturePolicyInfo.getObjectAt(4));
        this.signPolExtensionsASN1 = null;
        if (signaturePolicyInfo.size() == 6) {
            this.signPolExtensionsASN1 = this.readASN1Extensions((ASN1Sequence) signaturePolicyInfo.getObjectAt(5));
        }
    }

    /**
     * Retorna o nome do emissor da política
     * @param generalNames O {@link GeneralNames} que contém o nome do emissor
     * @return O nome do emissor da Política de Assinatura
     */
    public String getPolicyIssuerName(GeneralNames generalNames) {
        /*
         * FIXME - Como deve ser feito para retornar essa informação? Usar a
         * string normal retornada pelo GeneralName do BouncyCastle ou ler o
         * generalName pedaço a pedaço.
         */
        GeneralName[] names = generalNames.getNames();
        String issuerName = names[0].toString();
        return issuerName.substring(issuerName.indexOf("C=")).replaceAll(",", ", ");
    }

    /**
     * Retorna a sequência ASN.1 que contém informações da política
     * @return As informações da política codificadas em ASN.1
     */
    public ASN1Sequence getSignPolicyInfoAsn1Object() {
        return this.signPolicyInfoAsn1Object;
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param signaturePolicyInfo elemento XML que representa o atributo
     *            {@link CommonRules}.
     * @throws ParseException Exceção em caso de erro no parsing da data no atributo
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SignaturePolicyInfo(Node signaturePolicyInfo) throws ParseException, CertificateException, IOException, DOMException,
            NoSuchAlgorithmException {
        this.signPolicyIdentifier = signaturePolicyInfo.getChildNodes().item(0).getChildNodes().item(0).getTextContent();
        this.signPolExtensionsXML = null;
        String content = signaturePolicyInfo.getChildNodes().item(1).getTextContent();
        DateFormat dataFormat = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS");
        try {
            this.dateOfIssue = new Time(dataFormat.parse(content).getTime());
        } catch (Exception e) {
            dataFormat = new SimpleDateFormat("yyyy-MM-dd");
            this.dateOfIssue = new Time(dataFormat.parse(content).getTime());
        }
        this.policyIssuerName = signaturePolicyInfo.getChildNodes().item(2).getTextContent();
        this.fieldOfApplication = signaturePolicyInfo.getChildNodes().item(3).getTextContent();
        this.signatureValidationPolicy = new SignatureValidationPolicy(signaturePolicyInfo.getChildNodes().item(4));
        if (signaturePolicyInfo.getChildNodes().getLength() > 5) {
            this.signPolExtensionsXML = signaturePolicyInfo.getChildNodes().item(5).getChildNodes();
        }
    }

    /**
     * Retorna as regras adicionais da política presentes na sequência ASN.1
     * @param extensions A sequência ASN.1
     * @return As regras adicionais da política
     */
    private SignaturePolicyExtension[] readASN1Extensions(ASN1Sequence extensions) {
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
     * Retorna o atributo <code>SignPolicyIdentifier</code>.
     * @return O valor do atributo
     */
    public String getSignPolicyIdentifier() {
        return this.signPolicyIdentifier;
    }

    /**
     * Retorna o atributo <code>DateOfIssue</code>.
     * @return O valor do atributo
     */
    public Time getDateOfIssue() {
        return this.dateOfIssue;
    }

    /**
     * Retorna o atributo <code>PolicyIssuerName</code>.
     * @return O valor do atributo
     */
    public String getPolicyIssuerName() {
        return this.policyIssuerName;
    }

    /**
     * Retorna o atributo <code>FieldOfApplication</code>.
     * @return O valor do atributo
     */
    public String getFieldOfApplication() {
        return this.fieldOfApplication;
    }

    /**
     * Retorna o atributo <code>SignatureValidationPolicy</code>.
     * @return O valor do atributo
     */
    public SignatureValidationPolicy getSignatureValidationPolicy() {
        return this.signatureValidationPolicy;
    }

    /**
     * Retorna o atributo <code>SignPolExtensions</code> para ASN1.
     * @return O valor do atributo
     */
    public SignaturePolicyExtension[] getASN1SignPolExtensions() {
        return this.signPolExtensionsASN1;
    }

    /**
     * Retorna o atributo <code>SignPolExtensions</code> para XML.
     * @return O valor do atributo
     */
    public NodeList getXMLSignPolExtensions() {
        return this.signPolExtensionsXML;
    }

    /**
     * Verifica se existe o atributo <code>SignPolExtensions</code> para ASN1.
     * @return Indica se o atributo não é nulo
     */
    public boolean hasASN1SignPolExtensions() {
        return this.signPolExtensionsASN1 != null;
    }

    /**
     * Verifica se existe o atributo <code>SignPolExtensions</code> para XML.
     * @return Indica se o atributo não é nulo
     */
    public boolean hasXMLSignPolExtensions() {
        return this.signPolExtensionsXML != null;
    }
}
