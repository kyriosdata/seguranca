/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyExtension;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.ASN1Boolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.w3c.dom.Node;

import java.util.Arrays;
import java.util.Iterator;

///**
// * SignerRules ::= SEQUENCE {
// externalSignedData         BOOLEAN OPTIONAL,
// -- True if signed data is external to CMS structure
// -- False if signed data part of CMS structure
// -- not present if either allowed
// mandatedSignedAttr         CMSAttrs,    -- Mandated CMS signed attributes
// mandatedUnsignedAttr       CMSAttrs,    -- Mandated CMS unsigned attributed
// mandatedCertificateRef     [0] CertRefReq DEFAULT signerOnly,          -- Mandated Certificate Reference
// mandatedCertificateInfo    [1] CertInfoReq DEFAULT none,               -- Mandated Certificate Info
// signPolExtensions        [2] SignPolExtensions      OPTIONAL
// }
// * **/
//
///** <xsd:complexType name="SignerRulesType">
// <xsd:sequence>
// <xsd:element name="ExternalSignedObjects" type="xsd:boolean"
// minOccurs="0" />
// <xsd:element name="MandatedSignedQProperties" type="QPropertiesListType" />
// <xsd:element name="MandatedUnsignedQProperties" type="QPropertiesListType" />
// <xsd:element name="MandatedCertificateRef" type="CertificateReqType" />
// <xsd:element name="MandatedCertificateInfo" type="CertificateInfoType" />
// <xsd:element name="SignPolicyExtensions" type="SignPolExtensionsListType"
// minOccurs="0" />
// </xsd:sequence>
// </xsd:complexType>
//
// <xsd:complexType name="QPropertiesListType">
// <xsd:sequence minOccurs="0" maxOccurs="unbounded">
// <xsd:element name="QPropertyID" type="xsd:anyURI" />
// </xsd:sequence>
// </xsd:complexType>
//
// <xsd:simpleType name="CertificateReqType">
// <xsd:restriction base="xsd:string">
// <xsd:enumeration value="signerOnly" />
// <xsd:enumeration value="fullPath" />
// </xsd:restriction>
// </xsd:simpleType>
//
// <xsd:simpleType name="CertificateInfoType">
// <xsd:restriction base="xsd:string">
// <xsd:enumeration value="none" />
// <xsd:enumeration value="signerOnly" />
// <xsd:enumeration value="fullPath" />
// </xsd:restriction>
// </xsd:simpleType>
// */

/**
 * Esta classe especifica as regras do assinante. É um atributo da classe
 * {@link SignerAndVerifierRules}.
 */
public class SignerRules {

    /**
     * Enumeração dos modos de dados assinados
     */
    public enum ExternalSignedData {
        EXTERNAL, INTERNAL, EITHER
    }

    /**
     * Enumeração de referência obrigatória de certificado
     */
    public enum CertRefReq {
        SIGNER_ONLY, FULL_PATH
    }

    /**
     * Enumeralção de informação obrigatória de certificado
     */
    public enum CertInfoReq {
        NONE, SIGNER_ONLY, FULL_PATH
    }

    /**
     * Modo do dado assinado
     */
    private ExternalSignedData externalSignedData;
    /**
     * Atributos assinados obrigatórios
     */
    private String[] mandatedSignedAttr;
    /**
     * Atributos não-assinados obrigatórios
     */
    private String[] mandatedUnsignedAttr;
    /**
     * Referência obrigatória de certificado
     */
    private CertRefReq mandatedCertificateRef;
    /**
     * Informação obrigatória de certificado
     */
    private CertInfoReq mandatedCertificateInfo;
    /**
     * Regras adicionais da política de assinatura
     */
    private SignaturePolicyExtension[] signPolExtensions;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param signerRules codificação ASN1 do atributo {@link SignerRules}.
     */
    public SignerRules(ASN1Sequence signerRules) {

        this.mandatedCertificateRef = CertRefReq.SIGNER_ONLY;
        this.mandatedCertificateInfo = CertInfoReq.NONE;

        int index = 0;
        ASN1Encodable derEncodable = signerRules.getObjectAt(index);

        if (derEncodable instanceof ASN1Boolean) {
            if (((ASN1Boolean) derEncodable).isTrue()) {
                this.externalSignedData = ExternalSignedData.EXTERNAL;
            } else {
                this.externalSignedData = ExternalSignedData.INTERNAL;
            }
            derEncodable = signerRules.getObjectAt(++index);
        } else {
            this.externalSignedData = ExternalSignedData.EITHER;
        }

        this.mandatedSignedAttr = this.readObjectIdentifiers((ASN1Sequence) derEncodable);
        derEncodable = signerRules.getObjectAt(++index);
        this.mandatedUnsignedAttr = this.readObjectIdentifiers((ASN1Sequence) derEncodable);
        index++;

        ASN1TaggedObject taggetObj;
        for (int i = index; i < signerRules.size(); i++) {
            taggetObj = (ASN1TaggedObject) signerRules.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    this.mandatedCertificateRef = this.getCertRefReq((ASN1Enumerated) taggetObj.getObject());
                    break;

                case 1:
                    this.mandatedCertificateInfo = this.getCertInfoReq((ASN1Enumerated) taggetObj.getObject());
                    break;

                case 2:
                    this.signPolExtensions = this.readExtensions((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param item elemento XML que representa o atributo
     *            {@link SignerAndVerifierRules}.
     */
    public SignerRules(Node item) {
        int i = 0;
        // Verifica se existe o campo ExternalSignedObjects, senão existir seta
        // como EITHER
        if (item.getFirstChild().getLocalName().equals("ExternalSignedObjects")) {
            i++;
            String extSigData = item.getFirstChild().getTextContent();
            if (extSigData.equalsIgnoreCase("true")) {
                this.externalSignedData = ExternalSignedData.EXTERNAL;
            } else {
                this.externalSignedData = ExternalSignedData.INTERNAL;
            }
        } else {
            this.externalSignedData = ExternalSignedData.EITHER;
        }
        // obtendo informacoes do mandatedSignedQProperties
        Node mandatedSignedQProperties = item.getChildNodes().item(i);
        this.mandatedSignedAttr = new String[mandatedSignedQProperties.getChildNodes().getLength()];
        for (int j = 0; j < this.mandatedSignedAttr.length; j++) {
            this.mandatedSignedAttr[j] = mandatedSignedQProperties.getChildNodes().item(j).getTextContent();
        }
        i++;
        // obtendo informacoes do mandatedUnsignedQProperties
        Node mandatedUnsignedQProperties = item.getChildNodes().item(i);
        this.mandatedUnsignedAttr = new String[mandatedUnsignedQProperties.getChildNodes().getLength()];
        for (int j = 0; j < this.mandatedUnsignedAttr.length; j++) {
            this.mandatedUnsignedAttr[j] = mandatedUnsignedQProperties.getChildNodes().item(j).getTextContent();
        }
        i++;
        // obtendo informacoes do mandatedCertificateRef
        Node mandatedCertificateRef = item.getChildNodes().item(i);
        String certRef = mandatedCertificateRef.getFirstChild().getTextContent();
        if (certRef.equalsIgnoreCase("signerOnly"))
            this.mandatedCertificateRef = CertRefReq.SIGNER_ONLY;
        else if (certRef.equalsIgnoreCase("fullPath"))
            this.mandatedCertificateRef = CertRefReq.FULL_PATH;
        i++;
        // obtendo informacoes do mandatedCertificateInfo
        Node mandatedCertificateInfo = item.getChildNodes().item(i);
        String certInfo = mandatedCertificateInfo.getFirstChild().getTextContent();
        if (certInfo.equals("signerOnly"))
            this.mandatedCertificateInfo = CertInfoReq.SIGNER_ONLY;
        else if (certInfo.equals("fullPath"))
            this.mandatedCertificateInfo = CertInfoReq.FULL_PATH;
        else
            this.mandatedCertificateInfo = CertInfoReq.NONE;
    }

    /**
     * Retorna o valor de informação obrigatória de certificado
     * @param object O objeto ASN.1 que contém o valor
     * @return A informação obrigatória de certificado
     */
    private CertInfoReq getCertInfoReq(ASN1Enumerated object) {
        CertInfoReq ret = CertInfoReq.NONE;

        switch (object.getValue().intValue()) {
            case 0:
                ret = CertInfoReq.NONE;
                break;

            case 1:
                ret = CertInfoReq.SIGNER_ONLY;
                break;

            case 2:
                ret = CertInfoReq.FULL_PATH;
                break;
        }

        return ret;
    }

    /**
     * Retorna o valor de referência obrigatória de certificado
     * @param enumeration O objeto ASN.1 que contém o valor
     * @return A referência obrigatória de certificado
     */
    private CertRefReq getCertRefReq(ASN1Enumerated enumeration) {
        CertRefReq ret = CertRefReq.SIGNER_ONLY;

        switch (enumeration.getValue().intValue()) {
            case 1:
                ret = CertRefReq.SIGNER_ONLY;
                break;

            case 2:
                ret = CertRefReq.FULL_PATH;
                break;
        }
        return ret;
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
     * Retorna se o dado assinado é externo, interno ou qualquer um dos
     * anteriores.
     * @return O modo do dado assinado
     */
    public ExternalSignedData getExternalSignedData() {
        return this.externalSignedData;
    }

    /**
     * Retorna os OIDs, no caso do CAdES, ou as Tags, no caso do XAdES, dos
     * atributos assinados obrigatórios.
     * @return O array de OIDs ou Tags.
     */
    public String[] getMandatedSignedAttr() {
        return this.mandatedSignedAttr;
    }

    /**
     * Retorna os OIDs, no caso do CAdES, ou as Tags, no caso do XAdES, dos
     * atributos não assinados obrigatórios.
     * @return O array de OIDs ou Tags
     */
    public String[] getMandatedUnsignedAttr() {
        return this.mandatedUnsignedAttr;
    }

    /**
     * Retorna o atributo <code>mandatedCertificateRef</code>.
     * @return O valor do atributo
     */
    public CertRefReq getMandatedCertificateRef() {
        return this.mandatedCertificateRef;
    }

    /**
     * Retorna o atributo <code>mandatedCertificateInfo</code>.
     * @return O valor do atributo
     */
    public CertInfoReq getMandatedCertificateInfo() {
        return this.mandatedCertificateInfo;
    }

    /**
     * Retorna as regras adicionais da Política de Assinatura.
     * @return As regras adicionais da política
     */
    public SignaturePolicyExtension[] getSignPolExtensions() {
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

    /**
     * Retorna a extensão de assinatura brExtMandatedPdfSigDicEntries
     * @return O valor da extensão
     */
    public BrExtMandatedPdfSigDicEntries getBrExtMandatedPdfSigDicEntries(){

        Iterator<SignaturePolicyExtension> it = Arrays.asList(this.getSignPolExtensions()).iterator();
        BrExtMandatedPdfSigDicEntries brExtMandatedPdfSigDicEntries = null;

        while(it.hasNext() || brExtMandatedPdfSigDicEntries == null){
            SignaturePolicyExtension extension = it.next();

            if(extension.getExtnID().equals(BrExtMandatedPdfSigDicEntries.IDENTIFIER)){
                brExtMandatedPdfSigDicEntries = new BrExtMandatedPdfSigDicEntries(extension.getExtnValue());
            }
        }
        return brExtMandatedPdfSigDicEntries;
    }

    /**
     * Retorna a extensão de assinatura brExtMandatedPdfSigDicEntries
     * @return {@link BrExtDss}
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
     * Retorna a extensão de assinatura brExtMandatedDocTSEntries
     * @return O valor da extensão
     */
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
