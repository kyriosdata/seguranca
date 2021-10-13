/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

///**
// * TimestampTrustCondition ::= SEQUENCE {
// * ttsCertificateTrustTrees [0] CertificateTrustTrees OPTIONAL,
// * ttsRevReq [1] CertRevReq OPTIONAL,
// * ttsNameConstraints [2] NameConstraints OPTIONAL,
// * cautionPeriod [3] DeltaTime OPTIONAL,
// * signatureTimestampDelay [4] DeltaTime OPTIONAL }
// */
///**
// * <xsd:element name="TimeStampTrustCondition"
// * type="TimeStampTrustConditionType"/>
// * <xsd:complexType name="TimeStampTrustConditionType">
// * <xsd:sequence>
// * <xsd:element name="TtsCertificateTrustTrees"
// * type="CertificateTrustTreesType" minOccurs="0"/>
// * <xsd:element name="TtsRevReq" type="CertificateRevReqType"
// * minOccurs="0"/>
// * <xsd:element name="TtsNameConstraints" type="NameConstraintsType"
// * minOccurs="0"/>
// * <xsd:element name="CautionPeriod" type="DeltaTimeType" minOccurs="0"/>
// * <xsd:element name="SignatureTimeStampDelay" type="DeltaTimeType"
// * minOccurs="0"/>
// * </xsd:sequence>
// * </xsd:complexType>
// * <xsd:complexType name="DeltaTimeType">
// * <xsd:sequence>
// * <xsd:element name="DeltaSeconds" type="xsd:integer"/>
// * <xsd:element name="DeltaMinutes" type="xsd:integer"/>
// * <xsd:element name="DeltaHours" type="xsd:integer"/>
// * <xsd:element name="DeltaDays" type="xsd:integer"/>
// * </xsd:sequence>
// * </xsd:complexType>
// */
/**
 * Este atributo identifica as condições de confiança para a construção do
 * caminho de certificação usado para autenticar a autoridade de carimbo do
 * tempo e as restrições sobre o nome da autoridade de carimbo do tempo.
 */
public class TimeStampTrustCondition {

    /**
     * Certificados de pontos de confiança
     */
    private CertificateTrustPoint[] ttsCertificateTrustTrees;
    /**
     * Requerimentos de revocação
     */
    private CertRevReq ttsRevReq;
    /**
     * Restrição de nomes de assinantes
     */
    private NameConstraints ttsNameConstraints;
    /**
     * Período após a geração da assinatura no qual o verificador deve
     * esperar para garantir a validade da chave do assinante
     */
    private DeltaTime cautionPeriod;
    /**
     * Máximo de tempo aceitável entre o momento da assinatura e o momento que o
     * carimbo de tempo na assinatura é criado
     */
    private DeltaTime signatureTimestampDelay;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param timestampTrustCondition codificação ASN1 do atributo
     *            {@link TimeStampTrustCondition}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public TimeStampTrustCondition(ASN1Sequence timestampTrustCondition) throws CertificateException, IOException, NoSuchAlgorithmException {
        this.ttsCertificateTrustTrees = null;
        this.ttsRevReq = null;
        this.ttsNameConstraints = null;
        this.cautionPeriod = null;
        this.signatureTimestampDelay = null;
        for (int i = 0; i < timestampTrustCondition.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) timestampTrustCondition.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    this.ttsCertificateTrustTrees = this.readTrustTrees((ASN1Sequence) taggetObj.getObject());
                    break;
                case 1:
                    this.ttsRevReq = new CertRevReq((ASN1Sequence) taggetObj.getObject());
                    break;
                case 2:
                    this.ttsNameConstraints = new NameConstraints((ASN1Sequence) taggetObj.getObject());
                    break;
                case 3:
                    this.cautionPeriod = new DeltaTime((ASN1Sequence) taggetObj.getObject());
                    break;
                case 4:
                    this.signatureTimestampDelay = new DeltaTime((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param timeStampTrustCondition elemento XML que representa o atributo
     *            {@link TimeStampTrustCondition}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws DOMException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public TimeStampTrustCondition(Element timeStampTrustCondition) throws CertificateException, DOMException, NoSuchAlgorithmException {
        int elementSize = timeStampTrustCondition.getChildNodes().getLength();
        for (int i = 0; i < elementSize; i++) {
            Element element = (Element) timeStampTrustCondition.getChildNodes().item(i);
            if (element.getLocalName().equalsIgnoreCase("TtsCertificateTrustTrees")) {
                this.ttsCertificateTrustTrees = new CertificateTrustPoint[element.getChildNodes().getLength()];
                NodeList trustTrees = element.getChildNodes();
                for (int j = 0; j < trustTrees.getLength(); j++) {
                    this.ttsCertificateTrustTrees[j] = new CertificateTrustPoint(trustTrees.item(j));
                }
            } else if (element.getLocalName().equalsIgnoreCase("TtsRevReq")) {
                this.ttsRevReq = new CertRevReq(element);
            } else if (element.getLocalName().equalsIgnoreCase("TtsNameConstraints")) {
                // TODO TimeStampTrustCondition
            } else if (element.getLocalName().equalsIgnoreCase("CautionPeriod")) {
                // TODO TimeStampTrustCondition
            } else if (element.getLocalName().equalsIgnoreCase("SignatureTimeStampDelay")) {
                // TODO TimeStampTrustCondition
            }
        }
    }

    /**
     * Retorna o atributo <code>TtsCertificateTrustTrees</code>.
     * @return O valor do atributo
     */
    public CertificateTrustPoint[] getTtsCertificateTrustTrees() {
        return ttsCertificateTrustTrees;
    }

    /**
     * Retorna o atributo que representa o mínimo de requisitos para informação
     * de revogação.
     * @return O valor do atributo
     */
    public CertRevReq getTtsRevReq() {
        return ttsRevReq;
    }

    /**
     * Retorna o atributo <code>TtsNameConstraints</code>.
     * @return O valor do atributo
     */
    public NameConstraints getTtsNameConstraints() {
        return ttsNameConstraints;
    }

    /**
     * Retorna o atributo <code>CautionPeriod</code>.
     * @return O valor do atributo
     */
    public DeltaTime getCautionPeriod() {
        return cautionPeriod;
    }

    /**
     * Retorna o atributo <code>SignatureTimestampDelay</code>.
     * @return O valor do atributo
     */
    public DeltaTime getSignatureTimestampDelay() {
        return signatureTimestampDelay;
    }

    /**
     * Cria o array de pontos de segurança através da sequência ASN.1 dada
     * @param trustTrees A sequência ASN.1
     * @return O array gerado
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    private CertificateTrustPoint[] readTrustTrees(ASN1Sequence trustTrees) throws CertificateException, IOException,
        NoSuchAlgorithmException {
        CertificateTrustPoint[] certificateTrustTrees = null;
        if (trustTrees.size() > 0) {
            certificateTrustTrees = new CertificateTrustPoint[trustTrees.size()];
            for (int i = 0; i < certificateTrustTrees.length; i++) {
                certificateTrustTrees[i] = new CertificateTrustPoint((ASN1Sequence) trustTrees.getObjectAt(i));
            }
        }
        return certificateTrustTrees;
    }
}
