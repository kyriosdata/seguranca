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
import org.w3c.dom.DOMException;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

///**
// * SigningCertTrustCondition ::= SEQUENCE {
// signerTrustTrees            CertificateTrustTrees,
// signerRevReq                CertRevReq
// }
// */
///**
// * <xsd:complexType name="SigningCertTrustConditionType">
// <xsd:sequence>
// <xsd:element name="SignerTrustTrees" type="CertificateTrustTreesType" minOccurs="0"/>
// <xsd:element name="SignerRevReq" type="CertificateRevReqType" minOccurs="0"/>
// </xsd:sequence>
// </xsd:complexType>
// */

/**
 * Este atributo identifica condições de confiança para a construção do caminho
 * de certificação usado para a validação do atributo Signing Certificate.
 */
public class SigningCertTrustCondition {

    /**
     * Certificados de pontos de confiança
     */
    private CertificateTrustPoint[] signerTrustTrees;
    /**
     * Requerimentos de revocação
     */
    private CertRevReq signerRevReq;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param signingCertTrustCondition codificação ASN1 do atributo
     *            {@link SigningCertTrustCondition}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SigningCertTrustCondition(ASN1Sequence signingCertTrustCondition) throws CertificateException, IOException,
            NoSuchAlgorithmException {
        /*
         * Correção do possível bug do bouncycastle Obs.: Nesse ponto deveria
         * aparecer um tagged-object, mas por alguma razão as tags deixam de
         * existir após serem lidas e o seu objeto( um sequence) está
         * imediatamente na posição.
         */
        ASN1Sequence taggetObj = (ASN1Sequence) signingCertTrustCondition.getObjectAt(0);
        this.signerTrustTrees = this.readASN1TrustTrees(taggetObj);
        taggetObj = (ASN1Sequence) signingCertTrustCondition.getObjectAt(1);
        /*
         * Correção do possível bug do bouncycastle
         */
        this.signerRevReq = new CertRevReq(taggetObj);
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param signingCertTrustCondition elemento XML que representa o atributo
     *            {@link SigningCertTrustCondition}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws DOMException Exceção em caso de erro no elemento XML
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public SigningCertTrustCondition(Element signingCertTrustCondition) throws CertificateException, IOException, DOMException,
            NoSuchAlgorithmException {

        this.signerTrustTrees = null;
        this.signerRevReq = null;

        NodeList node = signingCertTrustCondition.getChildNodes();
        for (int i = 0; i < node.getLength(); i++) {
            Element element = (Element) node.item(i);
            String tagName = element.getTagName();

            if (tagName.equals("pa:SignerTrustTrees")) {
                this.signerTrustTrees = this.readXMLTrustTrees(element);
            } else if (tagName.equals("pa:SignerRevReq")) {
                this.signerRevReq = new CertRevReq(element);
            }
        }
    }

    /**
     * Retorna os certificados de pontos de confiança presentes na sequência ASN.1 dada
     * @param seq A sequência ASN.1
     * @return Os certificados de pontos de confiança
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    private CertificateTrustPoint[] readASN1TrustTrees(ASN1Sequence seq) throws CertificateException, IOException, NoSuchAlgorithmException {

        CertificateTrustPoint[] certificateTrustTrees = new CertificateTrustPoint[seq.size()];

        for (int i = 0; i < certificateTrustTrees.length; i++) {

            certificateTrustTrees[i] = new CertificateTrustPoint((ASN1Sequence) seq.getObjectAt(i));
        }
        return certificateTrustTrees;
    }

    /**
     * Retorna os certificados de pontos de confiança presentes no elemento XML
     * @param element O elemento XML
     * @return Os certificados de pontos de confiança
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws DOMException Exceção em caso de erro no elemento XML
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    private CertificateTrustPoint[] readXMLTrustTrees(Element element) throws CertificateException, IOException, DOMException,
        NoSuchAlgorithmException {

        CertificateTrustPoint[] certificateTrustTrees = new CertificateTrustPoint[element.getChildNodes().getLength()];

        for (int i = 0; i < certificateTrustTrees.length; i++) {
            Element element1 = (Element) element.getChildNodes().item(i);
            certificateTrustTrees[i] = new CertificateTrustPoint(element1);
        }
        return certificateTrustTrees;
    }

    /**
     * Retorna o atributo <code>SignerTrustTrees</code>.
     * @return O valor do atributo
     */
    public CertificateTrustPoint[] getSignerTrustTrees() {
        return signerTrustTrees;
    }

    /**
     * Retorna os requerimentos de revogação.
     * @return O valor do atributo
     */
    public CertRevReq getSignerRevReq() {
        return signerRevReq;
    }
}
