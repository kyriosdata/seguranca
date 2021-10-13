/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.DOMException;
import org.w3c.dom.Node;


/**
 * CertificateTrustPoint ::= SEQUENCE {
 * trustpoint Certificate, -- self-signed certificate
 * pathLenConstraint [0] PathLenConstraint OPTIONAL,
 * acceptablePolicySet [1] AcceptablePolicySet OPTIONAL, -- If not present "any policy"
 * nameConstraints [2] NameConstraints OPTIONAL,
 * policyConstraints [3] PolicyConstraints OPTIONAL }
 */
/**
 * <xsd:complexType name="CertificateTrustPointType">
 * <xsd:sequence>
 * <xsd:element name="TrustPoint"
 * type="ds:X509CertificateType"/>
 * <xsd:element name="PathLenConstraint"
 * type="xsd:integer" minOccurs="0"/>
 * <xsd:element name="AcceptablePolicySet"
 * type="AcceptablePoliciesListType" minOccurs="0"/>
 * <xsd:element name="NameConstraints"
 * type="NameConstraintsType" minOccurs="0"/>
 * <xsd:element name="PolicyConstraints"
 * type="PolicyConstraintsType" minOccurs="0"/>
 * </xsd:sequence>
 * </xsd:complexType>
 */
/**
 * Este atributo representa um conjunto de certificados autoassinados usados
 * para começar (ou terminar) o processamento do caminho de certificação e das
 * condições iniciais para a validação do caminho de certificação.
 */
public class CertificateTrustPoint {

    /**
     * Valor do resumo criptográfico
     */
    private String trustPointHash;
    /**
     * Certificado do ponto de confiança
     */
    private Certificate trustPoint;
    /**
     * Restrição do tamanho do caminho de certificação
     */
    private Integer pathLenConstraint;
    /**
     * Array de políticas de certificação aceitas pela PA
     */
    private String[] acceptablePolicySet;
    @SuppressWarnings("unused")
    // atributo não está sendo usado nas políticas atuais
    private NameConstraints nameConstraints;
    @SuppressWarnings("unused")
    // atributo não está sendo usado nas políticas atuais
    private PolicyConstraints policyConstraints;

    /**
     * Construtor usado para decodificar um atributo de uma política ASN1.
     * @param certificateTrustPoint codificação ASN1 do atributo
     *            {@link CertificateTrustPoint}.
     * @throws CertificateException Exceção em caso de erro na codificação do certificado
     * @throws IOException Exceção em caso de erro nos bytes do atributo
     * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public CertificateTrustPoint(ASN1Sequence certificateTrustPoint) throws CertificateException, IOException, NoSuchAlgorithmException {
        this.pathLenConstraint = null;
        this.acceptablePolicySet = null;
        this.nameConstraints = null;
        this.policyConstraints = null;
        ASN1Sequence seq = (ASN1Sequence) certificateTrustPoint.getObjectAt(0);
        this.trustPoint = CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(seq.getEncoded()));
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(this.trustPoint.getEncoded());
        byte[] messageDigest = md.digest();
        this.trustPointHash = this.convertToHex(messageDigest);
        for (int i = 1; i < certificateTrustPoint.size(); i++) {
            ASN1TaggedObject taggetObj = (ASN1TaggedObject) certificateTrustPoint.getObjectAt(i);
            switch (taggetObj.getTagNo()) {
                case 0:
                    ASN1Integer pathLenConst = (ASN1Integer) taggetObj.getObject();
                    BigInteger bigInteger = pathLenConst.getValue();
                    this.pathLenConstraint = bigInteger.intValue();
                    break;
                case 1:
                    this.acceptablePolicySet = this.readObjectIdentifiers((ASN1Sequence) taggetObj.getObject());
                    break;
                case 2:
                    this.nameConstraints = new NameConstraints((ASN1Sequence) taggetObj.getObject());
                    break;
                case 3:
                    this.policyConstraints = new PolicyConstraints((ASN1Sequence) taggetObj.getObject());
                    break;
            }
        }
    }

    /**
     * Construtor usado para decodificar um atributo de uma política XML.
     * @param item nodo XML que representa o atributo
     *            {@link AlgorithmConstraintSet}.
	 * @throws CertificateException Exceção em caso de erro na codificação do certificado
	 * @throws DOMException Exceção em caso de erro nos bytes do atributo
	 * @throws NoSuchAlgorithmException Exceção em caso de algoritmo de hash inválido
     */
    public CertificateTrustPoint(Node item) throws CertificateException, DOMException, NoSuchAlgorithmException {
        Node item1 = item.getFirstChild();
        Node node = item1.getFirstChild().getFirstChild();
        byte[] trustPointAux = Base64.decode(node.getTextContent());
        this.trustPoint = CertificateFactory.getInstance("X509").generateCertificate(new ByteArrayInputStream(trustPointAux));
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        md.update(trustPointAux);
        byte[] messageDigest = md.digest();
        this.trustPointHash = this.convertToHex(messageDigest);
        for (int i = 1; i < item.getChildNodes().getLength(); i++) {
            switch (item.getChildNodes().item(i).getLocalName()) {
                case "PathLenConstraint":
                    this.pathLenConstraint = Integer.parseInt(item.getChildNodes().item(i).getTextContent());
                    break;
                case "AcceptablePolicySet":
                    this.acceptablePolicySet = readObjectIdentifiers(item.getChildNodes().item(i));
                    break;
                case "NameConstraints":
                    // TODO implementar NameConstraints
                    break;
                case "PolicyConstraintsType":
                    // TODO implementar PolicyConstraints
                    break;
            }
        }
    }

	/**
	 * Cria um array com os identificadores dos objetos da sequeência ASN.1
	 * @param seq A sequeência ASN.1
	 * @return O array com identificadores
	 */
	private String[] readObjectIdentifiers(ASN1Sequence seq) {
        String[] ret = null;
        if (seq.size() > 0) {
            ret = new String[seq.size()];
            for (int i = 0; i < seq.size(); i++) {
                ret[i] = seq.getObjectAt(i).toString();
            }
        }
        return ret;
    }

	/**
	 * Cria um array com os identificadores dos objetos no nodo XML
	 * @param node O nodo XML
	 * @return O array com identificadores
	 */
    private String[] readObjectIdentifiers(Node node) {
        String[] ret = null;
        if (node.getChildNodes().getLength() > 0) {
            ret = new String[node.getChildNodes().getLength()];
            for (int i = 0; i < node.getChildNodes().getLength(); i++) {
                ret[i] = node.getChildNodes().item(i).getTextContent();
            }
        }
        return ret;
    }

    /**
     * Retorna o valor do atributo <code>PathLenConstraint</code>, que representa o
     * número máximo de ACs que podem existir no caminho de certificação, a
     * partir da AC Raiz.
     * @return O comprimento máximo do caminho de certificação
     */
    public Integer getPathLenConstraint() {
        return this.pathLenConstraint;
    }

    /**
     * Retorna o atributo <code>AcceptablePolicySet</code>, que representa o
     * conjunto inicial de políticas de certificação - cada uma que é aceita
     * pela Política de Assinatura.
     * @return Array com as políticas de certificação aceitas
     */
    public String[] getAcceptablePolicySet() {
        return this.acceptablePolicySet;
    }

    /**
     * Retorna o atributo <code>NameConstraints</code>, que representa o espaço
     * para nome dentro do qual todos os nomes de signatário nos subsequentes
     * certificados do caminho de certificação devem estar localizados.
     * @return O valor atributo {@link NameConstraints}.
     * @throws Exception Exceção pelo método não ser implementado
     */
    public NameConstraints getNameConstraints() throws Exception {
        // TODO implementar getNameConstraints
        throw new Exception("Método não implementado");
    }

    /**
     * Retorna o atributo <code>PolicyConstraints</code>, que representa a regra
     * que será usada no processamento do caminho de certificação.
     * @return O atributo {@link PolicyConstraints}.
	 * @throws Exception Exceção pelo método não ser implementado
     */
    public PolicyConstraints getPolicyConstraints() throws Exception {
        // TODO implementar getPolicyConstraints
        throw new Exception("Método não implementado");
    }

    /**
     * Retorna o hash do certificado do ponto de confiança
     * @return O valor de hash em hexadecimal
     */
    public String getTrustPointHash() {
        return trustPointHash;
    }

    /**
     * Retorna o certificado do ponto de confiança
     * @return O certificado do ponto de confiança
     */
    public Certificate getTrustPoint() {
        return trustPoint;
    }

    /**
     * Converte os bytes de hash para hexadecimal
     * @param data Os bytes de hash
     * @return O valor do hash em hexadecimal
     */
    private String convertToHex(byte[] data) {
        StringBuilder buf = new StringBuilder();
        for (byte datum : data) {
            int halfbyte = (datum >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9))
                    buf.append((char) ('0' + halfbyte));
                else
                    buf.append((char) ('a' + (halfbyte - 10)));
                halfbyte = datum & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }
}
