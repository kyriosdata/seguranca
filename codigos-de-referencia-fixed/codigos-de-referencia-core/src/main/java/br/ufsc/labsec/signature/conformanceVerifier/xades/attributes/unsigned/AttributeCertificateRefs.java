/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignerRole;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SigningCertificateException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esse atributo é usado para guardar as referências para o conjunto de
 * certificados das Autoridades de Atributos que foram usadas para validar o
 * Certificado de Atributo.
 * 
 * Esquema do atributo AttributeCertificateRefs retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="AttributeCertificateRefs" type="CompleteCertificateRefsType"/>
 * }
 */
public class AttributeCertificateRefs implements SignatureAttribute {

    public static final String IDENTIFIER = "AttributeCertificateRefs";
    /**
     * Lista de objetos de informação de certifiados
     */
    private List<CertID> certIdListType;
    /**
     * Objeto de verificador
     */
    private AbstractVerifier signatureVerifier;

    /**
     * Construtor usado somente na verificação da assinatura.
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * @throws SignatureAttributeException
     */
    public AttributeCertificateRefs(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Element attributeEncoded = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        decode(attributeEncoded);
        this.signatureVerifier = signatureVerifier;
    }

    /**
     * <p>
     * Construtor usado na criação do atributo.
     * </p>
     * @param certificates Lista de certificados das Autoridades De Atributos
     *            que foram usadas para validar o Certificado De Atributo
     * @param digestAlgorithm Algoritmo que será usado para obter o hash de
     *            cada certificado
     * 
     * @throws SignatureAttributeException
     */
    public AttributeCertificateRefs(List<X509Certificate> certificates, String digestAlgorithm) throws SignatureAttributeException {
        if (certificates == null || digestAlgorithm == null) {
            throw new SignatureAttributeException("Os parâmetros não podem ser nulos");
        }
        if (certificates.size() == 0) {
            throw new SignatureAttributeException("O caminho de certificação está vazio.");
        }
        String algorithmName = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(digestAlgorithm);
        if (algorithmName == null) {
            throw new SignatureAttributeException("O algoritmo de hash não é conhecido");
        }
        this.certIdListType = new ArrayList<CertID>();
        for (X509Certificate certificate : certificates) {
            byte[] certificateHash = this.getCertificateHash(certificate, algorithmName);
            CertID certId = new CertID();
            certId.setAlgorithm(digestAlgorithm);
            certId.setCertificateDigest(certificateHash);
            certId.setSerialNumber(certificate.getSerialNumber());
            certId.setName(certificate.getIssuerDN().getName());
            this.certIdListType.add(certId);
        }
    }

    /**
     * Constrói um objeto {@link AttributeCertificateRefs}
     * @param attributeEncoded O atributo codificado
     * @throws SignatureAttributeException
     */
    public AttributeCertificateRefs(Element attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

    /**
     * Constrói um objeto {@link AttributeCertificateRefs}
     * @param attribute O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Element attribute) throws SignatureAttributeException {
        Node certRefs = attribute.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "CertRefs").item(0);
        boolean hasAllValues = false;
        if (certRefs != null) {
            NodeList certNodeList = certRefs.getChildNodes();
            this.certIdListType = new ArrayList<CertID>();
            for (int i = 0; i < certNodeList.getLength(); i++) {
                Element certElement = (Element) certNodeList.item(i);

                Element certDigestElement = (Element) certElement.getFirstChild();
                Element digestMethodElement = (Element) certDigestElement.getFirstChild();
                Element digestValueElement = (Element) certDigestElement.getLastChild();
                String algorithm = digestMethodElement.getAttribute("Algorithm");
                byte[] hash = Base64.decode(digestValueElement.getTextContent());

                Element issuerSerialElement = (Element) certElement.getLastChild();
                Element x509IssuerNameElement = (Element) issuerSerialElement.getFirstChild();
                String issuerName = x509IssuerNameElement.getTextContent();
                Element x509IssuerSerialElement = (Element) issuerSerialElement.getLastChild();
                BigInteger serialNumber = new BigInteger(x509IssuerSerialElement.getTextContent());
                hasAllValues = (algorithm != null && hash != null && issuerName != null && serialNumber != null);

                this.certIdListType.get(i).setCertificateDigest(hash);
                this.certIdListType.get(i).setAlgorithm(algorithm);

                this.certIdListType.get(i).setSerialNumber(serialNumber);
                this.certIdListType.get(i).setName(issuerName);

                CertID certIDType = new CertID();
                this.certIdListType.add(certIDType);
            }
        }
        if (!hasAllValues) {
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + this.getIdentifier());
        }
    }

    /**
     * Calcula o hash do certificado dado
     * @param certificate O certificado
     * @param algorithm O algoritmo a ser utilizado no cálculo
     * @return O hash do certificado
     * @throws SignatureAttributeException
     */
    private byte[] getCertificateHash(X509Certificate certificate, String algorithm) throws SignatureAttributeException {
        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException(SigningCertificateException.NO_SUCH_ALGORITHM_EXCEPTION,
                    noSuchAlgorithmException.getStackTrace());
        }
        try {
            messageDigest.update(certificate.getEncoded());
        } catch (CertificateEncodingException certificateEncodingException) {
            throw new SignatureAttributeException(SigningCertificateException.CERTIFICATE_ENCODING_EXCEPTION,
                    certificateEncodingException.getStackTrace());
        }
        return messageDigest.digest();
    }

    // private X509IssuerSerialType getIssuerSerialType(String issuerName,
    // BigInteger subjectSerial) throws SignatureAttributeException
    // {
    // X509IssuerSerialType x509IssuerSerialType = new X509IssuerSerialType();
    // x509IssuerSerialType.setX509IssuerName(issuerName);
    // x509IssuerSerialType.setX509SerialNumber(subjectSerial);
    // return x509IssuerSerialType;
    //
    // }

    /**
     * Retorna o identificador do atributo
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return AttributeCertificateRefs.IDENTIFIER;
    }

    /**
     * Valida o atributo de acordo com suas regras específicas
     * @throws SignatureAttributeException
     */
    @Override
    public void validate() throws SignatureAttributeException {

        List<String> attributeList = this.signatureVerifier.getSignature().getAttributeList();
        int cont = 0;
        for (String attribute : attributeList) {
            if (attribute.equals(this.getIdentifier()))
                cont++;
        }
        if (cont > 1) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(
                    "A assinatura contém mais do que um attributo " + this.getIdentifier());
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        }
        Element signerRoleElement = null;
        signerRoleElement = this.signatureVerifier.getSignature().getEncodedAttribute(SignerRole.IDENTIFIER);
        if (signerRoleElement == null) {
            SignatureAttributeException signatureAttributeException = new SignatureAttributeException(this.getIdentifier()
                    + ": A assinatura não contém nenhum certificado de atributo.");
            signatureAttributeException.setCritical(this.isSigned());
            throw signatureAttributeException;
        } else {
            boolean hasAtLeastOneAttributecertificate = false;
            NodeList attributeCertificateNodeList = signerRoleElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                    "CertifiedRole");
            for (int i = 0; i < attributeCertificateNodeList.getLength(); i++) {
                if (attributeCertificateNodeList.item(i).getTextContent() != null)
                    hasAtLeastOneAttributecertificate = true;
            }
            if (!hasAtLeastOneAttributecertificate) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(this.getIdentifier()
                        + ": A assinatura não contém nenhum certificado de atributo.");
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
    }

    /**
     * Método usado na construção do atributo no momento onde é adicionado na
     * assinatura.
     * @return O atributo em formato de nodo XML
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {
        if (this.certIdListType == null)
            throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + this.getIdentifier()
                    + ". O atributo deve conter pelos menos um valor.");

        Document document = null;
        try {
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new SignatureAttributeException("Problema na construção do document", e.getStackTrace());
        }

        Element completeCertificatesRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:AttributeCertificateRefs");

        for (CertID certId : this.certIdListType) {
            Element certRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CertRefs");
            completeCertificatesRefs.appendChild(certRefs);

            Element cert = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Cert");
            certRefs.appendChild(cert);

            Element certDigest = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CertDigest");
            cert.appendChild(certDigest);

            Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
            digestMethod.setAttribute("Algorithm", certId.getAlgorithm());
            certDigest.appendChild(digestMethod);

            Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
            digestValue.setTextContent(new String(Base64.encode(certId.getCertificateDigest())));
            certDigest.appendChild(digestValue);

            Element issuerSerial = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:IssuerSerial");
            cert.appendChild(issuerSerial);

            Element x509IssuerName = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509IssuerName");
            x509IssuerName.setTextContent(certId.getName());
            issuerSerial.appendChild(x509IssuerName);

            Element x509SerialNumber = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509SerialNumber");
            x509SerialNumber.setTextContent(certId.getSerialNumber().toString());
            issuerSerial.appendChild(x509SerialNumber);

        }

        // CompleteCertificateRefsType completeCertificateRefsType = new
        // CompleteCertificateRefsType();
        // completeCertificateRefsType.setCertRefs(this.certIdListType);
        // Element attributeCertificateRefs;
        // try {
        // attributeCertificateRefs =
        // Marshaller.marshallAttribute(this.getIdentifier(),
        // CompleteCertificateRefsType.class, completeCertificateRefsType,
        // NamespacePrefixMapperImp.XADES_NS);
        // } catch (XmlProcessingException xmlProcessingException) {
        // throw new
        // SignatureAttributeException(xmlProcessingException.getMessage(),
        // xmlProcessingException.getStackTrace());
        // }
        // return attributeCertificateRefs;
        return completeCertificatesRefs;
    }

    /**
     * Informa se o atributo é assinado.
     * @return Indica se o atributo é assinado
     */
    @Override
    public boolean isSigned() {
        return false;
    }

    /**
     * Verifica se o atributo deve ter apenas uma instância na assinatura
     * @return Indica se o atributo deve ter apenas uma instância na assinatura
     */
    @Override
    public boolean isUnique() {
        return true;
    }
}
