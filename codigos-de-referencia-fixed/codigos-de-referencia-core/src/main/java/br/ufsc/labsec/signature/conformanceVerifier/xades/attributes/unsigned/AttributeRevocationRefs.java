/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CRLException;
import java.security.cert.X509CRL;
import java.sql.Time;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;
import java.util.TimeZone;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERSequence;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.ocsp.BasicOCSPResponse;
import org.bouncycastle.asn1.x509.AttributeCertificate;
import org.bouncycastle.asn1.x509.AttributeCertificateInfo;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.ocsp.BasicOCSPResp;
import org.bouncycastle.cert.ocsp.RespID;
import org.bouncycastle.util.encoders.Base64;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractVerifier;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.SignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.CommitmentTypeIndication;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignerRole;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esse atributo é usado para guardar as referências para todo
 * o conjunto de dados de revogação que foram usadas para validar o Certificado de Atributo
 * presente na assinatura.
 * 
 * Esquema do atributo AttributeRevocationRefs retirado do ETSI TS 101 903:
 * 
 * {@code
 * <xsd:element name="AttributeRevocationRefs" type="CompleteRevocationRefsType"/>
 * }
 */
public class AttributeRevocationRefs implements br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute {

    /**
     * O algoritmo de hash utilizado
     */
    private String algorithm;
    /**
     * Lista de referências de CRL
     */
    private List<CRLRefs> crlRefs;
    /**
     * Lista de referências de OCSP
     */
    private List<OCSPRefs> ocspRefs;
    /**
     * Objeto de verificador
     */
    private SignatureVerifier signatureVerifier;
    public static final String IDENTIFIER = "AttributeRevocationRefs";

    /**
     * <p>
     * Construtor usado para validar o atributo
     * </p>
     * @param signatureVerifier Usado para criar e verificar o atributo
     * @param index Índice usado para selecionar o atributo
     * 
     * @throws SignatureAttributeException
     */
    public AttributeRevocationRefs(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
        Element genericEncoding = signatureVerifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        this.decode(genericEncoding);
        this.signatureVerifier = (SignatureVerifier) signatureVerifier;
    }

    /**
     * <p>
     * Construtor usado para decodificar um atributo já existente.
     * </p>
     * 
     * @param genericEncoding O atributo codificado
     * 
     * @throws SignatureAttributeException
     */
    public AttributeRevocationRefs(Element genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * <p>
     * Construtor usado na criação do atributo. Pelo menos uma das duas listas
     * deve conter algum elemento de revogação.
     * </p>
     * 
     * @param crls Lista de CRLs do caminho de certificação
     * @param basicOCSPResponses Lista de respostas OCSPs para o caminho de
     *            certificação
     * @param digestAlgorithm Algoritmo de hash utilizado nas CRLs ou nas
     *            OCSPs
     * 
     * @throws SignatureAttributeException
     */
    public AttributeRevocationRefs(List<X509CRL> crls, List<BasicOCSPResponse> basicOCSPResponses, String digestAlgorithm)
            throws SignatureAttributeException {
        boolean hasAtLeastOne = false;
        if (crls != null && !crls.isEmpty()) {
            this.setAlgorithm(digestAlgorithm);
            this.makeCrlRefList(crls, digestAlgorithm);
            hasAtLeastOne = true;
        }
        if (basicOCSPResponses != null && !basicOCSPResponses.isEmpty()) {
            this.setAlgorithm(digestAlgorithm);
            this.makeOcspRefList(basicOCSPResponses, digestAlgorithm);
            hasAtLeastOne = true;
        }
        if (!hasAtLeastOne) {
            throw new SignatureAttributeException("O construtordeve conter pelo menos um elemento de revogação e um algoritmo de hash.");
        }
    }

    /**
     * Constrói um objeto {@link AttributeRevocationRefs}
     * @param attributeElement O atributo codificado
     * @throws SignatureAttributeException
     */
    private void decode(Element attributeElement) throws SignatureAttributeException {
        NodeList crlRefsList = attributeElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "CRLRefs");
        if (crlRefsList.getLength() > 0) {
            parseCrlRefs(crlRefsList);
        }
        NodeList ocspRefsList = attributeElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "OCSPRefs");
        if (ocspRefsList.getLength() > 0) {
            parseOcspRefs(ocspRefsList);
        }
    }

    /**
     * Atribue as referências no nodo à lista de referências OCSP
     * @param ocspRefsList Nodo com a lista de referências
     * @throws SignatureAttributeException
     */
    private void parseOcspRefs(NodeList ocspRefsList) throws SignatureAttributeException {
        this.ocspRefs = new ArrayList<OCSPRefs>();
        Element ocspRefsElement = (Element) ocspRefsList.item(0);
        NodeList ocspRefList = ocspRefsElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "OCSPRef");
        for (int i = 0; i < ocspRefList.getLength(); i++) {
            Element ocspRef = (Element) ocspRefList.item(i);
            Element certDigestElement = (Element) ocspRef.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "DigestAlgAndValue")
                    .item(0);
            Element digestMethodElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    "DigestMethod").item(0);
            this.algorithm = digestMethodElement.getAttribute("Algorithm");
            Element digestValueElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    "DigestValue").item(0);

            OCSPRefs ocsp = new OCSPRefs();
            ocsp.setAlgorithm(this.algorithm);
            ocsp.setDigestValue(Base64.decode(digestValueElement.getTextContent()).toString());
            this.ocspRefs.add(ocsp);
        }
    }

    /**
     * Atribue as referências no nodo à lista de referências de CRLs
     * @param crlRefsList Nodo com a lista de referências
     * @throws SignatureAttributeException
     */
    private void parseCrlRefs(NodeList crlRefsList) throws SignatureAttributeException {
        this.crlRefs = new ArrayList<CRLRefs>();
        Element crlRefs = (Element) crlRefsList.item(0);
        NodeList crlRefList = crlRefs.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "CRLRef");
        for (int i = 0; i < crlRefList.getLength(); i++) {
            Element crlRef = (Element) crlRefList.item(i);
            Element certDigestElement = (Element) crlRef.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, "DigestAlgAndValue")
                    .item(0);
            Element digestMethodElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    "DigestMethod").item(0);
            this.algorithm = digestMethodElement.getAttribute("Algorithm");
            Element digestValueElement = (Element) certDigestElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS,
                    "DigestValue").item(0);

            CRLRefs crl = new CRLRefs();
            crl.setAlgorithm(this.algorithm);
            crl.setDigestValue(new String(Base64.decode(digestValueElement.getTextContent())));
            this.crlRefs.add(crl);
        }
    }

    /**
     * Atribue o algoritmo utilizado no cálculo de hash
     * @param algorithm O algoritmo utilizado
     * @throws SignatureAttributeException Exceção em caso de algoritmo nulo ou desconhecido
     */
    private void setAlgorithm(String algorithm) throws SignatureAttributeException {
        if (algorithm == null)
            throw new SignatureAttributeException("O algoritmo não pode ser nulo");
        String obtainedIdentifier = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm);
        if (obtainedIdentifier == null)
            throw new SignatureAttributeException("O algoritmo indicado é desconhecido");
        this.algorithm = algorithm;
    }

    /**
     * Atribue as respostas OCSP à lista de referências OCSP
     * @param basicOCSPResponses A lista de respostas OCSP
     * @param algorithm O algoritmo da referência
     * @throws SignatureAttributeException
     */
    private void makeOcspRefList(List<BasicOCSPResponse> basicOCSPResponses, String algorithm) throws SignatureAttributeException {
        if (basicOCSPResponses == null || basicOCSPResponses.size() == 0)
            throw new SignatureAttributeException("Esse construtor não deve ser usado se não há nenhuma resposta OCSP para referênciar");
        this.ocspRefs = new ArrayList<OCSPRefs>();
        for (BasicOCSPResponse basicOCSPResponse : basicOCSPResponses) {
            this.makeOcspReference(algorithm, basicOCSPResponse);
        }
    }

    /**
     * Adiciona a resposta OCSP à lista de referências OCSP
     * @param algorithm O algoritmo da referência
     * @param basicOCSPResponse A resposta OCSP
     * @throws SignatureAttributeException
     */
    //FIXME rever, existem variaveis que não existem mais no meio do código morto. Rever o funcionamento deste método. E criar JavaDoc.
    private void makeOcspReference(String algorithm, BasicOCSPResponse basicOCSPResponse) throws SignatureAttributeException {
        OCSPRefs ocspRef = new OCSPRefs();
        // OCSPIdentifierType ocspIdentifier = new OCSPIdentifierType();
        BasicOCSPResp basicOcspResp = new BasicOCSPResp(basicOCSPResponse);
        ocspRef.setProducedAt(new Time(basicOcspResp.getProducedAt().getTime()));
        // ResponderIDType responderId = new ResponderIDType();
        RespID responderIdEncoded = basicOcspResp.getResponderId();
        ASN1Object responderIdChoice = responderIdEncoded.toASN1Primitive();
        DERTaggedObject responderIdTaggedObject = (DERTaggedObject) responderIdChoice;
        if (responderIdTaggedObject.getTagNo() == 1) {
            try {
                ocspRef.setResponderName(new String(responderIdTaggedObject.getEncoded()));
            } catch (IOException ioException) {
                throw new SignatureAttributeException("Não foi possível codificar a resposta OCSP", ioException.getStackTrace());
            }
        } else {
            try {
                ocspRef.setResponderKey(responderIdTaggedObject.getEncoded());
            } catch (IOException ioException) {
                throw new SignatureAttributeException("Não foi possível codificar a resposta OCSP", ioException.getStackTrace());
            }
        }
        // ocspIdentifier.setResponderID(responderId);
        // ocspRef.setOCSPIdentifier(ocspIdentifier);
        ocspRef.setAlgorithm(algorithm);
        //byte[] ocspDigestValue = null;
        MessageDigest digester = null;
        try {
            digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm));
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException("O Algoritmo de hash não é conhecido: " + algorithm,
                    noSuchAlgorithmException.getStackTrace());
        }
        try {
           // ocspDigestValue = digester.digest(basicOCSPResponse.getEncoded());
        	basicOCSPResponse.getEncoded();
        } catch (IOException ioException) {
            throw new SignatureAttributeException("Não foi possível codificar a resposta OCSP", ioException.getStackTrace());
        }
        // ocspDigest.setDigestValue(ocspDigestValue);
        // ocspRef.setDigestAlgAndValue(ocspDigest);
        this.ocspRefs.add(ocspRef);
    }

    /**
     * Atribue as CRLs à lista de referências CRLs
     * @param crls A lista de CRLs
     * @param algorithm O algoritmo da referência
     * @throws SignatureAttributeException
     */
    private void makeCrlRefList(List<X509CRL> crls, String algorithm) throws SignatureAttributeException {
        if (crls == null || crls.size() == 0)
            throw new SignatureAttributeException("Não se deve usar esse construtor se não há LCRs para serem referenciadas");
        this.crlRefs = new ArrayList<CRLRefs>();
        for (X509CRL crl : crls) {
            this.makeCrlReference(algorithm, crl);
        }
    }

    /**
     * Adiciona a CRL à lista de referências de CRLs
     * @param algorithm O algoritmo da referência
     * @param crl A CRL
     * @throws SignatureAttributeException
     */
    private void makeCrlReference(String algorithm, X509CRL crl) throws SignatureAttributeException {
        CRLRefs crlRef = new CRLRefs();
        crlRef.setName(crl.getIssuerX500Principal().toString());
        crlRef.setIssueTime(new Time(crl.getThisUpdate().getTime()));

        Set<String> nonCriticalExtensions = crl.getNonCriticalExtensionOIDs();
        if (nonCriticalExtensions.contains("2.5.29.20")) {
            BigInteger crlNumber = new BigInteger(crl.getExtensionValue("2.5.29.20"));
            crlRef.setCrlNumber(crlNumber);
        }
        crlRef.setAlgorithm(algorithm);
        MessageDigest digester = null;
        byte[] hash = null;
        try {
            digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm));
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            throw new SignatureAttributeException("O Algoritmo de hash não é conhecido: " + algorithm,
                    noSuchAlgorithmException.getStackTrace());
        }
        try {
            hash = digester.digest(crl.getEncoded());
        } catch (CRLException crlException) {
            throw new SignatureAttributeException("Não foi possível codificar a crl", crlException.getStackTrace());
        }
        crlRef.setDigestValue(new String(Base64.encode(hash)));
        this.crlRefs.add(crlRef);
    }

    // private XMLGregorianCalendar getXmlGregorianCalendarFromDate(Time time)
    // throws SignatureAttributeException
    // {
    // GregorianCalendar gregorianCalendar = new GregorianCalendar();
    // gregorianCalendar.setTime(time);
    // DatatypeFactory datatypeFactory;
    // try {
    // datatypeFactory = DatatypeFactory.newInstance();
    // } catch (DatatypeConfigurationException datatypeConfigurationException) {
    // SignatureAttributeException signatureAttributeException = new
    // SignatureAttributeException("Não foi possível obter a data de emissão da crl",
    // datatypeConfigurationException.getStackTrace());
    // signatureAttributeException.setCritical(this.isSigned());
    // throw signatureAttributeException;
    // }
    // XMLGregorianCalendar xmlGregorianCalendar =
    // datatypeFactory.newXMLGregorianCalendar(gregorianCalendar);
    // return xmlGregorianCalendar;
    // }

    /**
     * <p>
     * Identificador do atributo, neste caso o nome de uma tag XML.
     * </p>
     * @return O identificador do atributo
     */
    @Override
    public String getIdentifier() {
        return AttributeRevocationRefs.IDENTIFIER;
    }

    /**
     * <p>
     * Método que verifica a validade deste atributo, usado somente na
     * verificação.
     * </p>
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
            boolean hasAtLeastOneAttributecertificateRevocable = false;
            NodeList attributeCertificateNodeList = signerRoleElement.getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                    "CertifiedRole");
            for (int i = 0; i < attributeCertificateNodeList.getLength(); i++) {
                if (attributeCertificateNodeList.item(i).getTextContent() != null) {
                    byte[] attributeCertificateBytes = Base64.decode(attributeCertificateNodeList.item(i).getTextContent().getBytes());
                    ASN1Sequence sequence;
                    try {
                        sequence = (ASN1Sequence) DERSequence.fromByteArray(attributeCertificateBytes);
                    } catch (IOException ioException) {
                        SignatureAttributeException signatureAttributeException = new SignatureAttributeException(this.getIdentifier()
                                + ": Não foi possível obter o Certificado de Atributo.", ioException.getStackTrace());
                        signatureAttributeException.setCritical(this.isSigned());
                        throw signatureAttributeException;
                    }
                    AttributeCertificate attributeCertificate = AttributeCertificate.getInstance(sequence);
                    AttributeCertificateInfo attrCertificateInfo = attributeCertificate.getAcinfo();
                    Extensions extensions = attrCertificateInfo.getExtensions();
                    if (extensions != null) {
                        String noRevocationAvailableOid = "2.5.29.56";
                        ASN1ObjectIdentifier noRevocationAvailableIdentifier = new ASN1ObjectIdentifier(noRevocationAvailableOid);
                        Extension noRevocationAvailable = extensions.getExtension(noRevocationAvailableIdentifier);
                        if (noRevocationAvailable == null) {
                            hasAtLeastOneAttributecertificateRevocable = true;
                        }
                    } else
                        hasAtLeastOneAttributecertificateRevocable = true;
                }
            }
            if (!hasAtLeastOneAttributecertificateRevocable) {
                SignatureAttributeException signatureAttributeException = new SignatureAttributeException(this.getIdentifier()
                        + ": A assinatura não contém nenhum Certificado de Atributo revogável.");
                signatureAttributeException.setCritical(this.isSigned());
                throw signatureAttributeException;
            }
        }
    }

    /**
     * <p>
     * Obtem a estrutura do atributo para adiciona à assinatura.
     * </p>
     * @return O atributo em formato de nodo XML
     */
    @Override
    public Element getEncoded() throws SignatureAttributeException {

        Document document = null;
        try {
            document = DocumentBuilderFactory.newInstance().newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new SignatureAttributeException("Problema em construir o documento", e.getStackTrace());
        }

        Element completeRevocationRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:AttributeRevocationRefs");

        if (!this.crlRefs.isEmpty()) {
            Element crlRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CRLRefs");
            completeRevocationRefs.appendChild(crlRefs);
            for (CRLRefs ref : this.crlRefs) {
                Element crlRef = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CRLRef");
                crlRefs.appendChild(crlRef);
                Element digestAlgAndValue = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:DigestAlgAndValue");
                crlRef.appendChild(digestAlgAndValue);

                Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
                digestAlgAndValue.appendChild(digestMethod);
                digestMethod.setAttribute("Algorithm", ref.getAlgorithm());

                Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
                digestAlgAndValue.appendChild(digestValue);
                digestValue.setTextContent(ref.getDigestValue());

                Element crlIdentifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:CRLIdentifier");
                crlRef.appendChild(crlIdentifier);

                Element issuer = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Issuer");
                crlIdentifier.appendChild(issuer);

                Element issueTime = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:IssueTime");
                SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss");
                dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
                issueTime.setTextContent(dateFormatGmt.format(ref.getDate()));
                crlIdentifier.appendChild(issueTime);

                Element number = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:Number");
                crlIdentifier.appendChild(number);
                number.setTextContent(ref.getCrlNumber().toString());
            }
        }

        if (this.ocspRefs != null && !this.ocspRefs.isEmpty()) {
            Element ocspRefs = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:OCSPRefs");
            completeRevocationRefs.appendChild(ocspRefs);
            for (OCSPRefs ref : this.ocspRefs) {
                Element ocspRef = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:OCSPRef");
                ocspRefs.appendChild(ocspRef);

                Element ocspIdentifier = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:OCSPIdentifier");
                ocspRef.appendChild(ocspIdentifier);
                Element responderID = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ResponderID");
                ocspIdentifier.appendChild(responderID);
                if (!ref.isKeyName()) {
                    Element byName = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ByName");
                    responderID.appendChild(byName);
                    byName.setTextContent(ref.getResponderName());
                } else {
                    Element byKey = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ByKey");
                    responderID.appendChild(byKey);
                    byKey.setTextContent(new String(Base64.encode(ref.getResponderKey())));
                }

                Element producedAt = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:ProducedAt");
                SimpleDateFormat dateFormatGmt = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss");
                dateFormatGmt.setTimeZone(TimeZone.getTimeZone("GMT"));
                producedAt.setTextContent(dateFormatGmt.format(ref.getProducedAt()));
                ocspIdentifier.appendChild(producedAt);

                Element digestAlgAndValue = document.createElementNS(NamespacePrefixMapperImp.XADES_NS, "XAdES:DigestAlgAndValue");
                ocspRef.appendChild(digestAlgAndValue);

                Element digestMethod = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestMethod");
                digestMethod.setAttribute("Algorithm", ref.getAlgorithm());
                digestAlgAndValue.appendChild(digestMethod);

                Element digestValue = document.createElementNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:DigestValue");
                digestValue.setTextContent(ref.getDigestValue());
                digestAlgAndValue.appendChild(digestValue);

            }
        }

        return completeRevocationRefs;

        // if (this.crlRefs == null && this.crlRefs == null)
        // throw new
        // SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE
        // + this.getIdentifier() +
        // ". O atributo deve conter pelos menos um valor.");
        //
        // CompleteRevocationRefsType completeRevocationRefsType = new
        // CompleteRevocationRefsType();
        // completeRevocationRefsType.setCRLRefs(this.crlRefs);
        // completeRevocationRefsType.setOCSPRefs(this.ocspRefs);
        // Element attributeRevocationRefs;
        // try {
        // attributeRevocationRefs =
        // Marshaller.marshallAttribute(this.getIdentifier(),
        // CompleteRevocationRefsType.class,
        // completeRevocationRefsType,NamespacePrefixMapperImp.XADES_NS);
        // } catch (XmlProcessingException xmlProcessingException) {
        // throw new
        // SignatureAttributeException(xmlProcessingException.getMessage(),
        // xmlProcessingException.getStackTrace());
        // }
        // return attributeRevocationRefs;
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
