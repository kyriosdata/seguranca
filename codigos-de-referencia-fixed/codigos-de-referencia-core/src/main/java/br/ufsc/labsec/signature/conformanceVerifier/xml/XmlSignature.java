package br.ufsc.labsec.signature.conformanceVerifier.xml;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.CertificateCollection;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertRevReq;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.RevReq;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

import org.apache.commons.io.IOUtils;
import org.w3c.dom.*;

import javax.xml.crypto.*;
import javax.xml.crypto.dom.DOMStructure;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.dom.DOMValidateContext;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathConstants;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;
import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe representa uma assinatura XML.
 */
public class XmlSignature {

    /**
     * Constante "Type"
     */
    private static final String TYPE = "Type";
    /**
     * Constante "ds:Reference"
     */
    private static final String DS_REFERENCE = "ds:Reference";
    /**
     * Constante "SignedSignatureProperties"
     */
    private static final String SIGNED_SIGNATURE_PROPERTIES = "SignedSignatureProperties";
    /**
     * Constante "UnsignedSignatureProperties"
     */
    private static final String UNSIGNED_SIGNATURE_PROPERTIES = "UnsignedSignatureProperties";
    /**
     * Constante ":"
     */
    private static final String COLON = ":";
    /**
     * Constante "DOM"
     */
    private static final String DOM = "DOM";

    /**
     * O arquivo XML assinado
     */
    protected Document xml;
    /**
     * Nodo da assinatura no documento XML
     */
    protected Element signatureElement;
    /**
     * Contêiner de assinatura XML
     */
    private XmlSignatureContainer container;
    /**
     * Componente de assinatura XML
     */
    private XmlSignatureComponent xmlSignatureComponent;

    /**
     * Construtor
     * @param xml O documento XML assinado
     * @param signature O nodo de assinatura no documento
     * @param xmlSignatureContainer Contêiner de assinatura XML
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    protected XmlSignature(Document xml, Element signature, XmlSignatureContainer xmlSignatureContainer,
                           XmlSignatureComponent xmlSignatureComponent) {
        this.xml = xml;
        this.signatureElement = signature;
        this.container = xmlSignatureContainer;
        this.xmlSignatureComponent = xmlSignatureComponent;
    }

    /**
     * Retorna o nome do assinante
     * @return O nome do assinante
     */
    public String getSubjectName() {
        X509Certificate signerCertificate = this.getSigningCertificate();
        if (signerCertificate != null) {
            return signerCertificate.getSubjectX500Principal().toString();
        }

        return "";
    }

    /**
     * Retorna o certificado do assinante
     * @return O certificado do assinante
     */
    public X509Certificate getSigningCertificate() {
        X509Certificate signerCertificate = null;
        for (XmlSignature sig : this.container.getSignatures()) {
            signerCertificate = sig.getCertificatesAtKeyInfo().get(0);
        }

        return signerCertificate;
    }

    /**
     * Valida as informações da assinatura
     * @return O relatório da verificação
     */
    public SignatureReport validate() {
        SignatureReport report = new SignatureReport();

        X509CertSelector selector = new X509CertSelector();
        Element issuerSerialNumber = (Element) this.xml
                .getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509SerialNumber").item(0);
        Element issuerName = (Element) this.xml
                .getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS, "ds:X509IssuerName").item(0);
        if (issuerSerialNumber != null)
            selector.setSerialNumber(new BigInteger(issuerSerialNumber.getTextContent()));
        try {
            if (issuerName != null)
                selector.setIssuer(issuerName.getTextContent());
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, "Não foi possível decodificar o nome do assinante.", e);
        }

        X509Certificate signerCertificate = null;
        Iterator<CertificateCollection> it = this.xmlSignatureComponent.certificateCollection.iterator();

        do {
            signerCertificate = (X509Certificate) it.next().getCertificate(selector);
        } while (signerCertificate == null && it.hasNext());

        if (signerCertificate == null) {
            report.setSignerSubjectName("Assinante desconhecido");
        } else {
            report.setSignerSubjectName(signerCertificate.getSubjectX500Principal().toString());
            report.setPresenceOfInvalidAttributes(false);
            this.validateSignatureIntegrity(signerCertificate, report);
        }

        Set<TrustAnchor> trustAnchors = this.xmlSignatureComponent.trustAnchorInterface.getTrustAnchorSet();
        CertRevReq revocationReqs = new CertRevReq(RevReq.EnuRevReq.EITHER_CHECK, RevReq.EnuRevReq.EITHER_CHECK);
        Time timeReference = new Time(SystemTime.getSystemTime());

        CertificateValidation.ValidationResult certificateValidationResults = this.xmlSignatureComponent.certificatePathValidation
                .validate(signerCertificate, trustAnchors, revocationReqs, timeReference, report);

        report.verifyValidationResult(certificateValidationResults);
        report.setSchema(SignatureReport.SchemaState.VALID);

        return report;
    }

    /**
     * Valida as informações de hash e cifra assimétrica da assinatura.
     * Adiciona as informações no relatório passado por parâmetro
     * @param certificate Certificado utilizado na assinatura
     * @param report O relatório da verificação
     */
    private void validateSignatureIntegrity(X509Certificate certificate, SignatureReport report) {
        boolean valid = false;
        try {
            valid = this.verify(certificate, report);
        } catch (VerificationException e) {
            Application.logger.log(Level.SEVERE,"Não foi possível validar a integridade da assinatura", e);
        }
        report.setHash(valid);
        report.setAsymmetricCipher(valid);
    }

    /**
     * Valida as referências da assinatura XML. Adiciona as informações no relatório passado por parâmetro
     * @param signerCertificate O certificado utilizado na assinatura
     * @param report O relatório da verificação
     * @return Indica se as referências no documento são válidas
     * @throws VerificationException Exceção em caso problema na verificação, como problema no algoritmo da referência
     */
    private boolean verify(X509Certificate signerCertificate, SignatureReport report) throws VerificationException {
        boolean valid = true;
        try {
            DOMValidateContext validateContext = getDOMValidateContext(signerCertificate);
            XMLSignature xmlSignature = setDefaultNamespacePrefixAndUnmarchalSignature(validateContext);
            @SuppressWarnings("unchecked")
            List<Reference> references = xmlSignature.getSignedInfo().getReferences();

            boolean hasOneDetached = false;
            for (Reference reference: references) {
                if (isDetached(reference.getURI())) {
                    if (!hasOneDetached) {
                        hasOneDetached = true;
                    } else {
                        Application.logger.log(Level.SEVERE,
                                "Mais de um arquivo detached necessário",
                                new VerificationException(VerificationException.MORE_THAN_ONE_DETACHED_CONTENT));
                    }
                }
            }

            Iterator<Reference> i = references.iterator();
            Reference reference;
            boolean validReference;
            while (valid && i.hasNext()) {
                reference = i.next();
                validReference = false;
                if (isDetached(reference.getURI())) {
                    validReference = this.validateDetachedReference(reference);
                } else {
                    try {
                        // The ID attribute needs to be identified as such so that
                        // reference.validate(validateContext) can work properly
                        String uri = reference.getURI();
                        if (uri != null && uri.length() != 0 && uri.charAt(0) == '#') {
                            String id = uri.substring(1);

                            XPath xpath = XPathFactory.newInstance().newXPath();
                            NodeList referencedNodes = (NodeList) xpath.evaluate("//*[@Id='" + id + "']", this.xml, XPathConstants.NODESET);
                            if (referencedNodes != null) {
                                for (int j = 0; j < referencedNodes.getLength(); j++) {
                                    ((Element)referencedNodes.item(j)).setIdAttribute("Id", true);
                                }
                            }
                            referencedNodes = (NodeList) xpath.evaluate("//*[@ID='" + id + "']", this.xml, XPathConstants.NODESET);
                            if (referencedNodes != null) {
                                for (int j = 0; j < referencedNodes.getLength(); j++) {
                                    ((Element)referencedNodes.item(j)).setIdAttribute("ID", true);
                                }
                            }
                            referencedNodes = (NodeList) xpath.evaluate("//*[@id='" + id + "']", this.xml, XPathConstants.NODESET);
                            if (referencedNodes != null) {
                                for (int j = 0; j < referencedNodes.getLength(); j++) {
                                    ((Element)referencedNodes.item(j)).setIdAttribute("id", true);
                                }
                            }
                        }
                    } catch (XPathExpressionException e) {
                    }

                    validReference = reference.validate(validateContext);
                }
                report.addReferences(validReference);
                valid &= validReference;
            }

            if (references.isEmpty()) {
                report.setMessageDigest(null);
            } else {
                report.setMessageDigest(references.get(references.size()-1).getDigestValue());
            }

            if (valid) {
                XMLSignature.SignatureValue signatureValue = xmlSignature.getSignatureValue();
                valid = signatureValue.validate(validateContext);
            }
        } catch (MarshalException | XMLSignatureException
                | NoSuchAlgorithmException exception) {
            throw new VerificationException(exception);
        }

        return valid;
    }

    /**
     * Constrói um objeto {@see DOMValidateContext} para validação da árvore DOM da assinatura XML
     * @param signerCertificate O certificado a ser utilizado na construção
     * @return O objeto {@see DOMValidateContext}
     */
    private DOMValidateContext getDOMValidateContext(
            X509Certificate signerCertificate) {
        DOMValidateContext validateContext;
        if (signerCertificate != null) {
            validateContext = new DOMValidateContext(
                    signerCertificate.getPublicKey(), this.signatureElement);
        } else {
            validateContext = new DOMValidateContext(new KeySelector() {
                @Override
                public KeySelectorResult select(KeyInfo keyInfo,
                                                Purpose purpose, AlgorithmMethod method,
                                                XMLCryptoContext context) throws KeySelectorException {
                    throw new KeySelectorException(
                            "Não foi possível encontrar a chave do assinante.");
                }
            }, this.signatureElement);
        }
        return validateContext;
    }

    /**
     * Realiza o processo de unmarshal na assinatura e seta o prefixo dos nodos como o padrão XMLDsig
     * @param validateContext O contexto de validação do DOM para o unmarshal da assinatura
     * @return A assinatura XML após o processo
     * @throws MarshalException Exceção quando há algum problema durante o processo de unmarshal
     */
    private XMLSignature setDefaultNamespacePrefixAndUnmarchalSignature(
            DOMValidateContext validateContext) throws MarshalException {
        XMLSignatureFactory xmlSigFac = XMLSignatureFactory.getInstance(DOM);
        validateContext.setDefaultNamespacePrefix(NamespacePrefixMapperImp.XMLDSIG_NS);
        XMLSignature xmlSignature = xmlSigFac.unmarshalXMLSignature(validateContext);
        validateContext.setBaseURI(this.xml.getBaseURI());
        return xmlSignature;
    }

    /**
     * Verifica se a referência na assinatura aponta para um conteúdo destacado
     * @param uri A URI da referência
     * @return Indica se a referência na assinatura aponta para um conteúdo destacado
     */
    private boolean isDetached(String uri) {
        return uri.length() > 0 && uri.charAt(0) != '#';
    }

    /**
     * Valida o conteúdo destacado de uma referência
     * @param reference A referência que se deseja validar
     * @return Indica se a referência é válida
     * @throws NoSuchAlgorithmException Exceção caso o algoritmo da referência seja desconhecido
     */
    private boolean validateDetachedReference(Reference reference) throws NoSuchAlgorithmException {
        byte[] referenceDigestValue = reference.getDigestValue();
        MessageDigest digester = MessageDigest.getInstance(AlgorithmIdentifierMapper
                .getAlgorithmNameFromIdentifier(reference.getDigestMethod()
                        .getAlgorithm()));
        byte[] obtainedDigestValue = new byte[0];
        String uri = reference.getURI();

        if (uri.startsWith("http") || uri.startsWith("https")) {
            try {
				URL url = new URL(uri);
				HttpURLConnection connection = (HttpURLConnection) url.openConnection();
				InputStream stream = connection.getInputStream();
				obtainedDigestValue = digester.digest(IOUtils.toByteArray(stream));
			} catch (IOException e) {
				e.printStackTrace();
			}
		} else {
			obtainedDigestValue = digester.digest(this.container.getContent());
        }

		return MessageDigest.isEqual(referenceDigestValue, obtainedDigestValue);
    }

    /**
     * Verifica se a assinatura possui conteúdo externo
     * @return Indica se a assinatura possui conteúdo externo
     */
    public boolean isExternalSignedData() {
        NodeList referenceList = this.signatureElement.getElementsByTagName(DS_REFERENCE);
        Node tempNode;
        for (int i = 0; i < referenceList.getLength(); i++) {
            tempNode = referenceList.item(i);
            if (tempNode.getAttributes().getNamedItem(TYPE) == null) {
                if (isExternalReference(tempNode)) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Verifica se o nodo possui URI que indique conteúdo externo
     * @param tempNode O nodo a ser verificado
     * @return Indica se o nodo possui URI que indique conteúdo externo
     */
    private boolean isExternalReference(Node tempNode) {
        String uri = (tempNode.getAttributes().getNamedItem("URI").getTextContent());
        return !((uri.length() > 0 && uri.charAt(0) == '#')
                 || (uri.length() == 0));
    }

    /**
     * Retorna os certificados presentes no KeyInfo da assinatura XML
     * @param sig A assinatura a ser utilizada
     * @return A lista de certificados no KeyInfo da assinatura
     */
    private ArrayList<X509Certificate> getCertificatesOfKeyInfo(XMLSignature sig) {
        List<XMLStructure> keyInfoContent = sig.getKeyInfo().getContent();
        ArrayList<X509Certificate> certificates = new ArrayList<X509Certificate>();
        if (!keyInfoContent.isEmpty()) {
            for (Object x509Data : keyInfoContent) {
                if(x509Data instanceof X509Data) {
                    XadesSignature.addX509DataContent(certificates, null, (X509Data) x509Data);
                }
            }
        }
        return certificates;
    }

    /**
     * Retorna os certificados utilizados na assinatura através do nodo de assinatura no documento XML
     * @return A lista de certificados da assinatura
     */
    public List<X509Certificate> getCertificatesAtKeyInfo() {
        XMLSignatureFactory factory = XMLSignatureFactory.getInstance(DOM);
        XMLSignature sig = null;

        try {
            sig = factory.unmarshalXMLSignature(new DOMStructure(
                    signatureElement));
        } catch (MarshalException e) {
            Application.logger.log(Level.SEVERE,
                    "Problema na codificação da assinatura", e);
        }

        if (sig.getKeyInfo() != null) {
            return getCertificatesOfKeyInfo(sig);
        }

        return null;
    }

    /**
     * Retorna o nodo do atributo desejado
     * @param identifier O identificador do atributo
     * @return O nodo do atributo desejado
     * @throws SignatureAttributeNotFoundException Exceção caso o atributo não seja encontrado
     */
    public Element getEncodedAttribute(String identifier) throws SignatureAttributeNotFoundException {
        NodeList attributeNodeList = this.signatureElement
                .getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS, identifier);
        if (attributeNodeList.getLength() <= 0) {
            throw new SignatureAttributeNotFoundException(
                    SignatureAttributeNotFoundException.ATTRIBUTE_NOT_FOUND
                            + identifier);
        }
        Element attributeElement = (Element) attributeNodeList.item(0);
        return attributeElement;
    }

    /*
        Verifica se está assinatura em formato XML contém alguns atributos XAdES,
        para que seja possível diferenciar entre uma assinatura XAdES e uma XMLDsig.
     */
    /**
     * Retorna a lista de atributos da assinatura
     * @return A lista com os nomes dos atributos da assinatura
     */
    public List<String> getAttributeList() {
        List<String> attrList = new ArrayList<String>();

        NodeList signedSignatureProperties = this.signatureElement
                .getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                        SIGNED_SIGNATURE_PROPERTIES);
        if (signedSignatureProperties.getLength() > 0) {
            NodeList signedSignatureAttrs = signedSignatureProperties.item(0).getChildNodes();
            for (int i = 0; i < signedSignatureAttrs.getLength(); i++) {
                Element attrElement = (Element) signedSignatureAttrs.item(i);
                attrList.add(attrElement.getTagName().substring(
                        attrElement.getTagName().indexOf(COLON) + 1));
            }
        }

        if (attrList.size() == 0) {
            NodeList unsignedSignatureProperties = this.signatureElement
                    .getElementsByTagNameNS(NamespacePrefixMapperImp.XADES_NS,
                            UNSIGNED_SIGNATURE_PROPERTIES);
            if (unsignedSignatureProperties.getLength() > 0) {
                NodeList unsignedSignatureAttrs = unsignedSignatureProperties.item(
                        0).getChildNodes();
                for (int i = 0; i < unsignedSignatureAttrs.getLength(); i++) {
                    Element attrElement = (Element) unsignedSignatureAttrs.item(i);
                    attrList.add(attrElement.getTagName().substring(
                            attrElement.getTagName().indexOf(COLON) + 1));
                }
            }
        }
        return attrList;
    }
}
