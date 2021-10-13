package br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureContainer;
import br.ufsc.labsec.signature.exceptions.VerificationException;
import br.ufsc.labsec.signature.signer.suite.SingletonSuiteMapper;

import org.apache.commons.io.input.NullInputStream;
import org.w3c.dom.Document;
import org.xml.sax.SAXException;
import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.*;
import javax.xml.crypto.dsig.keyinfo.KeyInfo;
import javax.xml.crypto.dsig.keyinfo.KeyInfoFactory;
import javax.xml.crypto.dsig.keyinfo.X509Data;
import javax.xml.crypto.dsig.spec.C14NMethodParameterSpec;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import javax.xml.xpath.XPathExpressionException;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.logging.Level;

/**
 * Esta classe gera contêineres de assinaturas no formato XML.
 */
public abstract class XmlContainerGenerator {

    protected static final SingletonSuiteMapper SUITE_MAPPER = SingletonSuiteMapper.getInstance();
    /**
     * Chave privada do assinante
     */
    protected PrivateKey privateKey;
    /**
     * Cadeia de certificados do assinante
     */
    protected Certificate[] certificateChain;
    /**
     * Fábrica de assinaturas XML
     */
    protected static XMLSignatureFactory signatureFactory = XMLSignatureFactory.getInstance("DOM");
    /**
     * Componente de assinatura XML
     */
    protected XmlSignatureComponent xmlSignatureComponent;
    /**
     * Suite da assinatura
     */
    protected String signatureSuite;

    /**
     * Construtor
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlContainerGenerator(XmlSignatureComponent xmlSignatureComponent) {
        this.xmlSignatureComponent = xmlSignatureComponent;
    }

    /**
     * Atribue os valores de chave privada e cadeia de certificado do assinante
     * @param privateKey Chave privada do assinante
     * @param certificateChain Cadeia de certificados do assinante
     */
    private void selectInformation(PrivateKey privateKey, Certificate[] certificateChain) {
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
    }

    /**
     * Gera o contêiner de assinatura XML
     * @param inputStream O arquivo a ser assinado
     * @param privateKey Chave privada do assinante
     * @param certificateChain Cadeia de certificados do assinante
     * @return O contêiner de assinatura XML
     * @throws MarshalException Exceção quando há erro na manipulação da estrututra XML
     * @throws XMLSignatureException Exceção quando há erro durante o processo de assinatura
     */
    public XmlSignatureContainer generate(InputStream inputStream, PrivateKey privateKey, Certificate[] certificateChain) throws MarshalException, XMLSignatureException, ParserConfigurationException, XPathExpressionException, VerificationException {
        selectInformation(privateKey, certificateChain);
        InputStream signature = sign(inputStream);
        return new XmlSignatureContainer(signature, new NullInputStream(0), xmlSignatureComponent);
    }

    /**
     * Gera o contêiner de assinatura XML
     * @param url URL do arquivo a ser assinado no modo destacado
     * @param privateKey Chave privada do assinante
     * @param certificateChain Cadeia de certificados do assinante
     * @return O contêiner de assinatura XML
     * @throws MarshalException Exceção quando há erro na manipulação da estrututra XML
     * @throws XMLSignatureException Exceção quando há erro durante o processo de assinatura
     */
    public XmlSignatureContainer generate(String url, PrivateKey privateKey, Certificate[] certificateChain) throws MarshalException, XMLSignatureException, VerificationException {
        selectInformation(privateKey, certificateChain);
        InputStream signature = sign(url);
        return new XmlSignatureContainer(signature, new NullInputStream(0), xmlSignatureComponent);
    }

    /**
     * Realiza a assinatura
     * @return Retorna se a assinatura foi feita com sucesso
     */
    public boolean sign() {
        return false;
    }

    /**
     * Realiza a assinatura
     * @param in O arquivo a ser assinado
     * @return Retorna se a assinatura foi feita com sucesso
     */
    protected InputStream sign(InputStream in)
            throws MarshalException, XMLSignatureException, XPathExpressionException, ParserConfigurationException {
        return null;
    }

    /**
     * Realiza a assinatura
     * @param url A URL do arquivo a ser assinado no modo destacado
     * @return Retorna se a assinatura foi feita com sucesso
     */
    protected InputStream sign(String url) throws MarshalException, XMLSignatureException { return null; }

    /**
     * Gera a referência da assinatura
     * @return A referência gerada
     */
    public Reference buildReference() { return null; }

    /**
     * Constrói as informações do assinante a partir da referência dada
     * @param reference A referência
     * @return As informações do assinante
     */
    public SignedInfo buildSignedInfo(Reference reference) {
        SignedInfo signedInfo = null;
        String algorithm = SUITE_MAPPER.signatureAlgorithms.get(signatureSuite);
        try {
            signedInfo = signatureFactory.newSignedInfo
                    (signatureFactory.newCanonicalizationMethod
                                    (CanonicalizationMethod.INCLUSIVE_WITH_COMMENTS,
                                            (C14NMethodParameterSpec) null),
                            signatureFactory.newSignatureMethod(algorithm, null),
                            Collections.singletonList(reference));
        } catch (InvalidAlgorithmParameterException | NoSuchAlgorithmException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }

        return signedInfo;
    }

    /**
     * Constrói as informações de chave da assinatura
     * @return O objeto {@link KeyInfo} gerado
     */
    protected KeyInfo buildKeyInfo() {
        X509Certificate certificate = (X509Certificate) certificateChain[0];
        List<Object> x509Content = Arrays.asList(certificate.getSubjectX500Principal().getName(), certificate);

        KeyInfoFactory keyInfoFactory = signatureFactory.getKeyInfoFactory();
        X509Data x509Data = keyInfoFactory.newX509Data(x509Content);

        return keyInfoFactory.newKeyInfo(Collections.singletonList(x509Data));
    }

    /**
     * Constrói um novo documento com o conteúdo dado
     * @param inputStream O conteúdo XML
     * @return O documento gerado
     */
    protected Document buildDocument(InputStream inputStream) {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document document = null;

        try {
            document = documentBuilderFactory.newDocumentBuilder().parse(inputStream);
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }

        return document;
    }

    /**
     * Constrói um novo documento XML vazio
     * @return O documento gerado
     */
    protected Document buildEmptyDocument() {
        DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
        documentBuilderFactory.setNamespaceAware(true);
        Document document = null;

        try {
            document = documentBuilderFactory.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }
        return document;
    }

    /**
     * Realiza as transformações no documento XML
     * @param document O documento XML
     * @param outputStream O resultado da transformação
     */
    protected void transform(Document document, OutputStream outputStream) {
        try {
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            transformer.transform(new DOMSource(document), new StreamResult(outputStream));
        } catch (TransformerException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }
    }

    /**
     *
     */
    public void setSignatureSuite(String signatureSuite) {
        this.signatureSuite = signatureSuite;
    }
}