package br.ufsc.labsec.signature.conformanceVerifier.xml;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xades.NamespacePrefixMapperImp;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.NullInputStream;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.*;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * Esta classe representa um contêiner de assinaturas XML.
 */
@SuppressWarnings("rawtypes")
public class XmlSignatureContainer {

    /**
     * O arquivo XML assinado
     */
    protected Document xml;
    /**
     * Bytes do arquivo XMl assinado
     */
    private byte[] content;
    /**
     * Componente de assinatura XML
     */
    private XmlSignatureComponent xmlSignatureComponent;

    /**
     * Construtor
     * @param signatures Arquivo assinado
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlSignatureContainer(Document signatures, XmlSignatureComponent xmlSignatureComponent) {
        this.xml = signatures;
        this.xmlSignatureComponent = xmlSignatureComponent;
        this.setContent(new NullInputStream(0));
    }

    /**
     * Construtor
     * @param signatureContainer Stream de bytes do documento assinado
     * @param xmlSignatureComponent Componente de assinatura XML
     * @throws VerificationException Exceção caso os bytes do arquivo sejam inválidos
     */
    public XmlSignatureContainer(InputStream signatureContainer, InputStream detachedContainer, XmlSignatureComponent xmlSignatureComponent) throws VerificationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        try {
            DocumentBuilder builder = factory.newDocumentBuilder();
            this.xml = builder.parse(signatureContainer);
            this.xmlSignatureComponent = xmlSignatureComponent;
            this.setContent(detachedContainer);
        } catch (ParserConfigurationException e) {
            Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura.", e);
            throw new VerificationException(e);
        } catch (SAXException | IOException | NullPointerException e) {
            Application.loggerInfo.log(Level.WARNING, "Não foi possível abrir a assinatura como um org.w3c.dom.Document.");
            throw new VerificationException(e);
        }
    }

    /**
     * Construtor
     * @param target Caminho do documento de assinatura
     * @param signedContent Caminho do conteúdo que foi assinado
     * @param xmlSignatureComponent Componente de assinatura XML
     * @throws VerificationException Exceção caso os bytes do arquivo sejam inválidos
     */
    public XmlSignatureContainer(String target, String signedContent, XmlSignatureComponent xmlSignatureComponent) throws VerificationException {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        try {
            File signatureContainer = new File(target);
            DocumentBuilder builder = factory.newDocumentBuilder();
            this.xml = builder.parse(signatureContainer);
            this.xmlSignatureComponent = xmlSignatureComponent;
            this.setContent(new FileInputStream(new File(signedContent)));
        } catch (ParserConfigurationException | IOException | SAXException e) {
            Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura.", e);
            throw new VerificationException(e);
        }
    }

    /**
     * Inicializa os bytes do arquivo assinado através do valor do atributo {@see xml}
     */
    private void setContent(InputStream contentStream) {
        byte[] contentBytes = new byte[0];
        try {
            contentBytes = IOUtils.toByteArray(contentStream);
            contentStream.reset();
        } catch (IOException e) {
            Application.logger.log(Level.WARNING, e.getMessage());
        }
        if (contentBytes.length > 0) {
            this.content = contentBytes;
        } else {
            try {
                Transformer transformer = TransformerFactory.newInstance().newTransformer();
                ByteArrayOutputStream output = new ByteArrayOutputStream();
                transformer.transform(new DOMSource(this.xml), new StreamResult(output));
                this.content = output.toByteArray();
            } catch (TransformerException e) {
                Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar a assinatura.", e);
            }
        }
    }

    /**
     * Retorna os bytes do arquivo
     * @return Os bytes do arquivo assinado
     */
    byte[] getContent() {
        return this.content;
    }

    /**
     * Retorna o arquivo em formato InputStream
     * @return O arquivo em formato InputStream
     */
    public InputStream getStream() {
        return new ByteArrayInputStream(this.content);
    }

    /**
     * Retorna as assinaturas no arquivo
     * @return As assinaturas no arquivo
     */
    public List<XmlSignature> getSignatures() {
        List<XmlSignature> signatures = new ArrayList<XmlSignature>();
        NodeList signatureList = this.xml.
                getElementsByTagNameNS(NamespacePrefixMapperImp.XMLDSIG_NS, "Signature");
        if (signatureList.getLength() == 0) {
            signatureList = this.xml.getElementsByTagName("Signature");
        }

        for (int i = 0; i < signatureList.getLength(); i++) {
            Element signatureElement = (Element) signatureList.item(i);
            signatures.add(new XmlSignature(this.xml, signatureElement, this, this.xmlSignatureComponent));
        }
        return signatures;
    }

    /**
     * Verifica se o arquivo possui alguma assinatura com conteúdo destacado
     * @return Indica se o arquivo possui conteúdo destacado
     */
    public boolean hasDetachedContent() {
        for (XmlSignature sig : this.getSignatures()) {
            if (sig.isExternalSignedData()) {
                return true;
            }
        }
        return false;
    }

    /**
     * Retorna o arquivo em formato OutputStream
     * @param outputStream Stream no qual será colocado o valor do arquivo de assinatura
     * @throws EncodingException Exceção caso haja algum problema na conversão dos dados
     *         do arquivo para o stream
     */
    public void encode(OutputStream outputStream) throws EncodingException {
        try {
            Transformer transformer = TransformerFactory.newInstance()
                    .newTransformer();
            transformer.transform(new DOMSource(this.xml), new StreamResult(
                    outputStream));
        } catch (Exception e) {
            throw new EncodingException(e);
        }
    }
}
