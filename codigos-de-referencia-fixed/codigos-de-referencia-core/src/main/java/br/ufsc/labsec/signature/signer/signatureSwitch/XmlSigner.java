package br.ufsc.labsec.signature.signer.signatureSwitch;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.xml.XmlSignatureContainer;
import br.ufsc.labsec.signature.exceptions.VerificationException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner.*;
import br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner.XmlDetachedContainerGenerator;
import br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner.XmlEnvelopedContainerGenerator;
import br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner.XmlEnvelopingContainerGenerator;
import br.ufsc.labsec.signature.signer.signatureSwitch.xmlSigner.XmlContainerGenerator;

import org.apache.commons.io.IOUtils;
import org.apache.commons.io.input.NullInputStream;
import org.xml.sax.SAXException;

import java.io.IOException;
import java.io.InputStream;
import java.security.*;
import java.security.cert.Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.logging.Level;

import javax.xml.crypto.MarshalException;
import javax.xml.crypto.dsig.XMLSignatureException;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPathExpressionException;

/**
 * Esta classe gera assinaturas no formado XML.
 */
public class XmlSigner extends SignatureDataWrapperGenerator implements Signer {

    /**
     * Chave privada do assinante
     */
    protected PrivateKey privateKey;
    /**
     * Cadeia de certificados do assinante
     */
    protected Certificate[] certificateChain;
    /**
     * Componente de assinatura XML
     */
    private XmlSignatureComponent xmlSignatureComponent;
    /**
     * Gerador de contêineres de assinaturas XML
     */
    private XmlContainerGenerator xmlContainerGenerator;
    /**
     * Contêiner de assinatura XML
     */
    private XmlSignatureContainer container;
    /**
     * Mapa que relaciona os modos de assinatura com sua respectiva classe geradora
     */
    private HashMap<FileFormat, XmlContainerGenerator> mapFormats;
    /**
     * URL do arquivo a ser assinado no modo destacado
     */
    private String url;
    /**
     * O arquivo a ser assinado
     */
    private InputStream target;
    /**
     * O nome arquivo a ser assinado
     */
    private String filename;
    /**
     * Política a ser utilizada na assinatura
     */
    private String policyOid;
    /**
     * Modo de assinatura
     */
    private FileFormat format;
    /**
     * Suite da assinatura
     */
    private String suite;

    /**
     * Construtor
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlSigner(XmlSignatureComponent xmlSignatureComponent) {
        this.xmlSignatureComponent = xmlSignatureComponent;
        generateMapFormats();
    }

    /**
     * Atribue os valores de chave privada e certificado do assinante para a realização da assinatura
     * @param keyStore {@link KeyStore} que contém as informações do assinante
     * @param password Senha do {@link KeyStore}
     */
    public void selectInformation(KeyStore keyStore, String password) throws KeyStoreException {
        String alias = SwitchHelper.getAlias(keyStore);
        this.privateKey = SwitchHelper.getPrivateKey(keyStore, alias, password.toCharArray());
        this.certificateChain = keyStore.getCertificateChain(alias);
    }

    /**
     * Inicializa o gerador de contêiner de assinatura
     * @param target O arquivo que será assinado
     * @param policyOid OID da política de assinatura utilizada
     */
    public void selectTarget(InputStream target, String policyOid) {
        this.target = target;
        this.policyOid = policyOid;
        createXmlContainerGenerator();
    }

    /**
     Realiza a assinatura sobre o arquivo dado
     * @param filename Caminho do arquivo a ser assinado
     * @param target O arquivo a ser assinado
     * @param policyOid Política a ser utilizada na assinatura
     * @return  O arquivo assinado
     */
    @Override
    public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyOid) {
        this.filename = filename;
        selectTarget(target, policyOid.toString());
        if (xmlContainerGenerator != null) {
            sign();
            InputStream stream = getSignatureStream();
            SignatureDataWrapper signature;

            signature = new SignatureDataWrapper(stream, null, filename);

            return signature;
        }
        return null;
    }

    public SignatureDataWrapper getSignature(String filename, String target, SignerType policyOid) {
        selectTarget(target, policyOid.toString());
        if (xmlContainerGenerator != null) {
            sign();
            InputStream stream = getSignatureStream();
            SignatureDataWrapper signature = new SignatureDataWrapper(new NullInputStream(0), stream, filename);
            return signature;
        }
        return null;
    }

    /**
     Realiza a assinatura sobre o arquivo dado
     * @param filename Caminho do arquivo a ser assinado
     * @param toBeSigned O arquivo a ser assinado (pode ser nulo)
     * @param policy Política a ser utilizada na assinatura
     * @param url A URL do arquivo a ser assinado (pode ser nula ou vazia)
     * @return  O arquivo assinado
     */
    public SignatureDataWrapper getSignature(String filename, InputStream toBeSigned, SignerType policy, String url) {
        if (url != null && !url.equals("")) {
           return this.getSignature(filename, url, policy);
        }
        return this.getSignature(filename, toBeSigned, policy);
    }

    /**
     * Inicializa o gerador de contêineres de assinaturas XML
     */
    public void createXmlContainerGenerator() {
        this.xmlContainerGenerator = mapFormats.get(format);
        this.xmlContainerGenerator.setSignatureSuite(suite);
    }

    /**
     * Inicializa o mapa de modos de assinatura
     */
    private void generateMapFormats() {
        mapFormats = new HashMap<>();
        mapFormats.put(FileFormat.ATTACHED, new XmlEnvelopedContainerGenerator(xmlSignatureComponent));
        mapFormats.put(FileFormat.DETACHED, new XmlDetachedContainerGenerator(xmlSignatureComponent));
        mapFormats.put(FileFormat.ENVELOPED, new XmlEnvelopingContainerGenerator(xmlSignatureComponent));
        mapFormats.put(FileFormat.INTERNALLY_DETACHED, new XmlInternallyDetachedContainerGenerator(xmlSignatureComponent));
    }

    /**
     * Inicializa o gerador de contêiner de assinatura
     * @param url URL do arquivo a ser assinado
     * @param policyOid OID da política de assinatura utilizada
     */
    @Override
    public void selectTarget(String url, String policyOid) {
        this.url = url;
        this.policyOid = policyOid;
        createXmlContainerGenerator();
    }

    /**
     * Realiza a assinatura
     * @return Indica se o processo de assinatura foi concluído com sucesso
     */
    @Override
    public boolean sign() {
        if (this.xmlContainerGenerator != null) {
            try {
                if (this.format.equals(FileFormat.DETACHED) && (url != null && !url.equals(""))) {
                    this.container = xmlContainerGenerator.generate(url, privateKey, certificateChain);
                } else {
                    this.container = xmlContainerGenerator.generate(target, privateKey, certificateChain);
                }
            } catch (VerificationException | MarshalException | XMLSignatureException | ParserConfigurationException | XPathExpressionException e) {
                Application.logger.log(Level.SEVERE, "Não foi possível gerar a assinatura XML.", e);
            }
            return this.container != null;
        }
        return false;
    }

    /**
     * Retorna o arquivo assinado
     * @return O {@link InputStream} do arquivo assinado
     */
    @Override
    public InputStream getSignatureStream() {
        return this.container.getStream();
    }

    /**
     * Salva a assinatura gerada
     * @return Indica se a assinatura foi salva com sucesso
     */
    @Override
    public boolean save() {
        return false;
    }

    /**
     * Adiciona um atributo à assinatura
     * @param attribute O atributo a ser selecionado
     */
    @Override
    public void selectAttribute(String attribute) {

    }

    /**
     * Remove um atributo da assinatura
     * @param attribute O atributo a ser removido
     */
    @Override
    public void unselectAttribute(String attribute) {

    }

    /**
     * Retorna a lista de atributos disponíveis da assinatura
     * @return A lista de atributos disponíveis da assinatura
     */
    @Override
    public List<String> getAttributesAvailable() {
        return null;
    }

    /**
     * Retorna a lista dos tipos de assinatura disponíveis
     * @return Lista dos tipos de assinatura disponíveis
     */
    @Override
    public List<String> getAvailableModes() {
        return null;
    }

    /**
     * Retorna a lista de atributos assinados obrigatórios da assinatura
     * @return A lista de atributos assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedSignedAttributeList() {
        return null;
    }

    /**
     * Atribue o tipo de assinatura, anexada ou destacada
     * @param mode O tipo da assinatura
     */
    @Override
    public void setMode(FileFormat mode, String suite) {
        this.format = mode;
        this.suite = suite;
    }

    /**
     * Retorna a lista de atributos assinados disponíveis para a assinatura
     * @return A lista de atributos assinados disponíveis para a assinatura
     */
    @Override
    public List<String> getSignedAttributesAvailable() {
        return null;
    }

    /**
     * Retorna a lista de atributos não-assinados disponíveis para a assinatura
     * @return A lista de atributos não-assinados disponíveis para a assinatura
     */
    @Override
    public List<String> getUnsignedAttributesAvailable() {
        return null;
    }

    /**
     * Retorna a lista de políticas de assinatura disponiveis
     * @return A lista de políticas de assinatura
     */
    @Override
    public List<String> getPoliciesAvailable() {
        return null;
    }

    /**
     * Retorna a lista de atributos não assinados obrigatórios da assinatura
     * @return A lista de atributos não assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedUnsignedAttributeList() {
        return null;
    }

    /**
     * Retorna o nome do arquivo a ser assinado
     * @return O nome do arquivo a ser assinado
     */
    public String getFilename() {
        return filename;
    }

    @Override
    public boolean supports(InputStream target, SignerType signerType) throws CertificationPathException, SignerException {
        if (target == null) return true;

        byte[] targetBytes = new byte[0];
        try {
            targetBytes = IOUtils.toByteArray(target);
            target.reset();
        } catch (Exception e) {
            Application.logger.log(Level.INFO, e.getMessage(), e);
        }
        if (targetBytes.length > 0) {
            try {
                DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
                factory.setNamespaceAware(true);
                DocumentBuilder builder = factory.newDocumentBuilder();
                builder.parse(target);
                target.reset();
                return true;
            } catch (ParserConfigurationException | SAXException | IOException | NullPointerException e) {
                Application.logger.log(Level.SEVERE, "Ocorreu um erro ao processar o arquivo de XML.", e);
                throw new SignerException(SignerException.MALFORMED_TBS_FILE);
            }
        }

        return true;
    }
}