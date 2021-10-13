package br.ufsc.labsec.signature.signer.PolicyStorage;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesSigner;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.ServletStorage.SignatureChain;
import br.ufsc.labsec.signature.signer.ServletStorage.SignerRequestInformation;
import br.ufsc.labsec.signature.signer.SignerType;
import org.apache.commons.io.IOUtils;

import br.ufsc.labsec.signature.signer.signatureSwitch.CmsSigner;
import br.ufsc.labsec.signature.signer.signatureSwitch.PdfSigner;
import br.ufsc.labsec.signature.signer.signatureSwitch.XmlSigner;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.util.List;
import java.util.logging.Level;

/**
 * Esta classe é um componente responsável por lidar com o processo de assinatura, utilizando o assinador
 * correpondente ao tipo e modo de assinatura desejada.
 */
public final class StamperComponent extends Component {

    // Signers
    @Requirement
    public List<Signer> signers;

    /**
     * Retorna uma instância de assinador CMS
     * @return Uma instância de assinador CMS
     */
    private CmsSigner getCmsSigner() {
        return (CmsSigner) signers.stream().filter(p -> p instanceof CmsSigner).iterator().next();
    }

    /**
     * Retorna uma instância de assinador XML
     * @return Uma instância de assinador XML
     */
    private XmlSigner getXmlSigner() {
        return (XmlSigner) signers.stream().filter(p -> p instanceof XmlSigner).iterator().next();
    }

    /**
     * Retorna uma instância de assinador PDF
     * @return Uma instância de assinador PDF
     */
    private PdfSigner getPdfSigner() {
        return (PdfSigner) signers.stream().filter(p -> p instanceof PdfSigner).iterator().next();
    }

    /**
     * Retorna uma instância de assinador CAdES
     * @return Uma instância de assinador CAdES
     */
    private CadesSigner getCadesSigner() {
        return (CadesSigner) signers.stream().filter(p -> p instanceof CadesSigner).iterator().next();
    }

    /**
     * Retorna uma instância de assinador XAdES
     * @return Uma instância de assinador XAdES
     */
    private XadesSigner getXadesSigner() {
        return (XadesSigner) signers.stream().filter(p -> p instanceof XadesSigner).iterator().next();
    }

    /**
     * Retorna uma instância de assinador PAdES
     * @return Uma instância de assinador PAdES
     */
    private PadesSigner getPadesSigner() {
        return (PadesSigner) signers.stream().filter(p -> p instanceof PadesSigner).iterator().next();
    }

    // Target information
    /**
     * Nome do arquivo a ser assinado
     */
    private String filename;
    /**
     * Política a ser utilizada na assinatura
     */
    private SignerType policy;
    /**
     * Arquivo a ser assinado
     */
    private InputStream toBeSigned;
    /**
     * Senha do {@link KeyStore} do assinante
     */
    private String password;
    /**
     * Informações da chave do assinante
     */
    private KeyStore keyStore;
    /**
     * Modo de assinatura
     */
    private FileFormat format;
    /**
     * Suite da assinatura
     */
    private String suite;
    private String reason;
    private String location;
    /**
     * URL do arquivo a ser assinado em caso de assinatura XML ou XAdES destacada
     */
    private String url;

    /**
     * Todos os componentes são criados por uma aplicação. A aplicação está dispónivel
     * para as implementações dos componentes para que essas implementações
     * possam acessar os parâmetros e os controles básicos da aplicação.
     *
     * @param application Instância da aplicação
     */
    public StamperComponent(Application application) {
        super(application);
    }

    /**
     * Copia o {@link InputStream} dado
     * @param in O {@link InputStream} a ser copiado
     * @return A cópia gerada
     */
    private InputStream createResettableInputStream(InputStream in) {
        if (in != null) {
            try {
                return new ByteArrayInputStream(IOUtils.toByteArray(in));
            } catch (IOException ignored) {
            }
        }
        return new ByteArrayInputStream(new byte[0]);
    }

    /**
     * Assina os arquivos dados
     * @param signatureChainList A lista de informações dos arquivos a serem assinados
     */
    public void startStamp(List<SignatureChain> signatureChainList) {
        for (SignatureChain chain : signatureChainList) {
            try {
                chain.generateSignatureWithStamper(this);
            } catch (IOException e) {
                Application.logger.log(Level.SEVERE,
                        "Não foi possível realizar a assinatura.", e);
            }
        }
    }

    /**
     * Inicializa as informações da assinatura
     * @param filename Nome do arquivo a ser assinado
     * @param signerRequestInformation Informações sobre a assinatura
     * @param keyStore {@link KeyStore} do assinante
     * @param format Modo da assinatura
     * @throws IOException Exceção em caso de erro na obtenção do arquivo a ser assinado
     */
    public void selectTarget(String filename, SignerRequestInformation signerRequestInformation, KeyStore keyStore, FileFormat format, String suite) throws IOException {
        this.filename = filename;
        this.policy = signerRequestInformation.getSignaturePolicy();
        this.toBeSigned = createResettableInputStream(signerRequestInformation.getFileToBeSigned());
        this.password = signerRequestInformation.getCertificatePassword();
        this.keyStore = keyStore;
        this.format = format;
        this.suite = suite;
        this.reason = null;
        this.location = null;
        this.url = signerRequestInformation.getXmlUrl();
    }

    /**
     * Inicializa as informações da assinatura
     * @param filename Nome do arquivo a ser assinado
     * @param signerRequestInformation Informações sobre a assinatura
     * @param keyStore {@link KeyStore} do assinante
     * @param format Modo da assinatura
     * @param reason
     * @param location
     * @throws IOException Exceção em caso de erro na obtenção do arquivo a ser assinado
     */
    public void selectTarget(String filename, SignerRequestInformation signerRequestInformation, KeyStore keyStore, FileFormat format, String suite, String reason,
                             String location) throws IOException {
        selectTarget(filename, signerRequestInformation, keyStore, format, suite);
        this.reason = reason;
        this.location = location;
    }

    /**
     * Apaga as informações da assinatura
     */
    private void unselectTarget() {
        this.filename = null;
        this.policy = null;
        this.toBeSigned = null;
        this.password = null;
        this.keyStore = null;
        this.format = null;
        this.suite = null;
        this.reason = null;
        this.location = null;
        this.url = null;
        this.reason = null;
        this.location = null;
    }

    /**
     * Gera a assinatura e a adiciona na lista de assinaturas da aplicação
     */
    public void stamp() throws CertificationPathException, SignerException {
        try {
            SignatureDataWrapper dataWrapper = null;
            switch (this.policy) {
                case CMS:
                    CmsSigner cmsSigner = this.getCmsSigner();
                    cmsSigner.selectInformation(keyStore, password);
                    if (cmsSigner.supports(toBeSigned, policy)) {
                        cmsSigner.setMode(format, suite);
                        dataWrapper = cmsSigner.getSignature(filename, toBeSigned, policy);
                    }
                    break;
                case XML:
                    XmlSigner xmlSigner = this.getXmlSigner();
                    xmlSigner.selectInformation(keyStore, password);
                    if (xmlSigner.supports(toBeSigned, policy)) {
                        xmlSigner.setMode(format, suite);
                        dataWrapper = xmlSigner.getSignature(filename, toBeSigned, policy, url);
                    }
                    break;
                case PDF:
                    PdfSigner pdfSigner = getPdfSigner();
                    pdfSigner.selectInformation(keyStore, password);
                    if (pdfSigner.supports(toBeSigned, policy)) {
                        pdfSigner.setMode(null, suite);
                        dataWrapper = pdfSigner.getSignature(filename, toBeSigned, policy);
                    }
                    break;
                case CAdES:
                    CadesSigner cadesSigner = getCadesSigner();
                    cadesSigner.selectInformation(keyStore, password);
                    if (cadesSigner.supports(toBeSigned, policy)) {
                        cadesSigner.setMode(format, suite);
                        dataWrapper = cadesSigner.getSignature(filename, toBeSigned, policy);
                    }
                    break;
                case XAdES:
                    XadesSigner xadesSigner = getXadesSigner();
                    xadesSigner.selectInformation(keyStore, password);
                    if (xadesSigner.supports(toBeSigned, policy)) {
                        xadesSigner.setMode(format, suite);
                        dataWrapper = xadesSigner.getSignature(filename, toBeSigned, policy, url);
                    }
                    break;
                case PAdES:
                    PadesSigner padesSigner = getPadesSigner();
                    padesSigner.selectInformation(keyStore, password);
                    if (padesSigner.supports(toBeSigned, policy)) {
                        padesSigner.setMode(null, suite);
                        dataWrapper = padesSigner.getSignature(filename, toBeSigned, policy);
                    }
            }
            this.getApplication().getSignatureWrapperList().add(dataWrapper);
        } catch (KeyStoreException e) {
            Application.loggerInfo.log(Level.WARNING, "Erro ao assinar arquivo : " + e.getMessage());
        }
    }

    /**
     * Inicializa o componente
     */
    @Override
    public void startOperation() {
    }

    /**
     * Apaga as informações do componente
     */
    @Override
    public void clear() {
    }
}
