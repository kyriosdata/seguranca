package br.ufsc.labsec.signature.signer.ServletStorage;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.PolicyStorage.StamperComponent;
import br.ufsc.labsec.signature.signer.SignerType;

import java.io.IOException;
import java.security.KeyStore;
import java.util.concurrent.Callable;
import java.util.logging.Level;

/**
 * Esta classe representa um conjunto de informações sobre uma assinatura a ser feita
 */
public class SignatureChain {

    /**
     * Informações do assinante
     */
    private final SignerRequestInformation signerRequestInformation;
    private final ServletUtilities.ErrorHandler onSignatureError;
    private final ServletUtilities.ErrorHandler onAlgorithmError;
    /**
     * {@link KeyStore} do assinante
     */
    private final KeyStore keyStore;

    /**
     * Construtor
     * @param signerRequestInformation Informações do assinante
     * @param keyStore {@link KeyStore} do assinante
     * @param onSignatureError Ações a serem tomadas em caso de erro no processo de assinatura
     */
    public SignatureChain(SignerRequestInformation signerRequestInformation,
                          KeyStore keyStore,
                          ServletUtilities.ErrorHandler onSignatureError,
                          ServletUtilities.ErrorHandler onAlgorithmError) {
        this.signerRequestInformation = signerRequestInformation;
        this.onSignatureError = onSignatureError;
        this.onAlgorithmError = onAlgorithmError;
        this.keyStore = keyStore;
    }

    /**
     * Construtor
     * @param signerRequestInformation Informações do assinante
     * @param keyStore {@link KeyStore} do assinante
     */
    public SignatureChain(SignerRequestInformation signerRequestInformation,
                          KeyStore keyStore) {
        this.signerRequestInformation = signerRequestInformation;
        this.onSignatureError = null;
        this.onAlgorithmError = null;
        this.keyStore = keyStore;
    }

    /**
     * Realiza a assinatura quando a mesma é destacada e sobre uma URL de arquivo
     * @param stamperComponent Componente de assinatura
     * @throws IOException Exceção em caso de erro na obtenção do arquivo a ser assinado
     */
    private void url(StamperComponent stamperComponent) throws IOException {
        FileFormat format = signerRequestInformation.getSignatureFormat();
        String suite = signerRequestInformation.getSignatureSuite();
        String fileFormat = ServletUtilities.fileExtension(signerRequestInformation.getSignaturePolicy());
        String xmlUrl = signerRequestInformation.getXmlUrl();
        String fileName = ServletUtilities.makeFileNameForXML(xmlUrl, fileFormat);
        try {
            stamperComponent.selectTarget(fileName, signerRequestInformation, keyStore, format, suite);
            stamperComponent.stamp();
        } catch (CertificationPathException | SignerException e) {
            Application.logger.log(Level.WARNING, e.getMessage());
            if (onSignatureError != null) {
                onSignatureError.setError(e);
                onSignatureError.handleError();
            }
        }
    }

    /**
     * Realiza a assinatura quando a mesma não é sobre uma URL. Apenas assinaturas XML e XAdES destacadas podem
     * referenciar URLs para serem assinadas
     * @param stamperComponent Componente de assinatura
     * @throws IOException Exceção em caso de erro na obtenção do arquivo a ser assinado
     */
    private void notUrl(StamperComponent stamperComponent) throws IOException {
        String pdfReason = null;
        String pdfLocation = null;

        SignerType sigPol = signerRequestInformation.getSignaturePolicy();
        if (sigPol.isPdf()) {
            pdfReason = signerRequestInformation.getPdfReason();
            pdfLocation = signerRequestInformation.getPdfLocation();
        }

        FileFormat format = signerRequestInformation.getSignatureFormat();
        String suite = signerRequestInformation.getSignatureSuite();
        String fileName = signerRequestInformation.getFilename();

        try {
            stamperComponent.selectTarget(fileName, signerRequestInformation, keyStore, format, suite, pdfReason, pdfLocation);
            stamperComponent.stamp();
        } catch (CertificationPathException | SignerException e) {
            Application.logger.log(Level.WARNING, e.getMessage());
            if (onSignatureError != null) {
                onSignatureError.setError(e);
                onSignatureError.handleError();
            }
        }
    }

    /**
     * Identifica se a assinatura é destacada e feita sobre uma URL e escolhe o respectivo método de ação
     * @param stamperComponent Componente de assinatura
     * @throws IOException Exceção em caso de erro na obtenção do arquivo a ser assinado
     */
    public void generateSignatureWithStamper(StamperComponent stamperComponent) throws IOException {
        String xmlUrl = signerRequestInformation.getXmlUrl();
        if (!xmlUrl.isEmpty()) {
            this.url(stamperComponent);
        } else {
            this.notUrl(stamperComponent);
        }
    }
}
