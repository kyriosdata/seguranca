package br.ufsc.labsec.signature.signer.signatureSwitch;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PDDocumentUtils;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PDFSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PdfSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;
import br.ufsc.labsec.signature.signer.signatureSwitch.pdfSigner.SignatureContainerGenerator;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.*;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * Esta classe gera assinaturas no formado PDF.
 */
public class PdfSigner extends SignatureDataWrapperGenerator implements Signer {

    /**
     * Chave privada do assinante
     */
    private PrivateKey privateKey;
    /**
     * Cadeia de certificados do assinante
     */
    private Certificate[] certificateChain;
    /**
     * O arquivo a ser assinado
     */
    private InputStream target;
    /**
     * Política a ser utilizada na assinatura
     */
    private String policyOid;
    /**
     * Suite da assinatura
     */
    private String suite;
    private String reason;
    private String location;
    /**
     * Componente de assinatura PDF
     */
    private PdfSignatureComponent pdfSignatureComponent;
    /**
     * Gerador de contêineres de assinaturas PDF
     */
    private SignatureContainerGenerator pdfSignature;
    /**
     * Contêiner de assinatura PDF
     */
    private PDFSignatureContainer container;

    /**
     * Construtor
     * @param pdfSignatureComponent Componente de assinatura PDF
     */
    public PdfSigner(PdfSignatureComponent pdfSignatureComponent) {
        this.pdfSignatureComponent = pdfSignatureComponent;
    }

    /**
     * Inicializa o gerador de contêineres de assinaturas PDF
     */
    public void createPdfContainerGenerator()  {
        this.pdfSignature = new SignatureContainerGenerator(pdfSignatureComponent, privateKey, certificateChain);
        this.pdfSignature.setSignatureSuite(suite);
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
    @Override
    public void selectTarget(InputStream target, String policyOid) {
        this.target = target;
        this.policyOid = policyOid;
        createPdfContainerGenerator();
    }

    /**
     * Inicializa o gerador de contêiner de assinatura
     * @param target  Endereço do arquivo a ser assinado
     * @param policyOid OID da política de assinatura usada
     */
    @Override
    public void selectTarget(String target, String policyOid) {
        try {
            this.selectTarget(new FileInputStream(target), policyOid);
        } catch (FileNotFoundException e) {
            Application.logger.log(Level.SEVERE, "Arquivo não encontrado.", e);
        }
    }

    /**
     * Realiza a assinatura
     * @return Indica se o processo de assinatura foi concluído com sucesso
     */
    @Override
    public boolean sign() {
        if (pdfSignature != null) {
            this.container = pdfSignature.generate(target, location, reason);
            return true;
        }
        return false;
    }

    /**
     * Retorna o arquivo assinado
     * @return O {@link InputStream} do arquivo assinado
     */
    @Override
    public InputStream getSignatureStream() {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        container.encode(out);
        byte[] bytes = out.toByteArray();
        return new ByteArrayInputStream(bytes);
    }

    /**
     * Salva a assinatura gerada
     * @return Indica se a assinatura foi salva com sucesso
     */
    @Override
    public boolean save() {
        OutputStream outputStream = this.pdfSignatureComponent.ioService.save("pdf");

        PDFSignatureContainer sig = this.container;

        if (outputStream != null && sig != null) {
            sig.encode(outputStream);
        } else {
            return false;
        }
        return true;
    }

    /**
     * Adiciona um atributo à assinatura
     * @param attribute O atributo a ser selecionado
     */
    @Override
    public void selectAttribute(String attribute) {
        // TODO Auto-generated method stub

    }

    /**
     * Remove um atributo da assinatura
     * @param attribute O atributo a ser removido
     */
    @Override
    public void unselectAttribute(String attribute) {
        // TODO Auto-generated method stub

    }

    /**
     * Retorna a lista de atributos disponíveis da assinatura
     * @return A lista de atributos disponíveis da assinatura
     */
    @Override
    public List<String> getAttributesAvailable() {
        return new ArrayList<String>();
    }

    /**
     * Retorna a lista dos tipos de assinatura disponíveis
     * @return Lista dos tipos de assinatura disponíveis
     */
    @Override
    public List<String> getAvailableModes() {
        return new ArrayList<String>();
    }

    /**
     * Retorna a lista de atributos assinados obrigatórios da assinatura
     * @return A lista de atributos assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedSignedAttributeList() {
        return new ArrayList<String>();
    }

    /**
     * Atribue o tipo de assinatura, anexada ou destacada
     * @param mode O tipo da assinatura
     */
    @Override
    public void setMode(FileFormat mode, String suite) {
        this.suite = suite;
    }

    /**
     * Retorna a lista de atributos assinados disponíveis para a assinatura
     * @return A lista de atributos assinados disponíveis para a assinatura
     */
    @Override
    public List<String> getSignedAttributesAvailable() {
        return new ArrayList<String>();
    }

    /**
     * Retorna a lista de atributos não-assinados disponíveis para a assinatura
     * @return A lista de atributos não-assinados disponíveis para a assinatura
     */
    @Override
    public List<String> getUnsignedAttributesAvailable() {
        return new ArrayList<String>();
    }

    /**
     * Retorna a lista de políticas de assinatura disponiveis
     * @return A lista de políticas de assinatura
     */
    @Override
    public List<String> getPoliciesAvailable() {
        List<String> polices = new ArrayList<String>();
        polices.add("PDF");
        return polices;
    }

    /**
     * Retorna a lista de atributos não assinados obrigatórios da assinatura
     * @return A lista de atributos não assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedUnsignedAttributeList() {
        return new ArrayList<String>();
    }

    @Override
    public boolean supports(InputStream target, SignerType signerType) throws CertificationPathException, SignerException {
        try {
            PDDocumentUtils.openPDDocument(target);
            target.reset();
            return true;
        } catch (IOException e) {
            throw new SignerException(SignerException.MALFORMED_TBS_FILE);
        }
    }

    /**
     Realiza a assinatura sobre o arquivo dado
     * @param filename Caminho do arquivo a ser assinado
     * @param target O arquivo a ser assinado
     * @param policyOid Política a ser utilizada na assinatura
     * @return  O arquivo assinado
     */
    @Override
    public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyOid){
        selectTarget(target, policyOid.toString());
        if (this.pdfSignature != null) {
            sign();
            InputStream signature = getSignatureStream();
            return new SignatureDataWrapper(signature, null, filename);
        }
        return null;
    }
}
