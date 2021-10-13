package br.ufsc.labsec.signature.conformanceVerifier.xml;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.Constants;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.signed.SignaturePolicyIdentifier;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.VerificationException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;
import java.security.Security;
import java.security.cert.CertPath;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe implementa os métodos para verificação de uma assinatura XML.
 * Implementa {@link Verifier}.
 */
public class XmlVerifier implements Verifier {

    /**
     * Contêiner de assinatura XML
     */
    private XmlSignatureContainer signatureContainer;
    /**
     * Assinatura XML a ser verificada
     */
    private XmlSignature selectedSignature;
    /**
     * Componente de assinatura XML
     */
    private XmlSignatureComponent xmlSignatureComponent;
    /**
     * Resultados da verificação do documento
     */
    private Report report;

    /**
     * Construtor
     * @param xmlSignatureComponent Componente de assinatura XML
     */
    public XmlVerifier(XmlSignatureComponent xmlSignatureComponent) {
       this.xmlSignatureComponent = xmlSignatureComponent;
    }

    /**
     * Inicializa os bytes do documento XML assinado
     * @param target Os bytes do documento XML assinado
     * @param signedContent Os bytes do conteúdo assinado no documento
     * @throws VerificationException Exceção caso os bytes não sejam uma assinatura válida
     */
    @Override
    public void selectTarget(byte[] target, byte[] signedContent) throws VerificationException {
        this.signatureContainer = new XmlSignatureContainer(new ByteArrayInputStream(target), new ByteArrayInputStream(signedContent), this.xmlSignatureComponent);

        if (this.signatureContainer.getSignatures().isEmpty()) {
            throw new VerificationException("Impossivel decodificar a assinatura.");
        }
    }

    /**
     * Retorna as assinaturas no documento
     * @return As assinaturas no documento
     */
    @Override
    public List<String> getSignaturesAvailable() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Seleciona uma das assinaturas
     * @param target Identificador das assinatura
     */
    @Override
    public void selectSignature(String target) {
        // TODO Auto-generated method stub
    }

    /**
     * Retorna os resultados da validação de uma assinatura
     * @return Os resultados da validação de uma assinatura
     */
    @Override
    public SignatureReport getValidationResult() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Retorna os atributos das assinaturas
     * @return Os atributos das assinaturas
     */
    @Override
    public List<String> getAvailableAttributes() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Adiciona um atributo
     * @param attribute Nome do atributo que deve ser inserido
     * @return Indica se a inserção foi bem sucedida
     */
    @Override
    public boolean addAttribute(String attribute) {
        // TODO Auto-generated method stub
        return false;
    }

    /**
     * Limpa as informações do verificador
     * @return Indica se a limpeza foi bem sucedida
     */
    @Override
    public boolean clear() {
        this.selectedSignature = null;
        this.signatureContainer = null;
        this.report = null;
        return true;
    }

    /**
     * Cria um objeto {@link Report} com as informações da verificação
     * @param target O documento a ser verificado
     * @param signedContent O conteúdo assinado do documento XML
     * @param type Tipo de relatório desejado
     * @return O relatório da verificação
     * @throws VerificationException Exceção caso haja algum problema na verificação
     */
    @Override
    public Report report(byte[] target, byte[] signedContent, Report.ReportType type) throws VerificationException {
        Security.addProvider(new BouncyCastleProvider());
        this.createReport();
        this.selectTarget(target, signedContent);

        if (this.signatureContainer != null) {
            for (XmlSignature sign : this.signatureContainer.getSignatures()) {
                this.selectedSignature = sign;
                this.report.addSignatureReport(sign.validate());
            }
        }

        return this.report;
    }

    /**
     * Inicializa um objeto {@link Report}
     */
    private void createReport() {
        this.report = new Report();
        report.setSoftwareName(Constants.VERIFICADOR_NAME);
        report.setSoftwareVersion(Constants.SOFTWARE_VERSION);
        report.setVerificationDate(new Date());
        report.setSourceOfDate("Offline");
    }

    /**
     * Verifica se o documento é uma assinatura XML
     * @param filePath Diretório do arquivo a ser verificado
     * @return Indica se o arquivo é uma assinatura XML
     */
    @Override
    public boolean isSignature(String filePath) {
        // TODO Auto-generated method stub
        return false;
    }

    /**
     * Verifica se a assinatura possui conteúdo destacado
     * @return Indica se a assinatura possui conteúdo destacado
     */
    @Override
    public boolean needSignedContent() {
        return this.signatureContainer.hasDetachedContent();
    }

    /**
     * Retorna uma lista de atributos obrigatórios
     * @return Uma lista de atributos obrigatórios
     */
    @Override
    public List<String> getMandatedAttributes() {
        return new ArrayList<String>();
    }

    /**
     * Verifica se o documento assinado é uma assinatura XML
     * @param signature Os bytes do documento assinado
     * @param detached Os bytes do arquivo destacado
     * @return Indica se o documento assinado é uma assinatura XML
     * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um certificado ICP-Brasil
     */
    @Override
    public boolean supports(byte[] signature, byte[] detached) throws SignatureNotICPBrException {
        try {
            this.selectTarget(signature, detached);
            List<XmlSignature> signatures = this.signatureContainer.getSignatures();

            if (!signatures.isEmpty()) {
                boolean validSignature = true;
                Iterator<XmlSignature> itSign = signatures.iterator();
                while (itSign.hasNext() && validSignature) {
                    validSignature = this.validSignature(itSign.next());
                }
                return validSignature;
            }
        } catch (VerificationException | ClassCastException e) {
            return false;
        }
        return false;
    }

    /**
     * Verifica se a assinatura foi feita com um certificado ICP-Brasil e se é uma assinatura XML
     * @param sig A assinatura a ser verificada
     * @return Indica se a assinatura é uma assinatura XML e ICP-Brasil
     * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um certificado ICP-Brasil
     */
    private boolean validSignature(XmlSignature sig) throws SignatureNotICPBrException {
        boolean noPolicy = false;
        boolean isICPBR = false;
        X509Certificate c = sig.getSigningCertificate();
        isICPBR = this.checkCertPath(c);
        if (!isICPBR) {
            throw new SignatureNotICPBrException("Signer certificate is not from ICP-Brasil.");
        }
        noPolicy = !sig.getAttributeList().contains(SignaturePolicyIdentifier.IDENTIFIER);

        return noPolicy && isICPBR;
    }

    /**
     * Verifica se é possível criar o caminho de certificação da assinatura
     * @param certificate Certificado utilizado na assinatura
     * @return Indica se o caminho de certificação foi criado com sucesso
     */
    private boolean checkCertPath(X509Certificate certificate) {
        Set<TrustAnchor> trustAnchors = this.xmlSignatureComponent.trustAnchorInterface.getTrustAnchorSet();
        Time timeReference = new Time(SystemTime.getSystemTime());

        CertPath certpath = this.xmlSignatureComponent.certificatePathValidation.generateCertPathNoSave(certificate, trustAnchors, timeReference);

        return certpath != null;
    }

    /**
     * Retorna o contêiner de assinatura XML
     * @return O contêiner de assinatura XML
     */
    public XmlSignatureContainer getSignatureContainer() {
        return this.signatureContainer;
    }

    /**
     * Retorna a assinatura no documento selecionada para verificação
     * @return A assinatura selecionada para verificação
     */
    public XmlSignature getSelectedSignature() {
        return this.selectedSignature;
    }
}
