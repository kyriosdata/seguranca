package br.ufsc.labsec.signature.conformanceVerifier.pades;

import br.ufsc.labsec.signature.SignaturePolicyInterface.AdESType;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.AttributeMap;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaEtsSigPolicyId;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.DssAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.SignatureDictionaryAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.pades.utils.LastSignatureResolver;
import br.ufsc.labsec.signature.conformanceVerifier.pades.utils.PDFScriptChecker;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PDDocumentUtils;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report.ReportType;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.VerificationException;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.*;
import java.sql.Time;
import java.util.*;

/**
 * Esta classe implementa os métodos para verificação de uma assinatura PAdES.
 * Implementa {@link Verifier}.
 */
public class PadesVerifier implements Verifier {

    private final static List<String> PROHIBITED_SIGNATURE_DICTIONARY_ENTRIES;
     /**
     * Data de referência para a verificação
     */
    private Time timeReference;
    /**
     * O relatório da verificação
     */
    private Report report;


    static {
        PROHIBITED_SIGNATURE_DICTIONARY_ENTRIES = new ArrayList<>();
        PROHIBITED_SIGNATURE_DICTIONARY_ENTRIES.add("Cert");
        PROHIBITED_SIGNATURE_DICTIONARY_ENTRIES.add("R");
        PROHIBITED_SIGNATURE_DICTIONARY_ENTRIES.add("Prop_AuthType");
    }

    /**
     * Componente de assinatura PAdES
     */
    private PadesSignatureComponent padesComponent;

    /**
     * Construtor
     * @param padesComponent Componente de assinatura PAdES
     */
    public PadesVerifier(PadesSignatureComponent padesComponent) {
        this.padesComponent = padesComponent;
    }

    /**
     * Inicializa os bytes do documento PAdES assinado
     * @param target Os bytes do documento PAdES assinado
     * @param signedContent Os bytes do conteúdo assinado no documento
     */
    @Override
    public void selectTarget(byte[] target, byte[] signedContent) {
        PDDocument documentPDF = null;
        try {
            documentPDF = PDDocumentUtils.openPDDocument(new ByteArrayInputStream(target));
            List<PDSignature> dicSignatures = documentPDF.getSignatureDictionaries();
            documentPDF.close();
            for (PDSignature dicSignature : dicSignatures) {
                byte[] contents = dicSignature.getContents(new ByteArrayInputStream(target));
                byte[] contentsSigned = dicSignature.getSignedContent(new ByteArrayInputStream(target));
                this.padesComponent.getCadesVerifier().selectTarget(contents, contentsSigned);
            }
        } catch (PbadException | IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Verifica se o dicionário de assinatura está de acordo
     * com a extensão de política de assinatura.
     * @param dicSignature Dicionário da assinatura
     */
    private AttribReport checkBrExtMandatedPdfSigDicEntries(COSDictionary dicSignature) {
        AttribReport attribReport = new AttribReport();
        String errorMessage = "";
        for (String key : PROHIBITED_SIGNATURE_DICTIONARY_ENTRIES) {
            if (dicSignature.containsKey(key)) {
                attribReport.setAttribName("BrExtMandatedPdfSigDicEntries");
                attribReport.setError(true);
                errorMessage = "A chave " + key + ", proibida, foi utilizada no dicionario de assinaturas.";
                attribReport.setErrorMessage(errorMessage);

                CadesVerifier cadesVerifier = (CadesVerifier) this.padesComponent.getCadesVerifier();
                Report report = cadesVerifier.getReport();
                List<SignatureReport> sigReports = report.getSignatures();

                sigReports.get(sigReports.size() - 1).addExtraAttrReport(attribReport);
            }
        }

        attribReport.setAttribName("BrExtMandatedPdfSigDicEntries");
        if (errorMessage.equals("")) {
            attribReport.setError(false);
        } else {
            attribReport.setError(true);
            attribReport.setErrorMessage(errorMessage);
        }

        return attribReport;
    }

    /**
     * Verifica se o relatório da assinatura contém o atributo obrigatório sigPolicyId.
     * A falta deste atributo dificulta a invalidação da assinatura
     * @param sigReport O relatório de assinatura
     */
    private void checkIdAaSigPolicyIdInSignatureReport(SignatureReport sigReport) {
        final String SIG_POLICY_ID_ATTR = AttributeMap.translateName(IdAaEtsSigPolicyId.IDENTIFIER);
        List<AttribReport> attributeReports = sigReport.getOptionalAttrib();
        for (int i = 0; i < attributeReports.size(); i++) {
            if (attributeReports.get(i).getAttribName().equals(SIG_POLICY_ID_ATTR)) {
                // Contém o atributo sigPolicyId como opcional
                return;
            }
        }
        attributeReports = sigReport.getRequiredAttrib();
        for (int i = 0; i < attributeReports.size(); i++) {
            if (attributeReports.get(i).getAttribName().equals(SIG_POLICY_ID_ATTR)) {
                // Contém o atributo sigPolicyId como obrigatório
                return;
            }
        }

        AttribReport attribReport = new AttribReport();
        attribReport.setAttribName(SIG_POLICY_ID_ATTR);
        attribReport.setErrorMessage(SignatureAttributeException.ATTRIBUTE_NOT_FOUND);
        attribReport.setError(true);
        attributeReports.add(attribReport);
        sigReport.setPresenceOfInvalidAttributes(true);
    }

    /**
     * Retorna as assinaturas no documento
     * @return As assinaturas no documento
     */
    @Override
    public List<String> getSignaturesAvailable() throws EncodingException, SignatureAttributeException {
        return padesComponent.cadesVerifier.getSignaturesAvailable();
    }

    /**
     * Seleciona uma das assinaturas
     * @param target Identificador das assinatura
     */
    @Override
    public void selectSignature(String target) {
        padesComponent.cadesVerifier.selectSignature(target);
    }

    /**
     * Retorna o relatório da validação de uma assinatura
     * @return O relatório da validação de uma assinatura
     */
    @Override
    public SignatureReport getValidationResult() {
        return padesComponent.cadesVerifier.getValidationResult();
    }

    /**
     * Retorna os atributos que podem ser inseridos na assinatura selecionada
     * @return Os atributos que podem ser inseridos na assinatura
     */
    @Override
    public List<String> getAvailableAttributes() {
        return padesComponent.cadesVerifier.getAvailableAttributes();
    }

    /**
     * Adiciona um atributo
     * @param attribute Nome do atributo que deve ser inserido
     * @return Indica se a inserção foi bem sucedida
     */
    @Override
    public boolean addAttribute(String attribute) {
        return padesComponent.cadesVerifier.addAttribute(attribute);
    }

    /**
     * Limpa as informações do verificador
     * @return Indica se a limpeza foi bem sucedida
     */
    @Override
    public boolean clear() {
        boolean clearly = padesComponent.cadesVerifier.clear();
        padesComponent.clear();
        report = null;
        return clearly;
    }

    /**
     * Cria um objeto {@link Report} com as informações da verificação do documento
     * @param pdfFile O documento a ser verificado
     * @param signedContent O conteúdo assinado do documento PAdES
     * @param type Tipo de relatório desejado
     * @return O relatório da verificação
     * @throws VerificationException Exceção caso haja algum problema na verificação
     */
    @Override
    public Report report(byte[] pdfFile, byte[] signedContent, Report.ReportType type) throws VerificationException {
        if (this.getTimeReference() == null)
            this.setTimeReference(new Time(SystemTime.getSystemTime()));

        PDDocument documentPDF = null;
        try ( InputStream inputStreamPdf = new ByteArrayInputStream(pdfFile)) {
            documentPDF = PDDocumentUtils.openPDDocument(inputStreamPdf);
            List<PDSignature> signatureList = documentPDF.getSignatureDictionaries();
            int i = 0;
            while (!signatureList.isEmpty()) {
                LastSignatureResolver lastSignatureResolver = new LastSignatureResolver(this);
                lastSignatureResolver.updateLastSignature(signatureList);
                PDSignature signatureObj = lastSignatureResolver.getLastSignature();

                String typeDictionary = getTypeOfDictionary(signatureObj);
                if (typeDictionary.equals("Sig") && Arrays.equals(signatureObj.getContents(pdfFile), signedContent)) {
                    this.reportForSignature(lastSignatureResolver, i++, signatureObj, pdfFile, type, documentPDF);
                    break;
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        finally {
            PDDocumentUtils.closePDDocument(documentPDF);
        }

        return this.report;
    }

    /**
     * Gera o relatório de verificação de uma assinatura
     * @param lastSignatureResolver Resolvedor de atributos da última assinatura
     * @param i Índice da assinatura
     * @param signatureObj A assinatura PAdES
     * @param pdfFile Bytes do arquivo assinado
     * @param reportType Tipo do relatório
     * @param document Documento assinado
     * @throws VerificationException Exceção em caso de erro na verificação
     * @throws IOException Exceção em caso um documento assinado mal formado
     */
    private void reportForSignature(LastSignatureResolver lastSignatureResolver, int i, PDSignature signatureObj, byte[] pdfFile, ReportType reportType,
                                    PDDocument document) throws VerificationException, IOException {
        byte[] signatureBytes = signatureObj.getContents(pdfFile);
        byte[] signedContent = signatureObj.getSignedContent(pdfFile);
        PadesSignature sig = new PadesSignature(document, signatureObj, pdfFile);
        PadesSignatureVerifier sigVerifier = new PadesSignatureVerifier(padesComponent, sig, this.timeReference);
        DssAttribute dss = (DssAttribute) sig.getEncodedAttribute("DSS", sigVerifier);
        lastSignatureResolver.resolveLastSignaturePolicy(dss, pdfFile);

        this.verifyPadesSignature(signatureObj, i, sigVerifier);
        Report signatureReport = this.runCadesVerifierReport(signatureBytes, signedContent, reportType);

        this.treatPadesAttributes(sigVerifier, signatureObj, document, signatureReport);
        this.resolveReport(signatureReport);
    }

    /**
     * Verifica a presença de atributos obrigatórios na assinatura
     * @param sigVerifier Verificador PAdES
     * @param signatureObj A assinatura PAdES
     * @param document O documento assinado
     * @param signatureReport O relatório da verificação
     */
    private void treatPadesAttributes(PadesSignatureVerifier sigVerifier, PDSignature signatureObj, PDDocument document,
                                      Report signatureReport) {
        COSDictionary signatureDict = signatureObj.getCOSObject();

        List<TimeStampReport> tsReports = new ArrayList<>(sigVerifier.getTimeStampReportList());
        List<AttribReport> padesReports = new ArrayList<>(sigVerifier.getAttReportList());
        padesReports.add(checkBrExtMandatedPdfSigDicEntries(signatureDict));
        List<SignatureReport> signatureReports = signatureReport.getSignatures();
        checkIdAaSigPolicyIdInSignatureReport(signatureReports.get(signatureReports.size() - 1));

        addReportsToSignatureReport(signatureReport, document, padesReports, tsReports, sigVerifier);
    }

    /**
     * Adiciona os valores de validação dos atributos e carimbos ao relatório de verificação da assinatura
     * @param signatureReport O relatório da verificação
     * @param document O documento assinado
     * @param padesReports Lista de relatórios de atributos
     * @param tsReports Lista de relatórios de carimbo de tmepo
     * @param sigVerifier Verificador PAdES
     */
    private void addReportsToSignatureReport(Report signatureReport, PDDocument document,
                                             List<AttribReport> padesReports, List<TimeStampReport> tsReports,
                                             PadesSignatureVerifier sigVerifier) {
        SignaturePolicyProxy sigPolicyProxy = (SignaturePolicyProxy) sigVerifier.getSignaturePolicy();
        List<SignatureReport> signatures = signatureReport.getSignatures();
        SignatureReport lastSigReport = signatures.get(signatures.size() - 1);

        boolean validAttrs = true;
        for (TimeStampReport tsReport : tsReports) {
            tsReport.setAsymmetricCipher(true);
            tsReport.setHash(true);
            validAttrs &= tsReport.isValid();
            lastSigReport.addTimeStampReport(tsReport);
        }

        if (sigPolicyProxy.getSignaturePolicy() != null) {
            for(AttribReport report : padesReports) {
                validAttrs &= !report.hasError();
                lastSigReport.addAttribRequiredReport(report);
            }
        } else {
            for(AttribReport report : padesReports) {
                lastSigReport.addAttribOptionalReport(report);
            }
        }

        lastSigReport.setPresenceOfInvalidAttributes(lastSigReport.isHasAttributeExceptions() || !validAttrs);
        new PDFScriptChecker(document).treatPresenceOfJavaScript(lastSigReport);
    }

    /**
     * Realiza a verificação do conteúdo CAdES da assinatura
     * @param contents Bytes da assinatura
     * @param contentsSigned Bytes do conteúdo assinado
     * @param type Tipo do relatório
     * @return O relatório gerado pela verificação
     * @throws VerificationException Exceção em caso de erro na verificação
     */
    private Report runCadesVerifierReport(byte[] contents, byte[] contentsSigned, ReportType type)
            throws VerificationException {
        SignaturePolicyProxy sigPolicyProxy = this.padesComponent.getSignaturePolicy();
        CadesVerifier cadesVerifier = (CadesVerifier) this.padesComponent.cadesVerifier;
        cadesVerifier.createReport();
        sigPolicyProxy.getLpaReport(cadesVerifier.getReport(), AdESType.PAdES);
        return padesComponent.cadesVerifier.report(contents, contentsSigned, type);
    }

    /**
     * Verifica a validade da assinatura PAdES
     * @param signature A assinatura PAdES a ser verificada
     * @param currSig Índice da assinatura
     * @param padesSigVerifier Verificador PAdES
     */
    private void verifyPadesSignature(PDSignature signature, int currSig, PadesSignatureVerifier padesSigVerifier) {
        AttribReport sigDicReport = this.generateSignatureDictionaryReport(signature);
        padesSigVerifier.getAttReportList().add(sigDicReport);
        padesSigVerifier.verify(currSig == 0);
    }

    /**
     * Cria o relatório do atributo 'SignatureDictionary' e faz a validação do atributo
     * @param signature A assinatura PAdES
     * @return O relatório gerado
     */
    private AttribReport generateSignatureDictionaryReport(PDSignature signature) {
        SignatureDictionaryAttribute signatureDictionaryAttr =
                new SignatureDictionaryAttribute(signature, this.getPadesComponent());
        AttribReport sigDicReport = new AttribReport();
        sigDicReport.setAttribName("SignatureDictionary");
        signatureDictionaryAttr.validate(sigDicReport);
        return sigDicReport;
    }

    /**
     * Atribue o valor dado ao relatório de verificação caso o relatório esteja nulo
     * @param signatureReport O novo valor do relatório caso o mesmo esteja nulo
     */
    private void resolveReport(Report signatureReport) {
        if (this.report == null) {
            // CHECK maybe this code was never executed
            this.report = signatureReport;
        }
    }

    /**
     * Verifica se o documento é uma assinatura PAdES
     * @param filePath Diretório do arquivo a ser verificado
     * @return Indica se o arquivo é uma assinatura PAdES
     */
    @Override
    public boolean isSignature(String filePath) {
        return padesComponent.cadesVerifier.isSignature(filePath);
    }

    /**
     * Verifica se a assinatura possui conteúdo destacado
     * @return Indica se a assinatura possui conteúdo destacado
     */
    @Override
    public boolean needSignedContent() {
        return false;
    }

    /**
     * Retorna uma lista de atributos obrigatórios
     * @return Uma lista de atributos obrigatórios
     */
    @Override
    public List<String> getMandatedAttributes() {
        return padesComponent.cadesVerifier.getMandatedAttributes();
    }

    /**
     * Retorna a data de referência
     * @return A data de referência
     */
    public Time getTimeReference() {
        return timeReference;
    }

    /**
     * Atribue a data de referência
     * @param timeReference A nova data de referência
     */
    public void setTimeReference(Time timeReference) {
        this.timeReference = timeReference;
    }

    /**
     * Verifica se o documento assinado é uma assinatura PAdES
     * @param signature Os bytes do documento assinado
     * @param detached Os bytes do arquivo destacado
     * @return Indica se o documento assinado é uma assinatura PAdES
     * @throws SignatureNotICPBrException Exceção caso a assinatura não seja feita com um certificado ICP-Brasil
     */
    @Override
    public boolean supports(byte[] signature, byte[] detached) throws SignatureNotICPBrException {
        CadesVerifier cadesVerifier = (CadesVerifier) this.padesComponent.cadesVerifier;
        boolean supports = cadesVerifier.supports(signature, detached);
        String padesPolicy = "2\\.16\\.76\\.1\\.7\\.1\\.1[1-4]\\.(.*)";
        return supports && cadesVerifier.getOid().matches(padesPolicy);
    }

    /**
     * Retorna o valor da entrada 'Type' no dicionário da assinatura
     * @param signatureObj A assinatura
     * @return O valor da entrada 'Type' no dicionário da assinatura
     */
    public String getTypeOfDictionary(PDSignature signatureObj) {
        COSBase baseType = signatureObj.getCOSObject().getDictionaryObject("Type");
        COSName nametype = (COSName) baseType;
        return nametype.getName();
    }

    /**
     * Retorna o componente de assinatura PAdES
     * @return O componente de assinatura PAdES
     */
    public PadesSignatureComponent getPadesComponent() {
        return padesComponent;
    }
}
