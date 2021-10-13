package br.ufsc.labsec.signature.conformanceVerifier.gui;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.component.Requirement;
import br.ufsc.labsec.signature.Constants;
import br.ufsc.labsec.signature.IdentitySelector;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CmsSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CmsSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CmsVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cms.exceptions.SignatureNotICPBrException;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.DocTimeStampAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PDDocumentUtils;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PdfIncrementalUpdatesAuxiliary;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.PossibleIncrementalUpdateException;
import br.ufsc.labsec.signature.conformanceVerifier.report.NotICPBrasilSignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.PaReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report;
import br.ufsc.labsec.signature.conformanceVerifier.report.Report.ReportType;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.xades.XadesVerifier;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.exceptions.VerificationException;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.util.io.Streams;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe é responsável pela inicialização de uma verificação.
 * Estende {@link Component}.
 */
public class ReportGuiComponent extends Component {

    @Requirement
    public List<Verifier> verifiers;
    @Requirement
    public IdentitySelector identitySelector;

    /**
     * Lista dos {@link Verifier} disponíveis
     */
    // should be updated if new verifiers come around
    private static final List<String> sortOrder = Arrays.asList(
            "CmsVerifier", "PadesVerifier",
            "CadesVerifier", "XadesVerifier", "XmlVerifier"
    );

    /**
     * Construtor
     * @param application Uma aplicação com seus componentes
     */
    public ReportGuiComponent(Application application) {
        super(application);
    }

    /**
     * Inicializa o componente
     */
    @Override
    public void startOperation() {
    }

    /**
     * Limpa as informações do componente
     */
    @Override
    public void clear() {
    }

    /**
     * Seleciona o {@link Verifier} correto para realizar a verificação
     * do arquivo de assinatura
     * @return O {@link Verifier} que suporta o arquivo de assinatura
     * @throws SignatureNotICPBrException Exceção caso o arquivo seja assinado
     *      por um certificado que não pertence à ICP-Brasil
     */
    public Verifier chooseSignatureVerifier() throws SignatureNotICPBrException {
        SignatureDataWrapper streams = this.getApplication().getSignatureWrapperList().get(0);
        InputStream signature = streams.sig(), detached = streams.det();
        boolean pdf = false;

        // Arquivos de assinatura PDF/PAdES englobam assinaturas de outros tipos, como CAdES.
        // Estas assinaturas são extraídas do documento PDF/PAdES e usadas na escolha do verifier.
        Verifier v = null;
        try {
            PDDocument pdfDoc = PDDocumentUtils.openPDDocument(signature);
            List<PDSignature> listSignatures = pdfDoc.getSignatureDictionaries();
            pdfDoc.close();

            boolean empty = true;
            // Aqui se assume que no documento há um mix de assinaturas pertencentes à ICP-Brasil e não
            // pertencentes, ou seja, caso haja mais que uma assinatura, se alguma assinatura pertence à
            // ICP-Brasil deve-se poder gerar um relatório.
            for (int i = 0; i < listSignatures.size() && v == null; i++) {
                PDSignature signatureObj = listSignatures.get(i);
                if (!DocTimeStampAttribute.signatureIsTimestamp(signatureObj)) {
                    empty = false;
                    signature.reset();
                    byte[] sig = signatureObj.getContents(signature);
                    signature.reset();
                    byte[] signedContent = signatureObj.getContents(signature);
                    try {
                        v = chooseSignatureVerifier(sig, signedContent);
                    } catch (SignatureNotICPBrException e) {
                        // ignore and continue
                    }
                }
            }
            if (empty) {
                // Em algumas assinaturas, assim como o artefato cms-46ed13357066dc6c.p7s,
                // o conteúdo assinado pode ser um arquivo PDF, de modo que seja necessário
                // passar pela escolha de um verificador.
                throw new VerificationException("Arquivo não é um PDF assinado");
            } else if (v == null) {
                throw new SignatureNotICPBrException("Signer certificate is not from ICP-Brasil.");
            }
            pdf = true;
        } catch (Exception exception) {
            if (exception instanceof SignatureNotICPBrException) {
                throw (SignatureNotICPBrException) exception;
            }
            try {
                signature.reset();
            } catch (IOException e) {
                e.printStackTrace();
            }

            v = chooseVerifierWithStreams(signature, detached);
        }


        // Caso o documento seja PDF/PAdES e a assinatura extraída dentro dele seja uma assinatura ICP-Brasil,
        // o `Verifier` escolhido acusará que a assinatura é destacada, referente ao resto do PDF na qual ela
        // está inserida. Para que esta necessidade incorreta seja evitada, o verifier é resetado com uma
        // instanciação de objeto `Verifier` qualquer.
        if (pdf) {
            v = new CadesVerifier(null);
        }

        return v;
    }

    /**
     * Seleciona o {@link Verifier} correto para realizar a verificação
     * do arquivo de assinatura
     * @param sig Os bytes do arquivo de assinatura
     * @param det Os bytes do conteúdo assinado
     * @return O {@link Verifier} que suporta o arquivo de assinatura
     * @throws SignatureNotICPBrException Exceção caso o arquivo seja assinado
     *      por um certificado que não pertence à ICP-Brasil
     */
    private Verifier chooseSignatureVerifier(byte[] sig, byte[] det) throws SignatureNotICPBrException {
        this.verifiers.sort(Comparator.comparing(
                (v) -> sortOrder.indexOf(v.getClass().getSimpleName())));
        Iterator<Verifier> it = this.verifiers.iterator();

        boolean chosen;
        Verifier v;

        do {
            v = it.next();
            chosen = v.supports(sig, det);
        } while (it.hasNext() && !chosen);

        if (!chosen) {
            v = null;
        }

        return v;
    }

    /**
     * Seleciona o {@link Verifier} correto para realizar a verificação
     * do arquivo de assinatura
     * @param signature O Stream do arquivo de assinatura
     * @param detached O Stream do conteúdo assinado
     * @return O {@link Verifier} que suporta o arquivo de assinatura
     * @throws SignatureNotICPBrException Exceção caso o arquivo seja assinado
     *      por um certificado que não pertence à ICP-Brasil
     */
    private Verifier chooseVerifierWithStreams(InputStream signature, InputStream detached) throws SignatureNotICPBrException {
        try {
            return chooseSignatureVerifier(
                    Streams.readAll(signature),
                    Streams.readAll(detached));
        } catch (NullPointerException | IOException e) {
            e.printStackTrace();
        }

        return null;
    }

    /**
     * Inicia a verificação dos documentos
     * @return A lista de relatórios das verificações
     */
    public List<Report> startVerification() {
        List<SignatureDataWrapper> sigWrapperList = this.getApplication().getSignatureWrapperList();
        List<Report> reports = new ArrayList<>();

        for (SignatureDataWrapper sw : sigWrapperList) {
            byte[] sig = null, det = null;
            String filename = sw.name();
            try {
                sig = Streams.readAll(sw.sig());
                det = Streams.readAll(sw.det());
            } catch (IOException e) {
                e.printStackTrace();
            }

            Report r = new Report();
            Verifier v = null;
            try {
                v = chooseSignatureVerifier(sig, det);
                if (v == null) {
                    r = this.extractSignatureFromPdf(sig, filename);
                } else {
                    Application.loggerInfo.log(Level.INFO, "Assinatura suportada por " + v.getClass().getName());
                    try {
                        r = v.report(sig, det, ReportType.HTML);
                        r.setSourceFile(filename);
                        r.log();
                        v.clear();
                    } catch (VerificationException e) {
                        Application.logger.log(Level.SEVERE, "Erro ao gerar o relatório", e);
                        e.printStackTrace();
                    }
                }
            } catch (SignatureNotICPBrException e) {
                Application.logger.log(Level.WARNING, "Assinatura não pertence à ICP-Brasil");
                r.setSourceFile(filename);
            } finally {
                reports.add(r);
            }
        }

        return reports;
    }

    /**
     * Valida as atualizações incrementais em uma assinatura PDF/PAdES
     * @param content Os bytes da assinatura
     * @param listReports Lista de relatórios de assinatura
     * @param documentPDF O documento PDF assinado
     * @param generatedReport Conjunto com os identificadores dos relatórios
     * @throws IOException Exceção caso o documento PDF apresente algum erro em seus dicionários
     */
    private void pdfSignatureReportIncrementalUpdatesStatus(byte[] content,
                                                            List<SignatureReport> listReports,
                                                            PDDocument documentPDF,
                                                            Set<Integer> generatedReport) throws IOException {
        PdfIncrementalUpdatesAuxiliary pdfIncrementalUpdatesAuxiliary =
                new PdfIncrementalUpdatesAuxiliary(documentPDF, content);
        List<IUException> exceptions = pdfIncrementalUpdatesAuxiliary.verify();

        int signatureIndex = listReports.size()-1;
        int exceptionIndex = exceptions.size()-1;
        boolean indeterminate, invalidate;
        indeterminate = invalidate = false;

        List<PDSignature> signatures = documentPDF.getSignatureDictionaries();
        IUException exception = null;
        for (int i = signatures.size()-1; i >= 0; i--) {
            PDSignature signature = signatures.get(i);
            while (exceptionIndex >= 0 && exceptions.get(exceptionIndex).getIndexInSignatureDictionary() == i) {
                IUException e = exceptions.get(exceptionIndex);
                if (!invalidate && e instanceof PossibleIncrementalUpdateException) {
                    indeterminate = true;
                    exception = e;
                } else if (e instanceof IncrementalUpdateException) {
                    invalidate = true;
                    exception = e;
                }
                exceptionIndex--;
            }
            /* Caso não seja um carimbo de tempo, então será uma assinatura */
            if (!DocTimeStampAttribute.signatureIsTimestamp(signature)) {
                if (!generatedReport.contains(i)) {
                    // Report not present. Error building this signature report.
                    continue;
                }
                SignatureReport signatureReport = listReports.get(signatureIndex);
                if (invalidate && exception != null) {
                    signatureReport.invalidateDueToIncrementalUpdates();
                    signatureReport.setErrorMessage(exception.getMessage());
                } else if (indeterminate && exception != null) {
                    signatureReport.indeterminateDueToPossibleIncrementalUpdate();
                    signatureReport.setErrorMessage(exception.getMessage());
                }
                signatureIndex--;
            }
        }
    }

    /**
     * Retorna o relatório de verificação de uma assinatura que não foi
     * gerada com um certificado pertencente à ICP-Brasil
     * @param sigExtracted Os bytes da assinatura
     * @param detached Os bytes do conteúdo assinado
     * @return O relatório da assinatura não pertencente à ICP-Brasil
     */
    public SignatureReport getNotIcpbrSignatureReport(byte[] sigExtracted, byte[] detached) {
        NotICPBrasilSignatureReport signatureReport = new NotICPBrasilSignatureReport();
        try {
            // CAdES or PAdES
            CadesSignatureContainer signatureContainer =  new CadesSignatureContainer(sigExtracted);
            CadesSignature signature = signatureContainer.getSignatures().get(0);

            X509Certificate signerCertificate = signature.getSigningCertificate();
            if (signerCertificate == null) {
                signatureReport.setSignerSubjectName("Assinante desconhecido");
            } else {
                signatureReport.setSignerSubjectName(signerCertificate.getSubjectX500Principal().toString());
            }
            return signatureReport;
        } catch (SignatureAttributeException e) {
            // CMS
            X509Certificate signerCertificate = null;
            try {
                CmsVerifier verifier = (CmsVerifier) verifiers.get(0);
                verifier.selectTarget(sigExtracted, detached);
                CmsSignatureContainer signatureContainer = ((CmsVerifier) verifiers.get(0)).getSignatureContainer();
                CmsSignature signature = signatureContainer.getSignatures().get(0);

                signerCertificate = signature.getSigningCertificate();
            } catch (VerificationException verificationException) { }
            if (signerCertificate == null) {
                signatureReport.setSignerSubjectName("Assinante desconhecido");
            } else {
                signatureReport.setSignerSubjectName(signerCertificate.getSubjectX500Principal().toString());
            }
            return signatureReport;
        } catch (IOException | ArrayIndexOutOfBoundsException e) {
            Application.logger.log(Level.WARNING, "Assinatura mal formada");
        } catch (EncodingException | CadesSignatureException | CertificateException e) {
            Application.logger.log(Level.WARNING, "Erro ao encontrar o certificado do assinante");
        }
        return null;
    }

    /**
     * Extrai a assinatura de um documento PDF para identificar qual {@link Verifier} a suporta
     * e realiza a verificação
     * @param sig Os bytes da assinatura
     * @param filename O nome do arquivo de assinatura
     * @return O relatório da verificação
     */
    private Report extractSignatureFromPdf(byte[] sig, String filename) {
        Report report = new Report();
        report.setSoftwareName(Constants.VERIFICADOR_NAME);
        report.setSoftwareVersion(Constants.SOFTWARE_VERSION);
        report.setVerificationDate(new Date());
        report.setSourceOfDate("Offline");
        report.setSourceFile(filename);
        try {
            PDDocument pdfDoc = PDDocumentUtils.openPDDocument(sig);
            List<PDSignature> listSignatures = pdfDoc.getSignatureDictionaries();
            pdfDoc.close();

            if (listSignatures.isEmpty()) {
                return report;
            }
            Set<Integer> generatedReport = new HashSet<>();
            Integer index = 0;
            for (PDSignature signature : listSignatures) {
                /* Somente chama-se o verificador para assinaturas, não timestamps.
                * Carimbos de tempo são verificados dentros dos verifiers.*/
                if (DocTimeStampAttribute.signatureIsTimestamp(signature)) {
                    continue;
                }
                byte[] sigExtracted = signature.getContents(new ByteArrayInputStream(sig));
                byte[] det = signature.getSignedContent(new ByteArrayInputStream(sig));

                Verifier v = null;
                try {
                    v = chooseSignatureVerifier(sigExtracted, det);
                } catch (SignatureNotICPBrException e) {
                    Application.logger.log(Level.WARNING, "Assinatura não pertence à ICP-Brasil");
                    SignatureReport r = getNotIcpbrSignatureReport(sigExtracted, det);
                    if (r != null) {
                        report.addSignatureReport(r);
                        generatedReport.add(index++);
                    }
                }

                if (v != null) {
                    Application.loggerInfo.log(Level.INFO, "Assinatura suportada por " + v.getClass().getName());

                    try {
                        Report r;
                        if (v instanceof PadesVerifier) {
                            r = v.report(sig, sigExtracted, ReportType.HTML);
                        } else {
                            r = v.report(sigExtracted, det, ReportType.HTML);
                        }
                        for (SignatureReport sr : r.getSignatures()) {
                            report.addSignatureReport(sr);
                            generatedReport.add(index);
                        }
                        for (PaReport pr : r.getPaList()) {
                            report.addPaReport(pr);
                        }
                        if (v instanceof PadesVerifier || v instanceof CadesVerifier || v instanceof XadesVerifier) {
                            // LPA
                            report.setLpaValid(r.isLpaValid());
                            report.setLpaErrorMessage(r.getLpaErrorMessage());
                            report.setLpaVersion(r.getLpaVersion());
                            report.setLpaExpired(r.isLpaExpired());
                            report.setOnline(r.isOnline());
                            report.setPeriod(r.getPeriod());
                        }
                        v.clear();
                    } catch (VerificationException e) {
                        Application.logger.log(Level.SEVERE, "Erro ao gerar o relatório", e);
                        e.printStackTrace();
                    }
                    index++;
                }
            }
            pdfSignatureReportIncrementalUpdatesStatus(sig, report.getSignatures(), pdfDoc, generatedReport);
        } catch (IOException | IndexOutOfBoundsException e) {
            if (report.getSignatures().isEmpty()) {
                Application.logger.log(Level.SEVERE, "Erro ao extrair assinaturas do pdf", e.getMessage());
            } else {
                Application.logger.log(Level.SEVERE, "Erro avaliando atualizações incrementais no relatório", e.getMessage());
            }
        }
        return report;
    }

}
