package br.ufsc.labsec.signature.conformanceVerifier.pades.attributes;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.tsa.TimeStampVerifierInterface;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.PdfEntry;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.NotInICPException;
import org.apache.pdfbox.cos.COSBase;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.DERUTF8String;

import java.io.IOException;
import java.sql.Time;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * Esta classe representa o atributo de carimbo de tempo de uma assinatura PAdES.
 * Implementa {@link PadesAttribute}.
 */
public class DocTimeStampAttribute implements PadesAttribute {

    /**
     * Reconhece se o dicionário da PDSignature é de um DocTimeStamp
     */
    public static boolean signatureIsTimestamp(PDSignature signature) {
        /* SubFilters para DocTimeStamp sempre será igual a "ETSI.RFC3161". */
        return signature.getCOSObject().containsKey(COSName.SUB_FILTER)
                && signature.getCOSObject().getNameAsString(COSName.SUB_FILTER).equals("ETSI.RFC3161");
    }

	/**
	 * O dicionário do carimbo de tempo
	 */
    private PDSignature docTimeStampDictionary;
	/**
	 * A política de assinatura
	 */
	private SignaturePolicyProxy policy;
	/**
	 * O {@link Verifier} de assinatura PAdES
	 */
    private PadesSignatureVerifier verifier;
	/**
	 * Indica se o carimbo de tempo é o último na assinatura
	 */
	private boolean isLast;
	/**
	 * Valor do resumo criptográfico do carimbo
	 */
    private String vriHash;
	/**
	 * Relatório do carimbo de tempo
	 */
	private TimeStampReport timeStampReport;

	/**
	 * Construtor
	 * @param verifier {@link Verifier} de assinatura PAdES
	 * @param docTimeStampDictionary O carimbo de tempo
	 * @param vriHash Valor de resumo criptográfico do carimbo
	 */
    public DocTimeStampAttribute(PadesSignatureVerifier verifier, PDSignature docTimeStampDictionary, String vriHash) {
        this.policy = (SignaturePolicyProxy) verifier.getSignaturePolicy();
        this.verifier = verifier;
        this.docTimeStampDictionary = docTimeStampDictionary;
        this.isLast = isLast();
        this.vriHash = vriHash;
    }

	/**
	 * Valida o atributo
	 * @param report O relatório do atributo que será validado
	 * @return Indica se o atributo é válido
	 * @throws NotInICPException
	 */
    @Override
    public boolean validate(AttribReport report) throws NotInICPException {
        report.setAttribName("DocTimeStamp");
        String errorString = "";
        boolean isValid = true;
        List<PdfEntry> entries = policy.verifierRulesGetBrExtMandatedDocTSEntries().getMandatedDocTSEntries();

        if (!this.isLast) {
            validateDss();
        }

        String typeString = "";
        String policySubfilter = "";
        for (PdfEntry entry : entries) {
            String id = entry.getPdfEntryID();
            if (id.equals("Type")) {
                DERUTF8String temp = null;
                try {
                    temp = (DERUTF8String) DERUTF8String.fromByteArray(entry.getPdfEntryValue());
                } catch (IOException e) {
                    Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                }

                typeString = temp.getString();
            } else if (id.equals("SubFilter")) {
                DERUTF8String temp = null;
                try {
                    temp = (DERUTF8String) DERUTF8String.fromByteArray(entry.getPdfEntryValue());
                } catch (IOException e) {
                    Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                }
                policySubfilter = temp.getString();
            }
        }

        COSName dicType = (COSName) this.docTimeStampDictionary.getCOSObject().getDictionaryObject("Type");
        if (!typeString.equals(dicType.getName())) {
            isValid = false;
            errorString += "Campo Type do dicionário DocTimeStamp está incorreto.\n";
        }
        COSName dicSubFilter = (COSName) this.docTimeStampDictionary.getCOSObject().getDictionaryObject("SubFilter");
        if (!policySubfilter.equals(dicSubFilter.getName())) {
            isValid = false;
            errorString += "Campo SubFilter do dicionário DocTimeStamp está incorreto.\n";
        }


        byte[] pdfBytes = this.verifier.getPDFbytes();
        byte[] contents = null;

        try {
            contents = docTimeStampDictionary.getContents(pdfBytes);
        } catch (IOException e) {
            isValid = false;
            errorString += "Entrada Contents do dicionário DocTimeStamp está incorreto.\n";
        }
        Time timeReference = this.verifier.getTimeReference();
        CadesSignatureComponent cadesComponent = this.verifier.getCadesSignatureComponent();
        TimeStampVerifierInterface timeStampVerifierInterface = cadesComponent.getTimeStampVerifier();
//        String timeStampIdentifier = PKCSObjectIdentifiers.id_aa_signatureTimeStampToken.getId();
//        String tsIdName = AttributeFactory.translateOid(timeStampIdentifier);


        this.timeStampReport = new TimeStampReport();
        this.timeStampReport.setTimeStampIdentifier(typeString);
        this.timeStampReport.setSchema(SignatureReport.SchemaState.VALID);

        boolean timeStampSet = timeStampVerifierInterface.setTimeStamp(contents, typeString, this.policy, timeReference,
                new ArrayList<>(), this.isLast);
        if (!timeStampSet) {
            this.timeStampReport.setSchema(SignatureReport.SchemaState.INVALID);
        }

        try {
            timeStampVerifierInterface.setupValidationData(this.timeStampReport);
        } catch (AIAException e) {
            e.printStackTrace();
            this.timeStampReport.setSchema(SignatureReport.SchemaState.INVALID);
        }

        boolean temp = timeStampVerifierInterface.verify(this.timeStampReport);
        if (!temp) {
            errorString += "Não foi possivel validar o carimbo do tempo do DocTimeStamp.";
        }
        isValid = isValid && temp;

        Time timeStampGenerationTime = timeStampVerifierInterface.getTimeStampGenerationTime();
        this.verifier.setTimeReference(timeStampGenerationTime);

        if (!isValid) {
            report.setError(true);
            this.setErrorMessages(timeStampVerifierInterface.getValidationErrors(), report);
            report.setWarningMessage(errorString);
            this.timeStampReport.setSchema(SignatureReport.SchemaState.INVALID);
        }

        return isValid;
    }

	/**
	 * Atribue a mensagem de erro ao relatório do atributo
	 * @param exceptions A lista de exceções que ocorreram na validação
	 * @param r O relatório do atributo onde será adiciona a mensagem de erro
	 */
	private void setErrorMessages(List<Exception> exceptions, AttribReport r) {
        StringBuilder errMsgs = new StringBuilder();
        int len = exceptions.size();
        for (int i = 0; i < len - 1; ++i) {
            String msg = exceptions.get(i).getMessage();
            errMsgs.append(msg).append(";");
        }
        errMsgs.append(exceptions.get(len - 1).getMessage()).append(".");
        r.setErrorMessage(errMsgs.toString());
    }

	/**
	 * Verifica se o carimbo é o último na assinatura
	 * @return Indica se o carimbo é o último na assinatura
	 */
	private boolean isLast() {
        return this.docTimeStampDictionary.getByteRange()[1] == this.verifier.getPadesSignature().getLastByteRangeDocTS();
    }

	/**
	 * Valida a entrada DSS no dicionário do carimbo de tempo
	 */
	private void validateDss() {
        PDDocumentCatalog catalog = verifier.getPadesSignature().getDocument().getDocumentCatalog();
        COSBase baseObject = catalog.getCOSObject();
        COSDictionary dictiObj = (COSDictionary) baseObject;
        COSDictionary dssDictionary = (COSDictionary) dictiObj.getDictionaryObject("DSS");

        DssAttribute dssDocTS = new DssAttribute(verifier, dssDictionary, this.vriHash);
        AttribReport dssDocTSReport = new AttribReport();
        dssDocTS.validate(dssDocTSReport);

    }

	/**
	 * Retorna o relatório do carimbo de tempo
	 * @return O relatório do carimbo de tempo
	 */
	public TimeStampReport getTimeStampReport() {
        return timeStampReport;
    }

}
