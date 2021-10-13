package br.ufsc.labsec.signature.conformanceVerifier.pades;

import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.DocTimeStampAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.PadesAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.report.TimeStampReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.BrExtDss;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.BrExtMandatedDocTSEntries;
import br.ufsc.labsec.signature.exceptions.NotInICPException;

import java.sql.Time;
import java.util.ArrayList;
import java.util.List;

/**
 * Esta classe implementa os métodos para verificação dos atributos de uma assinatura PAdES.
 */
public class PadesSignatureVerifier {

    /**
     * Componente de assinatura PAdES
     */
    private PadesSignatureComponent padesComponent;
    /**
     * Assinatura PAdES a ser verificada
     */
    private PadesSignature signature;
    /**
     * Data de referência para a verificação
     */
    private Time timeReference;
    /**
     * Lista de relatórios de carimbo de tempo
     */
    private List<TimeStampReport> timeStampReportList;
    /**
     * Lista de relatórios de atributos
     */
    private List<AttribReport> attReportList;

    /**
     * Construtor
     * @param component Componente de assinatura PAdES
     * @param signature Assinatura PAdES a ser verificada
     * @param timeReference Data de referência para a verificação
     */
    public PadesSignatureVerifier(PadesSignatureComponent component, PadesSignature signature, Time timeReference) {
        this.signature = signature;
        this.padesComponent = component;
        this.timeReference = timeReference;
        this.timeStampReportList = new ArrayList<TimeStampReport>();
        this.attReportList = new ArrayList<AttribReport>();
    }

    /**
     * Retorna os bytes da assinatura
     * @return Os bytes da assinatura
     */
    public byte[] getPDFbytes() {
        return this.signature.getPdfBytes();
    }

    /**
     * Retorna a política de assinatura
     * @return A política de assinatura
     */
    public SignaturePolicyInterface getSignaturePolicy() {
        return this.padesComponent.getSignaturePolicy();
    }

    /**
     * Retorna o componente de assinatura CAdES
     * @return O componente de assinatura CAdES
     */
    public CadesSignatureComponent getCadesSignatureComponent() {
        return padesComponent.getCadesSignatureComponent();
    }

    /**
     * Verifica os atributos da assinatura
     * @param last Indica se a assinatura é a última assinatura do documento
     */
    public void verify(boolean last) {
        List<String> attributeList = this.signature.getAttributeList(last);
        SignaturePolicyProxy policy = this.padesComponent.getSignaturePolicy();
        verifyPresenceOfMandatedAttributes(this.attReportList, attributeList, policy);
        this.signature.setLastByteRangeDocTS();

        for (String attribute : attributeList) {
            PadesAttribute attr;

            if (attribute.equals("DocTimeStamp")) {
                attr = this.signature.getEncodedAttribute("DocTimeStamp", this);
                AttribReport extraReport = new AttribReport();
                try {
                    attr.validate(extraReport);
                    this.timeStampReportList.add(((DocTimeStampAttribute) attr).getTimeStampReport());
                } catch (NotInICPException e) {
                    extraReport.setError(true);
                    extraReport.setErrorMessage(e.getMessage());
                }
                this.attReportList.add(extraReport);
            } else if (attribute.equals("DSS")) {
                if (this.signature.getSignatureType().equals("Sig")) {
                    attr = this.signature.getEncodedAttribute("DSS", this);
                    AttribReport extraReport = new AttribReport();
                    try {
                        attr.validate(extraReport);
                    } catch (NotInICPException e) {
                        extraReport.setError(true);
                        extraReport.setErrorMessage(e.getMessage());
                    }
                    this.attReportList.add(extraReport);
                }
            }
        }
    }

    /**
     * Verifica se todos os atributos obrigatórios estão presentes na assinatura
     * @param attReportList A lista de relatórios de atributos
     * @param attributeList Lista de atributos da asssinatura
     * @param policy A política de assinatura
     */
    private void verifyPresenceOfMandatedAttributes(
            List<AttribReport> attReportList, List<String> attributeList,
            SignaturePolicyProxy policy) {
        if (policy.verifierRulesExtensionExists(BrExtDss.IDENTIFIER)) {
            if (!attributeList.contains("DSS")) {
                String errorString = "PDF não contem o dicionário DSS.\n";
                AttribReport dssAttReport = new AttribReport();
                dssAttReport.setAttribName("DSS");
                dssAttReport.setErrorMessage(errorString);
                dssAttReport.setError(true);
                attReportList.add(dssAttReport);

            }
        }

        if (policy.verifierRulesExtensionExists(BrExtMandatedDocTSEntries.IDENTIFIER)) {
            if (!attributeList.contains("DocTimeStamp")) {
                String errorString = "PDF não contem o dicionário DocTimeStamp. \n";
                AttribReport docTimeStampAttReport = new AttribReport();
                docTimeStampAttReport.setAttribName("DocTimeStamp");
                docTimeStampAttReport.setErrorMessage(errorString);
                docTimeStampAttReport.setError(true);
                attReportList.add(docTimeStampAttReport);
            }
        }
    }

    /**
     * Retorna a data de referência
     * @return A data de referência
     */
    public Time getTimeReference() {
        return this.timeReference;
    }

    /**
     * Retorna a assinatura a ser verificada
     * @return A assinatura PAdES
     */
    public PadesSignature getPadesSignature() {
        return this.signature;
    }

    /**
     * Retorna a lista de relatórios de carimbo de tempo
     * @return A lista de relatórios de carimbo de tempo
     */
    public List<TimeStampReport> getTimeStampReportList() {
        return this.timeStampReportList;
    }

    /**
     * Atribue o valor da data de referência para a verificação
     * @param timeReference A nova data de referência
     */
    public void setTimeReference(Time timeReference) {
        this.timeReference = timeReference;
    }

    /**
     * Retorna a lista de relatórios de atributos
     * @return A lista de relatórios de atributos
     */
    public List<AttribReport> getAttReportList() {
        return this.attReportList;
    }

}
