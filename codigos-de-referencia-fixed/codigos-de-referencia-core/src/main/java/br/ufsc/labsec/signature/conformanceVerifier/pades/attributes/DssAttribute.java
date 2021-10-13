package br.ufsc.labsec.signature.conformanceVerifier.pades.attributes;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.pades.exceptions.DictionaryException;
import br.ufsc.labsec.signature.conformanceVerifier.pades.utils.DSSDecoder;
import br.ufsc.labsec.signature.conformanceVerifier.pades.utils.VRIEntries;
import br.ufsc.labsec.signature.conformanceVerifier.pades.utils.VRIValidator;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.BrExtDss;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.PdfEntry;
import org.apache.pdfbox.cos.*;
import br.ufsc.labsec.signature.Verifier;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.logging.Level;

/**
 * Esta classe representa o atributo DSS de uma assinatura PAdES.
 * Implementa {@link PadesAttribute}.
 */
public class DssAttribute implements PadesAttribute {

    /**
     * Dicionário do atributo
     */
    private final COSDictionary dssDictionary;
    /**
     * Valor do resumo criptográfico da assinatura
     */
    private final String signatureHash;
    /**
     * O {@link Verifier} de assinatura PAdES
     */
    private PadesSignatureVerifier verifier;
    /**
     * A política de assinatura
     */
    private SignaturePolicyProxy policy;

    /**
     * Construtor
     * @param verifier {@link Verifier} de assinatura PAdES
     * @param dssDictionary Dicionário do atributo
     * @param signatureHash Valor do resumo criptográfico da assinatura
     */
    public DssAttribute(PadesSignatureVerifier verifier, COSDictionary dssDictionary, String signatureHash) {
        this.dssDictionary = dssDictionary;
        this.verifier = verifier;
        this.policy = (SignaturePolicyProxy) this.verifier.getSignaturePolicy();
        this.signatureHash = signatureHash.toUpperCase();
    }

    /**
     * Resolve a política de assinatura armazenada no DSS, se existe uma.
     * @param policyOid
     * @return Verdadeiro se foi possível adquirir uma política para essa assinatura e Falso
     * caso contrário.
     */
    public boolean resolvePolicy(String policyOid) {
        if (this.dssDictionary != null) {
            String policyArtifactAttr = VRIEntries.PBAD_PolicyArtifact.name();
            String lpaSignatureAttr = VRIEntries.PBAD_LpaSignature.name();
            String lpaArtifactAttr = VRIEntries.PBAD_LpaArtifact.name();
            COSDictionary vriDictionary = (COSDictionary) dssDictionary.getDictionaryObject("VRI");
            vriDictionary = (COSDictionary) vriDictionary.getDictionaryObject(this.signatureHash);
            if (vriDictionary != null
                    && vriDictionary.containsKey(policyArtifactAttr)
                    && vriDictionary.containsKey(lpaArtifactAttr)) {
                try {
                    InputStream paArtifact = extractStreamFromVriArtifact(vriDictionary, policyArtifactAttr);
                    InputStream lpaArtifact = extractStreamFromVriArtifact(vriDictionary, lpaArtifactAttr);
                    InputStream lpaSigArtifact = extractStreamFromVriArtifact(vriDictionary, lpaSignatureAttr);
                    SignaturePolicyProxy signaturePolicyProxy = (SignaturePolicyProxy) verifier.getSignaturePolicy();
                    signaturePolicyProxy.setActualPolicy(policyOid, lpaArtifact, lpaSigArtifact, paArtifact, SignaturePolicyInterface.AdESType.PAdES);
                    return true;
                } catch (Exception e) {
                    Application.logger.log(Level.WARNING, "Não foi possível utilizar a política presente no dicionário de VRI");
                }
            }
        }
        return false;
    }

    /**
     * Extrai um stream de dados do dicionário de VRI
     * @param vri Dicionário VRI
     * @param entry entrada no dicionário a ser extraída
     * @return O {@link InputStream} de dados presente na entrada.
     */
    public InputStream extractStreamFromVriArtifact(COSDictionary vri, String entry) {
        COSArray paArtifacts = (COSArray) vri.getDictionaryObject(entry);
        COSObject paArtifactIndirectStream = (COSObject) paArtifacts.get(0);
        COSStream paArtifactStream = (COSStream) paArtifactIndirectStream.getObject();
        byte[] artifact = DSSDecoder.extractDataFromCOSStream(paArtifactStream);
        return new ByteArrayInputStream(artifact);
    }

    /**
     * Valida o atributo
     * @param report O relatório do atributo que será validado
     * @return Indica se o atributo é válido
     */
    @Override
    public boolean validate(AttribReport report) {
        report.setAttribName("DSS");
        StringBuilder errMsgBuilder = new StringBuilder();

        BrExtDss policyDss = policy.verifierRulesGetBrExtDss();
        if (policyDss == null) {
            errMsgBuilder.append(dssDefaultEntriesValidation());
            errMsgBuilder.append(vriDefaultValidation());
        } else {
            errMsgBuilder.append(dssEntriesValidation(policyDss));
            errMsgBuilder.append(vriValidation(policyDss));
        }

        String err = errMsgBuilder.toString();
        if (!err.equals("")) {
            report.setError(true);
            report.setErrorMessage(err);
            return false;
        }

        return true;
    }

    /**
     * Verifica se o dicionário do atributo possui todas as entradas obrigatórias
     * @return Uma String que indica quais entradas obrigatórias não estão presentes no dicionário,
     * ou uma String vazia caso todas estejam presentes.
     */
    private String dssDefaultEntriesValidation() {
        String[] mandatoryDSSEntries = {"Type", "Certs", "VRI"};
        List<String> remainingEntries = new ArrayList<>();

        for (String entry : mandatoryDSSEntries) {
            if (!dssDictionary.containsKey(entry))
                remainingEntries.add(entry);
        }

        return (remainingEntries.size() == 0) ?
                "" : dictionaryValidationErr("DSS", remainingEntries, false);
    }

    /**
     * Verifica se o dicionário VRI possui todas as entradas obrigatórias
     * @return Uma String que indica quais entradas obrigatórias não estão presentes no dicionário,
     * uma String vazia caso todas estejam presentes, ou uma mensagem de erro caso a entrada VRI
     * não esteja presente
     */
    private String vriDefaultValidation() {
        String[] mandatoryVRIEntries = {"Type", "Cert"};
        List<String> remainingEntries = new ArrayList<>();
        COSDictionary vriDictionary = (COSDictionary) dssDictionary.getDictionaryObject("VRI");

        String typeEntryError = vriEntryTypeValidation(vriDictionary);

        COSDictionary signatureVri = (COSDictionary) vriDictionary.getDictionaryObject(signatureHash);
        if (signatureVri == null) {
            return VRIValidator.VRI_NOT_FOUND_MESSAGE;
        } else {
            for (String entry : mandatoryVRIEntries) {
                if (!signatureVri.containsKey(entry))
                    remainingEntries.add(entry);
            }
        }

        return (remainingEntries.size() == 0) ?
                "" : dictionaryValidationErr("VRI", remainingEntries, false) + typeEntryError;
    }

    /**
     * Verifica o valor da entrada 'Type' do dicionário VRI
     * @param vri O dicionário VRI
     * @return Uma String que indica se o valor  da entrada 'Type' não é o esperado,
     * ou uma String nula caso o valor esteja correto
     */
    private String vriEntryTypeValidation(COSDictionary vri) {
        String err = "";
        String entryTypeValue = vri.getNameAsString("Type");
        if (vri.containsKey("Type") && !entryTypeValue.equals("VRI"))
            err = " Valor da entrada \"Type\" do VRI é " + entryTypeValue + ", mas deve ser \"VRI\".";
        return err;
    }

    /**
     * Valida os valores de 'ValidationValues' do dicionário do atributo
     * @param policyDss A entrada DSS da política de assinatura
     * @return Uma String que indica se há entradas no dicionário da política sem 'ValidationValues',
     * ou uma String nula caso todas as entradas possuam 'ValidationValues'
     */
    private String dssEntriesValidation(BrExtDss policyDss) {
        List<String> remainingEntries = new ArrayList<>();
        List<PdfEntry> policyEntries = policyDss.getDssDicEntries();
        for (PdfEntry pdfEntry : policyEntries) {
            String pdfEntryId = pdfEntry.getPdfEntryID();
            if (pdfEntryId.equals("ValidationValues")) {
                this.verifyValidationValues(remainingEntries, pdfEntry);
            } else {
                this.addRemainingEntry(remainingEntries, pdfEntryId);
            }
        }
        return (remainingEntries.size() == 0) ?
                "" : dictionaryValidationErr("DSS", remainingEntries, true);
    }

    /**
     * Verifica os valores de uma entrada 'ValidationValues'
     * @param remainingEntries Lista de entradas obrigatórias no dicionário que não estão presentes
     *                         na assinatura
     * @param vv A entrada no dicionário cujo 'ValidationValues' será verificado
     */
    private void verifyValidationValues(List<String> remainingEntries, PdfEntry vv) {
        int value = DSSDecoder.getValidationValue(vv.getPdfEntryValue()).intValue();
        String crl = VRIEntries.CRL.name() + "s";
        String ocsp = VRIEntries.OCSP.name() + "s";

        switch (value) {
            case 0:
                this.addRemainingEntry(remainingEntries, crl);
                break;
            case 1:
                this.addRemainingEntry(remainingEntries, ocsp);
                break;
            case 2:
                if (!dssDictionary.containsKey(crl) && !dssDictionary.containsKey(ocsp))
                    remainingEntries.add(crl + " ou " + ocsp);
                break;
            case 3:
                this.addRemainingEntry(remainingEntries, crl);
                this.addRemainingEntry(remainingEntries, ocsp);
                break;
        }
    }

    /**
     * Adiciona um novo elemento no dicionário do atributo
     * @param remainingEntries A lista onde o elemento será adicionado
     * @param e A entrada a ser adicionada
     */
    private void addRemainingEntry(List<String> remainingEntries, String e) {
        if (!dssDictionary.containsKey(e))
            remainingEntries.add(e);
    }

    /**
     * Cria uma String com uma mensagem de quais entradas obrigatórias estão faltando no dicionário
     * @param dictName Nome do dicionário
     * @param remainingEntries Lista das entradas obrigatórias que não estão presentes
     * @param paValidation
     * @return A String criada
     */
    private String dictionaryValidationErr(String dictName, List<String> remainingEntries, boolean paValidation) {
        StringBuilder err = new StringBuilder(dictName).append(" não contém");
        String accordingPA;
        if (paValidation)
            accordingPA = " exigidas pela PA: ";
        else
            accordingPA = ": ";

        if (Objects.requireNonNull(remainingEntries).size() == 1) {
            err.append(" a entrada '").append(remainingEntries.get(0)).append("' exigida pela PA");
        } else {
           err.append(" as seguintes entradas obrigatórias").append(accordingPA);
           for (int i = 0; i < remainingEntries.size() - 1; i++)
               err.append(remainingEntries.get(i)).append(", ");
           err.append(remainingEntries.get(remainingEntries.size() - 1));
        }

        return err + ". ";
    }

    /**
     * Valida o dicionário VRI do atributo
     * @param policyDss A entrada DSS da política de assinatura
     * @return Uma String que indica se há entradas obrigatórias que não estão presente no dicionário,
     * ou uma String nula caso não haja nenhuma entrada faltante
     */
    private String vriValidation(BrExtDss policyDss) {
        COSDictionary vriDictionary = (COSDictionary) this.dssDictionary.getDictionaryObject("VRI");
        COSBase baseDic = vriDictionary.getDictionaryObject(signatureHash);
        VRIValidator validator = new VRIValidator((COSDictionary) baseDic, policyDss.getVriDictionary());
        try {
            List<String> remainingEntries = validator.validation(this.verifier);
            return remainingEntries.size() == 0 ?
                    "" : dictionaryValidationErr("VRI", remainingEntries, true);
        } catch (DictionaryException e) {
            return e.getMessage();
        }
    }

}
