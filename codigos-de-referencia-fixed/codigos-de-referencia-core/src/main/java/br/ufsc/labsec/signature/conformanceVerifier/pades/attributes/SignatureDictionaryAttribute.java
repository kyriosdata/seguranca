package br.ufsc.labsec.signature.conformanceVerifier.pades.attributes;

import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.report.AttribReport;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.PdfEntry;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1String;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;

/**
 * Esta classe representa o atributo Dicionário de uma assinatura PAdES.
 */
public class SignatureDictionaryAttribute implements PadesAttribute {

    /**
     * A assinatura a qual o atributo pertence
     */
    private PDSignature signature;
    /**
     * O relatório do atributo
     */
    private AttribReport report;
    /**
     * Componente de assinatura PAdES
     */
    private PadesSignatureComponent padesComponent;

    /**
     * Construtor
     * @param signatureObj A assinatura que contém o atributo
     * @param component Componente de assinatura PAdES
     */
    public SignatureDictionaryAttribute(PDSignature signatureObj, PadesSignatureComponent component) {
        signature = signatureObj;
        padesComponent = component;
    }

    /**
     * Valida o atributo e adiciona o resultado ao relatório dado
     * @param attrReport O relatório do atributo que será validado
     * @return Indica se o atributo é válido
     */
    @Override
    public boolean validate(AttribReport attrReport) {
        SignaturePolicyProxy sigPolicyProxy = (SignaturePolicyProxy) padesComponent.signaturePolicyInterface;
        if (sigPolicyProxy.getSignaturePolicy() == null)
            return false;

        this.report = attrReport;
        List<PdfEntry> entries =
                sigPolicyProxy.signerRulesGetBrExtMandatedPdfSigDicEntries().getMandatedPdfSigDicEntries();
        return validEntries(entries, signature.getCOSObject());
    }

    /**
     * Valida as entradas do Dicionário
     * @param entries As entradas esperadas no dicionário
     * @param sigDic As entradas do dicionário da assinatura
     * @return Indica se todas as entradas são válidas
     */
    private boolean validEntries(List<PdfEntry> entries, COSDictionary sigDic) {
        boolean valid = true;
        for (PdfEntry entry : entries) {
            String key = entry.getPdfEntryID();
            byte[] paValueOctets = entry.getPdfEntryValue();
            if (sigDic.containsKey(key) && paValueOctets != null) {
                valid &= evaluation(key, paValueOctets, sigDic);
            }
        }
        return valid;
    }

    /**
     * Avalia a validade da entrada do dicionário
     * @param key Nome da entrada no dicionário
     * @param paValueOctets Valor em array de bytes da entrada
     * @param sigDic O dicionário da assinatura
     * @return Indica se a entrada é válida
     */
    private boolean evaluation(String key, byte[] paValueOctets, COSDictionary sigDic) {
        String paValue = octetsToString(paValueOctets);
        COSName sigDicEntryCOSName = (COSName) sigDic.getDictionaryObject(key);
        String sigDicValue = sigDicEntryCOSName.getName();
        boolean valid = paValue != null && paValue.equals(sigDicValue);
        if (!valid)
            treatInvalid(key, sigDicValue, paValue);
        return valid;
    }

    /**
     * Adiciona uma mensagem de alerta no relatório quando há algum problema no atributo
     * @param key Nome da entrada com erro
     * @param v Valor da entrada no dicionário
     * @param expected Valor esperado da entrada no dicionário
     */
    private void treatInvalid(String key, String v, String expected) {
        String currWarning = report.getWarningMessage() == null ? "" : report.getWarningMessage();
        if (v == null) {
            report.setWarningMessage(currWarning + " Ausência da entrada obrigatória 'Filter'.");
        } else if (!v.equals(expected)) {
            report.setWarningMessage(currWarning + " Valor da entrada '" + key + "' incorreto "
                    + "(" + v +" em vez de " + expected +").");
        }
    }

    /**
     * Transforma o array de bytes em uma String
     * @param octets O array de bytes de octetos
     * @return A String referente aos octetos
     */
    private String octetsToString(byte[] octets) {
        String str;
        InputStream inStrem = new ByteArrayInputStream(octets);
        try {
            str = ((ASN1String) new ASN1InputStream(inStrem).readObject()).getString();
        } catch (IOException e) {
            return null;
        }
        return str;
    }

}
