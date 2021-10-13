package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;

/**
 * Esta classe define a estrutura que decodifica entrada do dicionario de assinatura e,
 * opcionalmente, seu valor.
 */
public class PdfEntry {

    /**
     * Identificador da entrada
     */
    private DERUTF8String pdfEntryId;
    /**
     * Valor da entrada
     */
    private DEROctetString pdfEntryValue;


    /**
     * Decodifica nome e valor contido no ASN1
     * @param sequence Objeto ASN. que contém a entrada do dicionário
     */
    public PdfEntry(ASN1Sequence sequence) {
        int index = 0;
        ASN1Encodable derEncodable = sequence.getObjectAt(index);
        pdfEntryId = (DERUTF8String) derEncodable;
        if (sequence.size() == 2) {
            derEncodable = sequence.getObjectAt(++index);
            pdfEntryValue = (DEROctetString) derEncodable;
        }
    }

    /**
     * Retorna o identificador da entrada
     * @return O identificador da entrada
     */
    public String getPdfEntryID() {
        return pdfEntryId.getString();
    }

    /**
     * Retorna o valor da entrada
     * @return O valor da entrada
     */
    public byte[] getPdfEntryValue() {
        if (pdfEntryValue == null) {
            return null;
        }
        return pdfEntryValue.getOctets();
    }

}
