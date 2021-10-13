package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

///**
// * mandatedPdfSigDicEntries ::= SEQUENCE of PdfEntry
// * PdfEntry ::= SEQUENCE {
// * PdfEntryId UTF8String,
// * PdfEntryValue OCTET STRING OPTIONAL
// * }
// */

/**
 * Esta classe representa uma extensão que contém todas as entradas obrigatórias e, opcionalmente, seu
 * valor que deverá constar na assinatura
 */
public class BrExtMandatedPdfSigDicEntries {

    public static final String IDENTIFIER = "2.16.76.1.8.1";
    /**
     * Lista das entradas obrigatórias
     */
    private List<PdfEntry> mandatedPdfSigDicEntries;

    /**
     * Construtor usado para decodificar atributos da extensão em ASN1.
     * @param extensionValue codificação ASN1 dos atributos
     */
    public BrExtMandatedPdfSigDicEntries(DEROctetString extensionValue) {
        byte[] octates = extensionValue.getOctets();
        ASN1Sequence sequence = null;
        mandatedPdfSigDicEntries = new ArrayList<PdfEntry>();
        try {
            sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(octates);
        } catch (IOException e) {
            e.printStackTrace();
        }
        for (int i = 0; i < sequence.size(); i++) {
            PdfEntry pdfEntry = new PdfEntry((ASN1Sequence) sequence.getObjectAt(i));
            this.mandatedPdfSigDicEntries.add(pdfEntry);
        }
    }

    /**
     * Retorna a lista das entradas obrigatórias
     * @return A lista das entradas obrigatórias
     */
    public List<PdfEntry> getMandatedPdfSigDicEntries() {
        return this.mandatedPdfSigDicEntries;
    }

}
