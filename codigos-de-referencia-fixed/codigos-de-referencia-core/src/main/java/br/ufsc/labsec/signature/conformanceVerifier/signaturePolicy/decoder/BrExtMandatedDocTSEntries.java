package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;


/**
 * mandatedDocTSEntries ::= SEQUENCE of PdfEntry
 */

/**
 * Esta classe define os campos obrigatórios do carimbo do tempo do documento, que é inserido como uma
 * assinatura a parte no PDF. As entradas presentes nessa extensão são obrigatórias.
 */
public class BrExtMandatedDocTSEntries {

    public static final String IDENTIFIER = "2.16.76.1.8.3";
    /**
     * Lista das entradas obrigatórias
     */
    private List<PdfEntry> mandatedDocTSEntries;

    /**
     * Construtor usado para decodificar atributos da extensão em ASN1.
     * @param extensionValue codificação ASN1 dos atributos
     */
    public BrExtMandatedDocTSEntries(DEROctetString extensionValue) {

        byte[] octates = extensionValue.getOctets();
        ASN1Sequence sequence = null;

        try {
            sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(octates);
        } catch (IOException e) {
            e.printStackTrace();
        }

        this.mandatedDocTSEntries = new ArrayList<PdfEntry>();
        for (int i = 0; i < sequence.size(); i++) {
            PdfEntry pdfEntry = new PdfEntry((ASN1Sequence) sequence.getObjectAt(i));
            this.mandatedDocTSEntries.add(pdfEntry);
        }
    }

    /**
     * Retorna a lista das entradas obrigatórias
     * @return A lista das entradas obrigatórias
     */
    public List<PdfEntry> getMandatedDocTSEntries() {
        return mandatedDocTSEntries;
    }

}
