package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import br.ufsc.labsec.component.Application;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DEROctetString;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

///**
// * DssDictionary ::= SEQUENCE{
// * type PdfEntry,
// * vriDictionary VriDictionary OPTIONAL,
// * paArtifacts BOOLEAN DEFAULT FALSE
// * }
// */

/**
 * Esta classe representa o dicionário DSS, formado pela indicação do seu tipo, pelo campo
 * vriDictionary e pelo campo paArtifacts onde é possível indicar o armazenamento da PA e LPA.
 */
public class BrExtDss {

    public static final String IDENTIFIER = "2.16.76.1.8.2";
    /**
     * Lista do dicionário DSS
     */
    private List<PdfEntry> sequenceOfPdfEntry;
    /**
     * Dicionário VRI
     */
    private VriDictionary vriDictionary;


    /**
     * Construtor usado para decodificar atributos da extensão em ASN1.
     * @param extensionValue Os atributos em codificação ASN1
     */
    public BrExtDss(DEROctetString extensionValue) {
        byte[] octates = extensionValue.getOctets();
        ASN1Sequence attributes = null;
        ASN1Sequence dssDicSequence = null;
        try {
            dssDicSequence = (ASN1Sequence) ASN1Sequence.fromByteArray(octates);

        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }

        attributes = (ASN1Sequence) dssDicSequence.getObjectAt(0);

        this.sequenceOfPdfEntry = new ArrayList<PdfEntry>();
        for (int i = 0; i < attributes.size(); i++) {
            PdfEntry pdfEntry = new PdfEntry((ASN1Sequence) attributes.getObjectAt(i));
            this.sequenceOfPdfEntry.add(pdfEntry);
        }

        if (dssDicSequence.size() == 2) {
            ASN1Sequence vri = (ASN1Sequence) dssDicSequence.getObjectAt(1);
            this.vriDictionary = new VriDictionary(vri);
        }

    }

    /**
     * Retorna o dicionário VRI
     * @return O dicionário VRI
     */
    public VriDictionary getVriDictionary() {
        return this.vriDictionary;
    }

    /**
     * Retorna a lista de entradas do dicionário DSS
     * @return A lista de entradas
     */
    public List<PdfEntry> getDssDicEntries() {
        return this.sequenceOfPdfEntry;
    }


}
