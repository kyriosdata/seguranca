package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder;

import org.bouncycastle.asn1.ASN1Sequence;

import java.util.ArrayList;
import java.util.List;


///**
// * VriDictionary ::= SEQUENCE{
// * type PdfEntry,
// * timeReference TimeReferenceType OPTIONAL,
// * paArtifacts BOOLEAN DEFAULT FALSE
// * }
// * <p>
// * TimeReferenceType ::= ENUMERATED{
// * tu (0), -- data/hora em que o dicionário VRI foi inserido
// * ts (1) -- carimbo do tempo do tipo RFC 3161 codificado em BER
// * }
// */

/**
 * Esta classe representa o campo VriDictionary, que faz referência apenas a uma assinatura. Nele, é
 * possível indicar seu tipo, o timeReference, que é o tempo do momento da coleta
 * e validação das informações de validação da assinatura e do indicativo da
 * inclusão das PA e LPA utilizadas pela assinatura.
 *
 */
public class VriDictionary {

    /**
     * Enumeração do tipo de horário de referência
     */
    private enum TimeReferenceType {
        TU, TS
    }

    /**
     * Lista de entradas do dicionário VRI
     */
    private List<PdfEntry> sequenceOfPdfEntry;


    /**
     * Construtor usado para decodificar atributos da extensão em ASN1.
     * @param vriDicSequence O atributo em codificação ASN1
     */
    public VriDictionary(ASN1Sequence vriDicSequence) {

        this.sequenceOfPdfEntry = new ArrayList<PdfEntry>();

        for (int i = 0; i < vriDicSequence.size(); i++) {
            PdfEntry pdfEntry = new PdfEntry((ASN1Sequence) vriDicSequence.getObjectAt(i));
            this.sequenceOfPdfEntry.add(pdfEntry);
        }
    }

    /**
     * Retorna a lista de entradas do dicionário VRI
     * @return A lista de entradas
     */
    public List<PdfEntry> getSequenceOfPdfEntry() {
        return sequenceOfPdfEntry;
    }


}
