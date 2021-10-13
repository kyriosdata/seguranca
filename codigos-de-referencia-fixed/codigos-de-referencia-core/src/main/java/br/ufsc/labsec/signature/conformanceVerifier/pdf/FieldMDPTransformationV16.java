package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.PossibleIncrementalUpdateException;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSObject;
import org.apache.pdfbox.cos.COSObjectKey;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException.ExceptionType;

/**
 * Esta classe é responsável por detectar mudanças nos valores
 * dos campos de formulário de um arquivo PDF.
 */
public class FieldMDPTransformationV16 extends FieldMDPTransformation {

    /**
     * Construtor
     * @param signatureReference Dicionário da assinatura
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @throws IOException
     */
    public FieldMDPTransformationV16(COSDictionary signatureReference, PDDocument document, PDDocument previousVersion) throws IOException {
        super(signatureReference, document, previousVersion);
    }

    /**
     * Construtor
     * @param signatureReference Dicionário da assinatura
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @param p Índice do parâmetro de transformação
     * @throws IOException
     */
    public FieldMDPTransformationV16(COSDictionary signatureReference, PDDocument document, PDDocument previousVersion, int p) throws IOException {
        super(signatureReference, document, previousVersion, p);
    }

    /**
     * Realiza a transformação. Verifica se houveram mudanças no arquivo.
     * @throws IncrementalUpdateException Exceção em caso de haver atualizações incrementais na assinatura
     * @throws PossibleIncrementalUpdateException Exceção em caso de não ser possível identificar
     *  quais modificações incrementais foram feitas após uma assinatura
     */
    @Override
    public void fieldMDPTransform() throws IncrementalUpdateException, PossibleIncrementalUpdateException {
        try {
            FieldAndAnnotationEvaluation evaluation = new FieldAndAnnotationEvaluation(mdpFields, this.document, this.previousVersion, this.p);
            // Manually compare objects
            for (int i = 0; i < mdpFields.size(); i++) {
                COSObjectKey key = mdpFields.get(i);
                COSObject previousObject = evaluation.getFirstVersion().getDocument().getObjectFromPool(key);
                COSObject actualObject = evaluation.getActualVersion().getDocument().getObjectFromPool(key);
                List<Action> differences = evaluation.getDifferences(actualObject, previousObject);
                differences = differences.stream().filter(p -> p.getPath().hasNext() &&
                        PDDocumentUtils.isFieldEntry(p.getPath().getNext().getName())).collect(Collectors.toList());
                if (!differences.isEmpty()) {
                    IncrementalUpdateException.throwExceptionFromFieldMDP(previousVersion, ExceptionType.GENERATED_FROM_COMPARISON);
                }
            }
        } catch (IOException e) {
            PossibleIncrementalUpdateException.throwExceptionFromNoVerification(previousVersion);
        }
    }
}
