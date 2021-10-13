package br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions;

import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.IOException;

/**
 * Esta classe representa a presença de atualizações incrementais na assinatura.
 */
public class IncrementalUpdateException extends IUException {
    /**
     * Tipo da exceção
     */
    private ExceptionType type;
    public static final String FIELD_MPD_SIGNATURE_EXCEPTION_ALERT = "Modificações foram reprovadas pelo uso incorreto dos campos DocMDP\n" +
            "e FieldMDP contra o que foi especificado pelo autor original do documento.";
    public static final String MULTIPLE_SIGNATURES_EXCEPTION_ALERT = "A existência de múltiplas assinaturas são reprovadas " +
            "contra o que foi especificado pelo autor original do documento, pelos campos DocMDP e FieldMDP";

    /**
     * Contrutor
     * @param indexInSignatureDictionary Índice da assinatura com erro
     * @param message Mensagem de erro
     * @param type O tipo da causa da exceção
     */
    private IncrementalUpdateException(int indexInSignatureDictionary, String message, ExceptionType type) {
       super(message, indexInSignatureDictionary);
        this.type = type;
    }

    /**
     * Gera uma exceção causada por erro na modificação incremental
     * @param indexInSignatureDictionary Indice da assinatura
     * @param modification A modificação com erro
     * @param type O tipo da exceção
     */
    public static void throwExceptionFromModification(
            int indexInSignatureDictionary, String modification, ExceptionType type) throws IncrementalUpdateException {
        throw new IncrementalUpdateException(
                indexInSignatureDictionary,
                "Foi reprovado um(a) " + modification + " não especificado(a) pelo autor original do documento, com campos DocMDP e FieldMDP.",
                type);
    }

    /**
     * Gera uma exceção causada por erro na modificação incremental
     * @param document O documento PDF
     * @param modification A modificação com erro
     * @param type O tipo da exceção
     */
    public static void throwExceptionFromModification(
            PDDocument document, String modification, ExceptionType type) throws IncrementalUpdateException {
        try {
            throwExceptionFromModification(
                    document.getSignatureDictionaries().size()-1, modification, type);
        } catch (IOException e) {
            throwExceptionFromModification( 0, modification, type);
        }
    }

    /**
     * Gera uma exceção causada pela presença de múltiplas assinaturas
     * @param indexInSignatureDictionary Indice da assinatura
     * @param type O tipo da exceção
     */
    public static void throwExceptionFromSignatureCount(int indexInSignatureDictionary, ExceptionType type)
    throws IncrementalUpdateException{
        throw new IncrementalUpdateException(indexInSignatureDictionary, MULTIPLE_SIGNATURES_EXCEPTION_ALERT, type);
    }

    /**
     * Gera uma exceção causada pela presença de múltiplas assinaturas
     * @param document O documento PDF
     * @param type O tipo da exceção
     */
    public static void throwExceptionFromSignatureCount(PDDocument document, ExceptionType type)
    throws IncrementalUpdateException {
        try {
            throwExceptionFromSignatureCount(document.getSignatureDictionaries().size()-1, type);
        } catch (IOException e) {
            throwExceptionFromSignatureCount(0, type);
        }
    }

    /**
     * Gera uma exceção causada por valor incorreto no campo FieldMDP
     * @param indexInSignatureDictionary Indice da assinatura
     * @param type O tipo da exceção
     */
    public static void throwExceptionFromFieldMDP(int indexInSignatureDictionary, ExceptionType type)
    throws IncrementalUpdateException {
        throw new IncrementalUpdateException(indexInSignatureDictionary, FIELD_MPD_SIGNATURE_EXCEPTION_ALERT, type);
    }

    /**
     * Gera uma exceção causada por valor incorreto no campo FieldMDP
     * @param document O documento PDF
     * @param type O tipo da exceção
     */
    public static void throwExceptionFromFieldMDP(PDDocument document, ExceptionType type)
    throws IncrementalUpdateException {
        try {
            throwExceptionFromFieldMDP(document.getSignatureDictionaries().size()-1, type);
        } catch (IOException e) {
            throwExceptionFromFieldMDP(0, type);
        }
    }

    /**
     * Retorna o tipo da exceção
     * @return O tipo da exceção
     */
    public ExceptionType getType() {
        return type;
    }

    /**
     * Enumeração da causa da exceção
     */
    public enum ExceptionType {
        GENERATED_FROM_HASH, GENERATED_FROM_COMPARISON
    }
}
