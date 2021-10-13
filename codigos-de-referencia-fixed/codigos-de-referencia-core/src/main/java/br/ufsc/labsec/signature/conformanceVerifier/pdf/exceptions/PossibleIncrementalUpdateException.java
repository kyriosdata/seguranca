package br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions;

import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.IOException;

/**
 * Esta classe representa o erro gerado quando não é possível identificar
 * quais modificações incrementais foram feitas após uma assinatura.
 */
public class PossibleIncrementalUpdateException extends IUException {
    public static final String NO_VERIFICATION_ALERT = "Não foi possível identificar se modificações incrementais foram feitas" +
            " após esta assinatura";

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param indexInSignatureDictionary Índice da assinatura com erro
     */
    private PossibleIncrementalUpdateException(String message, int indexInSignatureDictionary) {
        super(message, indexInSignatureDictionary);
    }

    /**
     * Gera uma exceção causada por modificações incrementais
     * @param modification A modificação
     * @param indexInSignatureDictionary Índice da assinatura
     */
    public static void throwExceptionFromModification(String modification, int indexInSignatureDictionary)
    throws PossibleIncrementalUpdateException {
        throw new PossibleIncrementalUpdateException(
                "Foi identificado um(a) " + modification + ". Porém, não é definido nenhum métodos implementado de " +
                        "verificação para modificações incrementais pelo autor original do documento", indexInSignatureDictionary);
    }

    /**
     * Gera uma exceção causada por modificações incrementais
     * @param modification A modificação
     * @param document O documento PDF
     */
    public static void throwExceptionFromModification(String modification, PDDocument document)
    throws PossibleIncrementalUpdateException {
        try {
            throwExceptionFromModification(modification, document.getSignatureDictionaries().size() - 1);
        } catch (IOException e) {
            throwExceptionFromModification(modification, 0);
        }
    }

    /**
     * Gera uma exceção causada por erro durante a verificação das modificações
     * @param indexInSignatureDictionary Índice da assinatura
     */
    public static void throwExceptionFromNoVerification(int indexInSignatureDictionary)
    throws PossibleIncrementalUpdateException{
        throw new PossibleIncrementalUpdateException(NO_VERIFICATION_ALERT, indexInSignatureDictionary);
    }

    /**
     * Gera uma exceção causada por erro durante a verificação das modificações
     * @param document O documento PDF
     */
    public static void throwExceptionFromNoVerification(PDDocument document)
    throws PossibleIncrementalUpdateException {
        try {
            throwExceptionFromNoVerification(document.getSignatureDictionaries().size() - 1);
        } catch (IOException e) {
            throwExceptionFromNoVerification(0);
        }
    }
}
