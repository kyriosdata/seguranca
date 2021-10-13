package br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions;

/**
 * Esta classe representa um erro causado por uma modificação incremental
 * na assinatura.
 */
public class IUException extends Throwable {
    /**
     * Índice da assinatura que causou o erro
     */
    private int indexInSignatureDictionary;

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param indexInSignatureDictionary Índice da assinatura que causou o erro
     */
    public IUException(String message, int indexInSignatureDictionary) {
        super(message);
        this.indexInSignatureDictionary = indexInSignatureDictionary;
    }

    /**
     * Retorna o índice da assinatura que causou o erro
     * @return O índice da assinatura que causou o erro
     */
    public int getIndexInSignatureDictionary() {
        return indexInSignatureDictionary;
    }

    /**
     * Comparação entre dois objetos desta exceção
     */
    public static class Comparator implements java.util.Comparator<IUException> {
        @Override
        public int compare(IUException t1, IUException t2) {
            return t1.indexInSignatureDictionary - t2.indexInSignatureDictionary;
        }
    }
}
