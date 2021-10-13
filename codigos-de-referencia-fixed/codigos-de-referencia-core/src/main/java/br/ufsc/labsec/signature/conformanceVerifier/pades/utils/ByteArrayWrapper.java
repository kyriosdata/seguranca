package br.ufsc.labsec.signature.conformanceVerifier.pades.utils;

import java.util.Arrays;

/**
 * Wrapper de um array de bytes
 */
public class ByteArrayWrapper {

    /**
     * Array de bytes
     */
    private byte[] byteArray;

    /**
     * Construtor
     * @param byteArray O array de bytes
     */
    public ByteArrayWrapper(byte[] byteArray) {
        this.byteArray = byteArray;
    }

    /**
     * Retorna o array de bytes
     * @return O array de bytes
     */
    public byte[] getByteArray() {
        return byteArray;
    }

    /**
     * Verifica a igualdade entre dois objetos ByteArrayWrapper
     * @param obj O objeto a ser comparado
     * @return Indica se os dois objetos são iguais
     */
    @Override
    public boolean equals(Object obj) {
        ByteArrayWrapper toCompare = (ByteArrayWrapper) obj;
        return Arrays.equals(this.byteArray, toCompare.getByteArray());
    }

    /**
     * Função de hash do ByteArrayWrapper
     * @return O hash do objeto
     */
    @Override
    public int hashCode() {
        return Arrays.hashCode(this.byteArray);
    }
}
