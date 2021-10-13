package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.util.Date;

/**
 * Esta classe engloba informações sobre uma referência OCSP
 */
public class OCSPRefs {

    /**
     * Data da criação da resposta
     */
    private Date producedAt;
    /**
     * Nome do emissor da resposta
     */
    private String responderName;
    /**
     * Chave do emissor da resposta
     */
    private byte[] responderKey;
    /**
     * Algoritmo utilizado para hash
     */
    private String algorithm;
    /**
     * Valor de hash do OCSP
     */
    private String digestValue;

    /**
     * Retorna o valor de hash do OCSP
     * @return O hash do OCSP
     */
    public String getDigestValue() {
        return this.digestValue;
    }

    /**
     * Atribue o nome do emissor da resposta
     * @return O nome do emissor da resposta
     */
    public String getResponderName() {
        return this.responderName;
    }

    /**
     * Atribue a chave do emissor da resposta
     * @return A chave do emissor da resposta
     */
    public byte[] getResponderKey() {
        return this.responderKey;
    }

    /**
     * Atribue a data da criação da resposta
     * @return A data da criação da resposta
     */
    public Date getProducedAt() {
        return this.producedAt;
    }

    /**
     * Retorna o algoritmo de hash
     * @return O algoritmo
     */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * Atribue o valor de hash do OCSP
     * @param digestValue O hash do OCSP
     */
    public void setDigestValue(String digestValue) {
        this.digestValue = digestValue;
    }

    /**
     * Atribue o algoritmo de hash
     * @param algorithm O algoritmo
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Retorna o nome do emissor da resposta
     * @param name O nome do emissor da resposta
     */
    public void setResponderName(String name) {
        this.responderName = name;
    }

    /**
     * Retorna a chave do emissor da resposta
     * @param responderKey A chave do emissor da resposta
     */
    public void setResponderKey(byte[] responderKey) {
        this.responderKey = responderKey;
    }

    /**
     * Retorna a data da criação da resposta
     * @param date A data da criação da resposta
     */
    public void setProducedAt(Date date) {
        this.producedAt = date;
    }

    /**
     * Verifica se o nome do emissor da resposta é vazio
     * @return Indica se o nome do emissor da resposta está vazio
     */
    public boolean isKeyName() {
        return (this.responderName.isEmpty());
    }

}
