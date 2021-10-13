package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.math.BigInteger;
import java.util.Date;

/**
 * Esta classe engloba informações sobre uma referência CRL
 */
public class CRLRefs {

    /**
     * Algoritmo utilizado para hash
     */
    private String algorithm;
    /**
     * Valor de hash da CRL
     */
    private String digestValue;
    /**
     * Nome do emissor
     */
    private String issuerName;
    /**
     * Data da emissão da CRL
     */
    private Date issueTime;
    /**
     * Número da CRL
     */
    private BigInteger crlNumber;

    /**
     * Retorna o nome do emissor
     * @return O nome do emissor
     */
    public String getName() {
        return this.issuerName;
    }

    /**
     * Retorna o valor de hash da CRL
     * @return O hash da CRL
     */
    public String getDigestValue() {
        return this.digestValue;
    }

    /**
     * Retorna o algoritmo de hash
     * @return O algoritmo
     */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * Retorna a data de emissão
     * @return A data de emissão
     */
    public Date getDate() {
        return this.issueTime;
    }

    /**
     * Retorna o número da CRL
     * @return O número da CRL
     */
    public BigInteger getCrlNumber() {
        return this.crlNumber;
    }

    /**
     * Atribue o nome do emissor
     * @param name O nome do emissor
     */
    public void setName(String name) {
        this.issuerName = name;
    }

    /**
     * Atribue o valor de hash da CRL
     * @param digestValue O hash da CRL
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
     * Atibue a data de emissão
     * @param date A data de emissão
     */
    public void setIssueTime(Date date) {
        this.issueTime = date;
    }

    /**
     * Atribue o número da CRL
     * @param crlNumber O número da CRL
     */
    public void setCrlNumber(BigInteger crlNumber) {
        this.crlNumber = crlNumber;
    }

}