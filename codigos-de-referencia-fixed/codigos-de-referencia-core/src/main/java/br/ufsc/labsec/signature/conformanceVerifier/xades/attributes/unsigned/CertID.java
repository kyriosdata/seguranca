package br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned;

import java.math.BigInteger;

/**
 * Esta classe engloba informações sobre um certificado
 */
public class CertID {

    /**
     * Nome do emissor
     */
    private String issuerName;
    /**
     * Número de série do certificado
     */
    private BigInteger serialNumber;
    /**
     * Algoritmo utilizado para hash
     */
    private String algorithm;
    /**
     * Valor de hash do certificado
     */
    private byte[] certificateDigest;

    /**
     * Retorna o nome do emissor
     * @return O nome do emissor
     */
    public String getName() {
        return this.issuerName;
    }

    /**
     * Retorna o número de série
     * @return O número de série
     */
    public BigInteger getSerialNumber() {
        return this.serialNumber;
    }

    /**
     * Retorna o algoritmo de hash
     * @return O algoritmo
     */
    public String getAlgorithm() {
        return this.algorithm;
    }

    /**
     * Retorna o valor de hash do certificado
     * @return O hash do certificado
     */
    public byte[] getCertificateDigest() {
        return this.certificateDigest;
    }

    /**
     * Atribue o nome do emissor
     * @param name O nome do emissor
     */
    public void setName(String name) {
        this.issuerName = name;
    }

    /**
     * Atribue o número de série do certificado
     * @param serialNumber O número de série
     */
    public void setSerialNumber(BigInteger serialNumber) {
        this.serialNumber = serialNumber;
    }

    /**
     * Atribue o algoritmo de hash
     * @param algorithm O algoritmo
     */
    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    /**
     * Atribue o valor de hash do certificado
     * @param certificateDigest O hash do certificado
     */
    public void setCertificateDigest(byte[] certificateDigest) {
        this.certificateDigest = certificateDigest;
    }

}
