package br.ufsc.labsec.signature.signer;

/**
 * Enumera os tipos de assinaturas possíveis
 */
public enum SignerType {
    CMS, PDF, XML,
    CAdES, PAdES, XAdES;

    // Prefixos dos OIDs de cada política de assinatura
    // de acordo com o DOC-ICP-15.03 versão 8.0
    private static final String CAdES_ADRB_OID_PREFIX = "2.16.76.1.7.1.1.";
    private static final String CAdES_ADRT_OID_PREFIX = "2.16.76.1.7.1.2.";
    private static final String CAdES_ADRV_OID_PREFIX = "2.16.76.1.7.1.3.";
    private static final String CAdES_ADRC_OID_PREFIX = "2.16.76.1.7.1.4.";
    private static final String CAdES_ADRA_OID_PREFIX = "2.16.76.1.7.1.5.";

    private static final String XAdES_ADRB_OID_PREFIX = "2.16.76.1.7.1.6.";
    private static final String XAdES_ADRT_OID_PREFIX = "2.16.76.1.7.1.7.";
    private static final String XAdES_ADRV_OID_PREFIX = "2.16.76.1.7.1.8.";
    private static final String XAdES_ADRC_OID_PREFIX = "2.16.76.1.7.1.9.";
    private static final String XAdES_ADRA_OID_PREFIX = "2.16.76.1.7.1.10.";

    private static final String PAdES_ADRB_OID_PREFIX = "2.16.76.1.7.1.11.";
    private static final String PAdES_ADRT_OID_PREFIX = "2.16.76.1.7.1.12.";
    private static final String PAdES_ADRC_OID_PREFIX = "2.16.76.1.7.1.13.";
    private static final String PAdES_ADRA_OID_PREFIX = "2.16.76.1.7.1.14.";

    public static final String CMS_STR = "CMS";
    public static final String PDF_STR = "PDF";
    public static final String XML_STR = "XML";

    /**
     * OID da política de assinatura
     */
    private String oid = "";

    /**
     * Retorna o OID da política de assinatura
     * @return OID da política de assinatura
     */
    @Override
    public String toString() {
        return oid;
    }

    /**
     * Identifica o tipo da política de assinatura pelo OID da política em caso de assinaturas avançadas
     * @param str O OID da política em caso de assinatura avançada, ou o tipo em caso de assinatura básica
     * @return O tipo de assinatura
     */
    public static SignerType fromString(String str) {
        SignerType policy = null;

        if (str.equals(CMS_STR)) {
            policy = CMS;
        } else if (str.equals(PDF_STR)) {
            policy = PDF;
        } else if (str.equals(XML_STR)) {
            policy = XML;
        } else if (str.startsWith(CAdES_ADRA_OID_PREFIX)
            || str.startsWith(CAdES_ADRB_OID_PREFIX)
            || str.startsWith(CAdES_ADRC_OID_PREFIX)
            || str.startsWith(CAdES_ADRT_OID_PREFIX)
            || str.startsWith(CAdES_ADRV_OID_PREFIX)) {
            policy = CAdES;
        } else if (str.startsWith(XAdES_ADRA_OID_PREFIX)
            || str.startsWith(XAdES_ADRB_OID_PREFIX)
            || str.startsWith(XAdES_ADRC_OID_PREFIX)
            || str.startsWith(XAdES_ADRT_OID_PREFIX)
            || str.startsWith(XAdES_ADRV_OID_PREFIX)) {
            policy = XAdES;
        } else if (str.startsWith(PAdES_ADRA_OID_PREFIX)
            || str.startsWith(PAdES_ADRB_OID_PREFIX)
            || str.startsWith(PAdES_ADRC_OID_PREFIX)
            || str.startsWith(PAdES_ADRT_OID_PREFIX)) {
            policy = PAdES;
        }

        if (policy != null) {
            policy.oid = str;
        }

        return policy;
    }

    /**
     * Indica se a assinatura é do tipo CAdES
     */
    public boolean isCAdES() {
        return this == CAdES;
    }

    /**
     * Indica se a assinatura é do tipo PAdES
     */
    public boolean isPAdES() {
        return this == PAdES;
    }

    /**
     * Indica se a assinatura é uma assinatura PDF simples ou avançada
     */
    public boolean isPdf() {
        return isPAdES() || this == PDF;
    }
}
