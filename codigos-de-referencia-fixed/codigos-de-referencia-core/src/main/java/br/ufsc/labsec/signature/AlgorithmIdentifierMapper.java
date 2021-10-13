/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature;

import java.util.Hashtable;
import java.util.Map;

import org.bouncycastle.cms.CMSSignedGenerator;

/**
 * Classe responsável por fazer o mapeamento entre o identificador de algoritmo
 * pelo seu nome.
 */
public class AlgorithmIdentifierMapper {
    static Map<String, String> map = new Hashtable<String, String>();

    static {
        map.put(CMSSignedGenerator.DIGEST_SHA1, "sha-1");
        map.put(CMSSignedGenerator.DIGEST_SHA224, "sha-224");
        map.put(CMSSignedGenerator.DIGEST_SHA256, "sha-256");
        map.put(CMSSignedGenerator.DIGEST_SHA384, "sha-384");
        map.put(CMSSignedGenerator.DIGEST_SHA512, "sha-512");
        map.put(CMSSignedGenerator.DIGEST_MD5, "md5");
        map.put(CMSSignedGenerator.DIGEST_GOST3411, "gost3411");
        map.put(CMSSignedGenerator.DIGEST_RIPEMD128, "ripemd-128");
        map.put(CMSSignedGenerator.DIGEST_RIPEMD160, "ripemd-160");
        map.put(CMSSignedGenerator.DIGEST_RIPEMD256, "ripemd-256");
        map.put("1.3.14.3.2.24", "MD2withRSA");
        map.put("1.3.14.3.2.25", "MD5withRSA");
        map.put("1.2.840.113549.1.1.4", "MD5WithRSAEncryption");
        map.put("1.2.840.113549.1.1.5", "SHA1withRSA");
        map.put("1.3.36.3.3.1.3", "RIPEMD128withRSA");
        map.put("1.3.36.3.3.1.2", "RIPEMD160withRSA");
        map.put("1.3.36.3.3.1.4", "RIPEMD256withRSA");
        map.put("1.2.840.10040.4.3", "SHA1withDSA");
        map.put("1.2.840.10045.4.1", "SHA1withECDSA");
        map.put("1.2.840.10045.4.3.1", "SHA224withECDSA");
        map.put("1.2.840.10045.4.3.2", "SHA256withECDSA");
        map.put("1.2.840.10045.4.3.3", "SHA384withECDSA");
        map.put("1.2.840.10045.4.3.4", "SHA512withECDSA");
        map.put("1.2.840.113549.1.1.14", "SHA224withRSA");
        map.put("1.2.840.113549.1.1.11", "SHA256withRSA");
        map.put("1.2.840.113549.1.1.12", "SHA384withRSA");
        map.put("1.2.840.113549.1.1.13", "SHA512withRSA");
        map.put("1.3.6.1.4.1.11591.15.1", "Ed25519");
        map.put("1.3.101.112", "Ed25519");
        map.put("1.3.101.113", "Ed448");
        map.put("http://www.w3.org/2000/09/xmldsig#sha1", "sha-1");
        map.put("http://www.w3.org/2001/04/xmlenc#sha256", "sha-256");
        map.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", "rsa-sha-1");
        map.put("http://www.w3.org/2000/09/xmldsig#dsa-sha1", "dsa-sha-1");
        map.put("http://www.w3.org/2009/xmldsig11#dsa-sha256", "dsa-sha-256");
        map.put("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "hmac-sha-1");
        map.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", "rsa-sha-256");
        map.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384", "rsa-sha-384");
        map.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512", "rsa-sha-512");
        map.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1", "ecdsa-sha-1");
        map.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256", "ecdsa-sha-256");
        map.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384", "ecdsa-sha-384");
        map.put("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512", "ecdsa-sha-512");
        map.put("SHA1withDSA", "http://www.w3.org/2000/09/xmldsig#dsa-sha1");
        map.put("SHA1withRSA", "http://www.w3.org/2000/09/xmldsig#rsa-sha1");
        map.put("SHA256withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        map.put("SHA384withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha384");
        map.put("SHA512withRSA", "http://www.w3.org/2001/04/xmldsig-more#rsa-sha512");
        map.put("SHA1withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha1");
        map.put("SHA256withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256");
        map.put("SHA384withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384");
        map.put("SHA512withECDSA", "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512");
    }

    /**
     * Retorna o nome do algoritmo a partir do identificador do algoritmo.
     * 
     * @param identifier - identificador de algoritmo de acordo com o seu padrão
     *            (ASN.1 ou XML).
     * @return nome do algoritmo
     */
    public static String getAlgorithmNameFromIdentifier(String identifier) {
        return map.get(identifier);
    }
}
