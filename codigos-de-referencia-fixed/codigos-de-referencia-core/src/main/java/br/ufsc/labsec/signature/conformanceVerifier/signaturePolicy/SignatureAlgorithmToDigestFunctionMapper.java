/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy;

import java.util.Hashtable;
import java.util.Map;

import javax.xml.crypto.dsig.DigestMethod;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.CMSSignedGenerator;

/**
 * Esta classe é usada para fazer o mapeamento entre um algoritmo de assinatura para um
 * algoritmo de resumo criptográfico
 * 
 */
public class SignatureAlgorithmToDigestFunctionMapper {
    /**
     * Mapa que relaciona um algoritmo de assinatura a um algoritmo de resumo criptográfico
     */
    static Map<String, String> map = new Hashtable<String, String>();

    static {
        map.put("http://www.w3.org/2000/09/xmldsig#rsa-sha1", DigestMethod.SHA1);
        map.put("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256", DigestMethod.SHA256);
        // map.put("http://www.w3.org/2000/09/xmldsig#rsa-sha384", "sha-384");
        // Não Suportado
        map.put("http://www.w3.org/2000/09/xmldsig#rsa-sha512", DigestMethod.SHA512);
        map.put(PKCSObjectIdentifiers.sha1WithRSAEncryption.getId(), CMSSignedDataGenerator.DIGEST_SHA1);
        map.put(PKCSObjectIdentifiers.sha256WithRSAEncryption.getId(), CMSSignedDataGenerator.DIGEST_SHA256);
        map.put(PKCSObjectIdentifiers.sha512WithRSAEncryption.getId(), CMSSignedDataGenerator.DIGEST_SHA512);
        map.put(PKCSObjectIdentifiers.sha384WithRSAEncryption.getId(), CMSSignedDataGenerator.DIGEST_SHA384);
    }

    /**
     * Retorna o nome do algoritmo de resumo critográfico a partir do
     * identificador do algoritmo de assinatura
     * 
     * @param identifier Identificador do algoritmo de assinatura.
     *                  No caso de assinaturas CAdES, o identificador será um
     *            membro da classe {@link CMSSignedGenerator} ou um OID, e no
     *            caso do XAdES, será uma URL
     * 
     * @return O nome do algoritmo de resumo critográfico correspondente
     */
    public static String getAlgorithmNameFromIdentifier(String identifier) {
        return map.get(identifier);
    }
}
