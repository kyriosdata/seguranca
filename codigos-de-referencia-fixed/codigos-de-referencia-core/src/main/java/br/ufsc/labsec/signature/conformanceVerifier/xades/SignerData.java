/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.security.PrivateKey;
import java.security.cert.X509Certificate;

import br.ufsc.labsec.signature.PrivateInformation;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;

/**
 * Esta classe representa um assinante. Cada assinante deve ter uma chave privada e uma
 * chave pública correspondente.
 * 
 * De acordo com o DOC-ICP-15 - 6.1.3, um dos tipos de assinatura eletrônica é a
 * assinatura digital, que utiliza um par de chaves criptográficas associado a
 * um certificado digital. Uma das chaves é a chave privada que é usada durante
 * o processo de geração de assinatura e a outra é chave pública, contida no
 * certificado digital e usada durante a verificação da assinatura.
 */
public class SignerData implements PrivateInformation {

    /**
     * A chave privada do assinante
     */
    private PrivateKey key;
    /**
     * O certificado do assinante
     */
    private X509Certificate certificate;

    /**
     * Define um assinante. Cada assinante é composto por uma chave privada e um
     * certificado de chave pública correspondente à chave privada.
     * 
     * @param signingCertificate O certificado do assinante
     * @param key A chave do assinante
     * 
     * @throws SignerException
     */
    public SignerData(X509Certificate signingCertificate, PrivateKey key) throws SignerException {
        if (signingCertificate == null)
            throw new SignerException(SignerException.MISSING_CERTIFICATE);
        if (key == null)
            throw new SignerException(SignerException.MISSING_PRIVATE_KEY);
        this.certificate = signingCertificate;
        this.key = key;
    }

    /**
     * Retorna a chave privada do assinante
     * 
     * @return A chave privada do assinante
     */
    @Override
    public PrivateKey getPrivateKey() {
        return key;
    }

    /**
     * Retorna o certificado do assinante
     * 
     * @return O certificado do assinante
     */
    @Override
    public X509Certificate getCertificate() {
        return certificate;
    }
}
