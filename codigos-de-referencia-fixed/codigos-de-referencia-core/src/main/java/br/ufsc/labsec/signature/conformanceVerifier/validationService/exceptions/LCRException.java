/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.validationService.exceptions;

import java.security.cert.Certificate;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção causada pela ausência de LCR.
 */
public class LCRException extends PbadException {

    private static final long serialVersionUID = 1L;
    public static final String CRL_NOT_FOUND = "CRL não encontrada.";
    /**
     * Certificado que possui erro na sua Lista de Certificados Revogados
     */
    private Certificate certWithError;

    /**
     * Construtor
     * @param cause A exceção que ocorreu durante a verificação
     * @param certWithError O certificado que causou o erro
     */
    public LCRException(Throwable cause, Certificate certWithError) {
        super(cause);
        this.certWithError = certWithError;
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param certWithError O certificado que causou o erro
     */
    public LCRException(String message, Certificate certWithError) {
        super(message);
        this.certWithError = certWithError;
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu durante a verificação
     * @param certWithError O certificado que causou o erro
     */
    public LCRException(String message, Exception cause, Certificate certWithError) {
        super(message, cause);
        this.certWithError = certWithError;
    }

    /**
     * Retorna o certificado com erro
     * @return O certificado que causou o erro
     */
    public Certificate getCertificate() {
        return this.certWithError;
    }
    
}
