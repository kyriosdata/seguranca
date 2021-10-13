/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.repository.PKCS12IdentityService.exceptions;

import java.security.cert.Certificate;

import br.ufsc.labsec.signature.exceptions.PbadException;

public class LCRException extends PbadException {

    /**
	 * 
	 */
    private static final long serialVersionUID = 1L;
    public static final String CRL_NOT_FOUND = "CRL não encontrada.";
    private Certificate certWithError;
    
    public LCRException(Throwable cause, Certificate certWithError) {
        super(cause);
        this.certWithError = certWithError;
    }

    public LCRException(String message, Certificate certWithError) {
        super(message);
        this.certWithError = certWithError;
    }

    public LCRException(String message, Exception cause, Certificate certWithError) {
        super(message, cause);
        this.certWithError = certWithError;
    }
    
    public Certificate getCertificate() {
        return this.certWithError;
    }
    
}
