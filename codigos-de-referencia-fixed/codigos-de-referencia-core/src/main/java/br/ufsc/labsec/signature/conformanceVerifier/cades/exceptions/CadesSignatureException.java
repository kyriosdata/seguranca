/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

public class CadesSignatureException extends PbadException {

    private static final long serialVersionUID = 1L;

    public CadesSignatureException(String message) {
        super(message);
    }

    public CadesSignatureException(Throwable cause) {
        super(cause);
    }

    public CadesSignatureException(String message, Throwable cause) {
        super(message, cause);
    }

}
