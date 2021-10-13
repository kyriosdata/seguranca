/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe representa uma exceção que ocorre quando há mais de uma
 * ocorrência de um atributo em uma assinatura quando a quantidade máxima
 * permitida é apenas uma ocorrência.
 */
public class UniqueAttributeException extends SignatureAttributeException {

    private static final long serialVersionUID = 1L;
    public static final String DUPLICATED_ATTRIBUTE = "O seguinte atributo não pode ter mais que uma ocorrencia na assinatura: ";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public UniqueAttributeException(String message) {
        super(message);
    }

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param stackTrace O stack trace da exceção que ocorreu
     */
    public UniqueAttributeException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }

    /**
     * Construtor
     * @param invalidCertificate O identificador do certificado
     * @param name O nome do proprietário do certificado
     */
    public UniqueAttributeException(String invalidCertificate, String name) {
        super(invalidCertificate + name);
    }
}
