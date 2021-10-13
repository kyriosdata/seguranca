/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions;

/**
 * Essa exceção indica que a assinatura não foi feita seguindo a totalidade de
 * regras impostas pela política de assinatura.
 */
public class SignatureConformityException extends ValidationException {

    private static final long serialVersionUID = 1L;
    public static final String INVALID_SIZE_KEY = "Tamanho da chave inválido";
    public static final String INVALID_ALGORITHM = "Algoritmos inválidos presentes na assinatura";

    /**
     * Construtor
     * @param message A mensagem de erro
     */
    public SignatureConformityException(String message) {
        super(message);
    }

    /**
     * Construtor.
     * Utiliza a mensagem padrão de erro
     */
    public SignatureConformityException() {
        super(SignatureConformityException.STANDART_ERROR);
    }

    /**
     * Construtor
     * @param invalidAttributes Array de atributos inválidos
     * @throws SignatureConformityException
     */
    public SignatureConformityException(String[] invalidAttributes) throws SignatureConformityException {
        StringBuilder message = new StringBuilder();
        if (invalidAttributes.length == 1) {
            message.append("Não foi encontrado o atributo não assinado obrigatório: ");
        } else
            message.append("Não foram encontrados os atributos não assinados obrigatórios: ");
        for (int i = 0; i < invalidAttributes.length - 1; i++) {
            if (invalidAttributes[i] != null)
                message.append(invalidAttributes[i]).append(", ");
        }
        message.append(invalidAttributes[invalidAttributes.length - 1]).append(".");
        throw new SignatureConformityException(message.toString());
    }

}
