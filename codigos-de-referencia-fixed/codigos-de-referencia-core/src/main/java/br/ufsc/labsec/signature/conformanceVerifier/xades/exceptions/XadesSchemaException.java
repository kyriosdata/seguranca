package br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa uma exceção que ocorreu durante a validação
 * do esquema XML.
 */
public class XadesSchemaException extends PbadException {

    public static final String CONNECTION_DISRUPTED =
            "Não foi possível validar o schema da assinatura por problemas " +
                    "de conexão. Por favor, tente novamente.";

    /**
     * Construtor
     * @param message A mensagem de erro
     * @param cause A exceção que ocorreu
     */
    public XadesSchemaException(String message, Throwable cause) {
        super(message, cause);
    }

}
