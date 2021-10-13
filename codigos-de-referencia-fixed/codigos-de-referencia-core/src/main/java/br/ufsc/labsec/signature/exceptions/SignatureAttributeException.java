/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.exceptions;

import br.ufsc.labsec.signature.exceptions.PbadException;

public class SignatureAttributeException extends PbadException {

    /**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	public static final String INDEX_OUT_OF_BOUNDS = "Índice fora dos limites: ";
	public static final String ATTRIBUTE_IS_NOT_IMPLEMENTED_YET = "Atributo não implementado";
	public static final String STRUCTURE_VIOLATION = "A característica Assinado/Não-assinado foi violada";
	public static final String ATTRIBUTE_BUILDING_FAILURE = "Falha ao construir o atributo: ";
	public static final String NOT_GOT_HASH = "Não foi possível codificar o certificado para obter o hash";
	public static final String UNKNOW_ATTRIBUTE = "O algoritmo indicado pelo atributo não é conhecido";
	public static final String WRONG_ALGORITHM = "O atributo IdAaSigningCertificateV2 não pode usar o algoritmo"
			+ " SHA1. O SHA1 deve ser usado somente com o atributo IdAaSigningCertificate";
	public static final String HASH_FAILURE = "Problemas ao obter o hash";
	public static final String MISSING_CERTIFICATE_VALUES = "A propriedade não-assinada CertificateValues"
			+ " precisa estar presente na assinatura para construção do ArchiveTimeStamp";
	public static final String MISSING_REVOCATION_VALUES = "A propriedade não-assinada RevocationValues"
			+ " precisa estar presente na assinatura para construção do ArchiveTimeStamp";
	public static final String PROBLEMS_TO_DECODE = "Problemas para decodificar partes do atributo ";
	public static final String ATTRIBUTE_NOT_FOUND = "O atributo selecionado não foi encontrado na assinatura";
	public static final String UNSIGNED_PROPERTIES_NOT_FOUND = "Nenhuma propriedade não assinada foi encontrada"
			+ " na assinatura";
	public static final String INVALID_ISSUER_SERIAL = "Um dos atributos IssuerSerial do id-aa-SigningCertificate"
			+ " não está válido";
	public static final String INVALID_PA_OID = "Identificador da política de assinatura é inválido: ";
	public static final String WRONG_DISTINGUISHED_NAME_ORDER = "A ordem dos RDNs no campo IssuerSerial está incorreta";

    public SignatureAttributeException(String message) {
        super(message);
    }

    public SignatureAttributeException(String message, StackTraceElement[] stackTrace) {
        super(message);
        this.setStackTrace(stackTrace);
    }
    
    public SignatureAttributeException(String message, Throwable cause) {
        super(message, cause);
    }

    public SignatureAttributeException(Throwable cause) {
        super(cause);
    }

    public void setCritical(boolean critical) {
        super.setCritical(critical);
    }
}
