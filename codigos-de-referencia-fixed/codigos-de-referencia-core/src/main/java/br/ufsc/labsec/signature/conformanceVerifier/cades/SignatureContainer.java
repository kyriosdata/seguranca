/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.OutputStream;

import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.exceptions.EncodingException;

/**
 * Esta interface representa um contêiner de assinaturas
 */
public interface SignatureContainer {

	/**
	 * Retorna o número de assinaturas contidas nesse contêiner. Isso inclui
	 * somente assinaturas em paralelo.
	 * 
	 * @return O número de assinaturas presentes.
	 */
	public int getSignatureCount();

	/**
	 * Retorna a assinatura de índice <code> index </code>, contida no
	 * contêiner.
	 * 
	 * @param index O índice da assinatura
	 * 
	 * @return A assinatura correspondente ao índice dado
	 * 
	 * @throws EncodingException
	 */
	public CadesSignature getSignatureAt(int index) throws EncodingException;

	/**
	 * Escreve a assinatura, já codificada para seu formato, no
	 * {@link OutputStream} desejado.
	 * 
	 * @param outputStream O stream que conterá a assinatura.
	 * 
	 * @throws EncodingException
	 */
	public void encode(OutputStream outputStream) throws EncodingException;

	/**
	 * Retorna o conteúdo do contêiner codificado em bytes. Este método é útil
	 * para quando se quer gravar as assinaturas em disco ou as enviar pela
	 * rede.
	 * 
	 * @return Os bytes do conteúdo do contêiner
	 * 
	 * @throws EncodingException
	 */
	public byte[] getBytes() throws EncodingException;

	/**
	 * Informa se uma assinatura está assinando algo que não está anexado ao
	 * arquivo da mesma, ou seja, se o conteúdo assinado é destacado da
	 * assinatura. Esse método é útil principalmente para assinaturas do tipo
	 * <b>CAdES</b>, que normalmente não possuí método para encontrar o arquivo
	 * assinado, logo esse método explicita a necessidade de se informar ou não
	 * qual o conteúdo foi assinado.
	 * 
	 * @return Indica se a assinatura possui conteúdo destacado
	 * 
	 * @throws EncodingException
	 */
	public boolean hasDetachedContent() throws EncodingException;

	/**
	 * Obtém o modo de assinatura
	 * 
	 * @param index O índice da assinatura dentro do contêiner
	 * 
	 * @return O modo da assinatura indicada
	 */
	public SignatureModeCAdES getMode(Integer index) throws SignatureModeException,
			EncodingException;
}
