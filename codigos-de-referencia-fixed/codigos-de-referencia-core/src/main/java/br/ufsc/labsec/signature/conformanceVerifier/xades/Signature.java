package br.ufsc.labsec.signature.conformanceVerifier.xades;

import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.List;

import org.w3c.dom.Element;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.CounterSignatureInterface;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.CounterSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.xades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.VerificationException;

/**
 * Esta interface representa uma assinatura digital. Esta interface é estendida pela classe
 * {@link XadesSignature}. De acordo com o DOC-ICP-15 - 6.1.3,
 * uma assinatura digital é um tipo de assinatura eletrônica que utiliza
 * um par de chaves criptográficas associado a um certificado digital.
 */
public interface Signature extends AbstractSignature {

	/**
	 * Obtém o identificador da PA (Política de Assinatura) utilizada nesta
	 * assinatura
	 * 
	 * @return identificador da PA utilizada por esta assinatura
	 */
	String getSignaturePolicyIdentifier();

	/**
	 * Obtém a codificação do primeiro atributo com este identificador na
	 * assinatura. Se o atributo for do tipo CAdES, o <code>attribute</code>
	 * será um OID, se for do tipo XAdES, será o nome de uma tag
	 * @param attributeId {@link String} de identificação do atributo
	 * @return A codificação específica do atributo
	 * @throws SignatureAttributeNotFoundException
	 */
	Element getEncodedAttribute(String attributeId)
			throws SignatureAttributeNotFoundException;

	/**
	 * Verifica a integridade da assinatura
	 * 
	 * @param signerCertificate O certificado do assinante
	 * @return <code> true </code>, se a integridade da assinatura estiver
	 *         válida
	 * @throws VerificationException
	 */
	boolean verify(X509Certificate signerCertificate, SignatureReport sigReport)
			throws VerificationException;

	/**
	 * Verifica se o dado assinado é externo à assinatura
	 * 
	 * @return <code> true </code>, se há algum dado assinado que é externo a
	 *         assinatura
	 */
	boolean isExternalSignedData();

	/**
	 * Utiliza o algoritmo indicado para realizar o resumo criptográfico da
	 * assinatura
	 * 
	 * @param algorithm O identificador do algoritmo de resumo criptográfico
	 * @return Os bytes do resumo criptográfico da assinatura
	 * @throws PbadException Exceção em caso de algoritmo inválido
	 */
	byte[] getSignatureValueHash(String algorithm) throws PbadException;

	/**
	 * Obtém a contra assinatura do detentor do certificado passado como
	 * parâmetro
	 * 
	 * @param signerCertificate O certificado do contra assinante que se deseja obter a contra
	 *            assinatura
	 * @return A contra assinatura
	 * @throws CounterSignatureException
	 */
	CounterSignatureInterface getCounterSignature(
			X509Certificate signerCertificate) throws CounterSignatureException;

	/**
	 * Retorna todas as contra assinaturas anexadas a uma assinatura, se não
	 * existir contra assinaturas é retornado null
	 * 
	 * @return A lista de contra assinaturas
	 */
	List<CounterSignatureInterface> getCounterSignatures();

	/**
	 * Utiliza o algoritmo indicado para realizar o resumo criptográfico das
	 * seguintes informações em ordem: - Valor da assinatura - Carimbo do tempo
	 * da assinatura - Referências de certificados completa - Referências de
	 * dados de validação completa - Referências de certificados de atributo
	 * completas* - Referências de dados de validação de certificados de
	 * atributo completa*
	 * 
	 * Os ultimos iténs indicados com * são opcionais e podem ou não estar
	 * presentes. Os outros dados devem necessáriamente estar presentes para que
	 * se possa obter o resumo criptográfico
	 * 
	 * @param algorithm O algoritmo a ser utilizado para o resumo
	 * @return Os bytes do resumo criptográfico
	 * @throws PbadException
	 */
	public byte[] getSigAndRefsHashValue(String algorithm) throws PbadException;

	/**
	 * Obtém o formato da assinatura
	 * @return O formato da assinatura
	 */
	public SignatureFormat getFormat();

	/**
	 * Obtém o modo de assinatura
	 * @return O modo de assinatura
	 */
	public ContainedSignatureMode getMode() throws SignatureModeException;

	/**
	 * Obtem a URI da LPA que contém a Política de Assinatura da assinatura
	 * 
	 * @return A URI da LPA
	 */
	public String getSignaturePolicyUri();

	/**
	 * Retorna o valor do resumo criptográfico da Política de Assinatura
	 * @return O valor do resumo criptográfico da PA
	 */
	public String getSignaturePolicyHashValue();

	/**
	 * Utiliza o algoritmo indicado para realizar o resumo criptográfico
	 * do carimbo de tempo de arquivamento.
	 * @param hashAlgorithmOid O OID do algoritmo a ser utilizado para o resumo
	 * @return Os bytes do resumo criptográfico
	 * @throws PbadException
	 */
	public byte[] getArchiveTimeStampHashValue(String hashAlgorithmOid)
			throws PbadException;

	/**
	 * Utiliza o algoritmo indicado para realizar o resumo criptográfico
	 * do carimbo de tempo de arquivamento.
	 * @param hashAlgorithm O algoritmo a ser utilizado para o resumo
	 * @param timeReference A data de referência do carimbo
	 * @return Os bytes do resumo criptográfico
	 * @throws PbadException
	 */
	public byte[] getArchiveTimeStampHashValue(String hashAlgorithm,
			Time timeReference) throws PbadException;

	/**
	 * Retorna o contêiner de assinatura
	 * @return O contêiner de assinatura
	 */
	public SignatureContainer getContainer();
}
