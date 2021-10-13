package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.security.cert.X509Certificate;
import java.sql.Time;
import java.util.List;

import org.bouncycastle.asn1.cms.Attribute;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.CounterSignatureInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CounterSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.VerificationException;


/**
 * Esta interface representa uma assinatura digital. Esta interface é estendida pela classe
 * {@link CadesSignature}. De acordo com o DOC-ICP-15 - * 6.1.3,
 * uma assinatura digital é um tipo de assinatura eletrônica que utiliza
 * um par de chaves criptográficas associado a um certificado digital.
 */
public interface Signature extends AbstractSignature {

	/**
	 * Obtém o identificador da PA (Política de Assinatura) utilizada nesta
	 * assinatura.
	 * 
	 * @return identificador da PA utilizada por esta assinatura.
	 * @throws PbadException 
	 */
	String getSignaturePolicyIdentifier() throws PbadException;

	/**
	 * Obtém a codificação de um atributo específico da assinatura. Se o
	 * atributo for do tipo CAdES, o <code>attribute</code> será um OID, se for
	 * do tipo XAdES, será o nome de uma tag. O <code>index</code> deve ser
	 * usado quando há mais de um atributo com o mesmo nome, caso contrário deve
	 * ter o valor zero. A classe {@link GenericEncoding} é usada como
	 * codificador pois ela trata o atributo conforme seu tipo (CAdES ou XAdES).
	 * 
	 * @param attribute
	 *            {@link String} de identificação do atributo.
	 * @param index
	 *            identificador da posição do atributo.
	 * @return codificação específica do atributo.
	 * @throws SignatureAttributeNotFoundException
	 */
	// GenericEncoding getEncodedAttribute(String attributeId, int index) throws
	// SignatureAttributeNotFoundException;

	/**
	 * Obtém a codificação do primeiro atributo com este identificador na
	 * assinatura. Se o atributo for do tipo CAdES, o <code>attribute</code>
	 * será um OID, se for do tipo XAdES, será o nome de uma tag
	 * @param attributeId O OID de identificação do atributo
	 * @return A codificação específica do atributo
	 * @throws SignatureAttributeNotFoundException
	 */
	Attribute getEncodedAttribute(String attributeId)
			throws SignatureAttributeNotFoundException;

	/**
	 * Verifica a integridade da assinatura.
	 * 
	 * @param signerCertificate
	 *            certificado do assinante.
	 * @return <code> true </code>, se a integridade da assinatura estiver
	 *         válida.
	 * @throws VerificationException
	 */
	boolean verify(X509Certificate signerCertificate,  SignatureReport sigReport)
			throws VerificationException;

	/**
	 * Verifica se o dado assinado é externo à assinatura.
	 * 
	 * @return <code> true </code>, se há algum dado assinado que é externo a
	 *         assinatura.
	 */
	boolean isExternalSignedData();

	/**
	 * Utiliza o algoritmo indicado para realizar o resumo criptográfico da
	 * assinatura.
	 * 
	 * @param algorithm
	 *            identificador do algoritmo de resumo criptográfico.
	 * @return bytes do resumo criptográfico da assinatura.
	 * @throws PbadException
	 */
	byte[] getSignatureValueHash(String algorithm) throws PbadException;

	/**
	 * Obtém a contra assinatura do detentor do certificado passado como
	 * parâmetro
	 * 
	 * @param signerCertificate
	 *            Certificado do contra assinante que se deseja obter a contra
	 *            assinatura
	 * @return Uma contra assinatura
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
	 * Os ultimos iténs indicados com * são opicionais e podem ou não estar
	 * presentes. Os outros dados devem necessáriamente estar presentes para que
	 * se possa obter o resumo criptográfico.
	 * @param algorithm O algoritmo a ser utilizado para o resumo
	 * @return Os bytes do resumo criptográfico
	 * @throws PbadException
	 */
	public byte[] getSigAndRefsHashValue(String algorithm) throws PbadException;


	/**
	 * Retorna o modo de assinatura
	 * @return O modo da assinatura
	 */
	public SignatureModeCAdES getMode() throws SignatureModeException;

	/**
	 * Obtem a URI da LPA que contém a política de assinatura da assinatura
	 * @return A URI da LPA
	 */
	public String getSignaturePolicyUri();

	/**
	 * Retorna o valor de hash da política
	 * @return O valor de hash da política
	 */
	public String getSignaturePolicyHashValue();

	public byte[] getArchiveTimeStampHashValue(String hashAlgorithmName)
			throws PbadException;

	public byte[] getArchiveTimeStampHashValue(String hashAlgorithmName,
			Time timeReference) throws PbadException;

	public SignatureContainer getContainer();
}
