/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.signature.ContentToBeSigned;

/**
 * Esta classe contém informações do conteúdo a ser assinado e os bytes do mesmo.
 * Implementa {@link ContentToBeSigned}.
 */
public class CadesContentToBeSigned implements ContentToBeSigned {

	/** Tipo do conteúdo a ser assinado. Ex: id-data (1.2.840.113549.1.7.1) */
	protected String eContentType;
	/** Modo de encapsulamento da assinatura (DETACHED ou ATTACHED) */
	protected SignatureModeCAdES signatureMode;
	/** Provedor de assinatura. Ex: BC */
	protected String signatureProvider;
	/** Representa os bytes do conteúdo a ser assinado. */
	protected byte[] contentToBeSigned;
	/** Representa o arquivo do conteúdo a ser assinado. */
	protected File contentFileToBeSigned;
	/** InputStream do conteúdo a ser assinado. */
	protected InputStream contentStreamToBeSigned;
	/** Valor de hash do conteúdo da assinautra */
	private byte[] contentHash;

	/**
	 * O tipo do conteúdo assinado nesse construtor é default do tipo id-data
	 * (OId = 1.2.840.113549.1.7.1). O Provider Bouncy Castle é utilizado.
	 * @param contentToBeSigned O conteúdo que será assinado.
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>.
	 */
	public CadesContentToBeSigned(byte[] contentToBeSigned,
			SignatureModeCAdES signatureMode) {
		this(PKCSObjectIdentifiers.data.getId(), contentToBeSigned,
				signatureMode);
	}

	/**
	 * O tipo do conteúdo assinado nesse construtor é default do tipo id-data
	 * (OId = 1.2.840.113549.1.7.1).
	 * 
	 * @param contentToBeSigned  O conteúdo que será assinado
	 * @param signatureMode  O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 * @param provider O Provider a ser utilizado na assinatura
	 */
	public CadesContentToBeSigned(byte[] contentToBeSigned,
			SignatureModeCAdES signatureMode, String provider) {
		this(PKCSObjectIdentifiers.data.getId(), contentToBeSigned,
				signatureMode, provider);
	}

	/**
	 * Este construtor é usado quando se quer construir um
	 * {@link CadesContentToBeSigned} com o conteúdo assinado diferente de
	 * id-data. O Provider Bouncy Castle é utilizado.
	 * 
	 * @param eContentType  O tipo do documento que será assinado. Ex: id-data
	 * @param contentToBeSigned O conteúdo que será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 */
	public CadesContentToBeSigned(String eContentType,
			byte[] contentToBeSigned, SignatureModeCAdES signatureMode) {
		this(eContentType, contentToBeSigned, signatureMode, "BC");
	}

	/**
	 * Este construtor é usado quando se quer construir um
	 * {@link CadesContentToBeSigned} com o conteúdo assinado diferente de
	 * id-data.
	 * 
	 * @param eContentType O tipo do documento que será assinado. Ex: id-data
	 * @param contentToBeSigned  O conteúdo que será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 * @param provider O Provider a ser utilizado na assinatura
	 */
	public CadesContentToBeSigned(String eContentType,
			byte[] contentToBeSigned, SignatureModeCAdES signatureMode,
			String provider) {
		this.eContentType = eContentType;
		this.contentToBeSigned = contentToBeSigned;
		this.signatureMode = signatureMode;
		this.signatureProvider = provider;
	}

	/**
	 * O tipo do conteúdo assinado nesse construtor é default do tipo id-data
	 * (OId = 1.2.840.113549.1.7.1). O Provider Bouncy Castle é utilizado.
	 * 
	 * @param contentToBeSigned O arquivo que contém conteúdo que
	 *            será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 */
	public CadesContentToBeSigned(File contentToBeSigned,
			SignatureModeCAdES signatureMode) {
		this(PKCSObjectIdentifiers.data.getId(), contentToBeSigned,
				signatureMode);
	}

	/**
	 * O tipo do conteúdo assinado nesse construtor é default do tipo id-data
	 * (OId = 1.2.840.113549.1.7.1).
	 * 
	 * @param contentToBeSigned O arquivo que contém conteúdo que
	 *            será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 * @param provider O Provider a ser utilizado na assinatura
	 */
	public CadesContentToBeSigned(File contentToBeSigned,
			SignatureModeCAdES signatureMode, String provider) {
		this(PKCSObjectIdentifiers.data.getId(), contentToBeSigned,
				signatureMode, provider);
	}

	/**
	 * Este construtor é usado quando se quer construir um
	 * {@link CadesContentToBeSigned} com o conteúdo assinado diferente de
	 * id-data. O Provider Bouncy Castle é utilizado.
	 *
	 * @param eContentType  O tipo do documento que será assinado. Ex: id-data
	 * @param contentToBeSigned O arquivo que contém conteúdo que
	 *            será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 */
	public CadesContentToBeSigned(String eContentType, File contentToBeSigned,
			SignatureModeCAdES signatureMode) {
		this(eContentType, contentToBeSigned, signatureMode, "BC");
	}

	/**
	 * Este construtor é usado quando se quer construir um
	 * {@link CadesContentToBeSigned} com o conteúdo assinado diferente de
	 * id-data.
	 * 
	 * @param eContentType O tipo do documento que será assinado. Ex: id-data
	 * @param contentToBeSigned O arquivo que contém conteúdo que
	 *            será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 * @param provider  O Provider a ser utilizado na assinatura
	 */
	public CadesContentToBeSigned(String eContentType, File contentToBeSigned,
			SignatureModeCAdES signatureMode, String provider) {
		this.eContentType = eContentType;
		this.contentFileToBeSigned = contentToBeSigned;
		this.signatureMode = signatureMode;
		this.signatureProvider = provider;
	}

	/**
	 * O tipo do conteúdo assinado nesse construtor é default do tipo id-data
	 * (OId = 1.2.840.113549.1.7.1). O Provider Bouncy Castle é utilizado.
	 * 
	 * @param contentToBeSigned O conteúdo que será assinado.
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>.
	 */
	public CadesContentToBeSigned(InputStream contentToBeSigned,
			SignatureModeCAdES signatureMode) {
		this(PKCSObjectIdentifiers.data.getId(), contentToBeSigned,
				signatureMode);
	}

	/**
	 * O tipo do conteúdo assinado nesse construtor é default do tipo id-data
	 * (OId = 1.2.840.113549.1.7.1).
	 * 
	 * @param contentToBeSigned O conteúdo que será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 * @param provider O Provider a ser utilizado na assinatura
	 */
	public CadesContentToBeSigned(InputStream contentToBeSigned,
			SignatureModeCAdES signatureMode, String provider) {
		this(PKCSObjectIdentifiers.data.getId(), contentToBeSigned,
				signatureMode, provider);
	}

	/**
	 * Este construtor é usado quando se quer construir um
	 * {@link CadesContentToBeSigned} com o conteúdo assinado grande que deve
	 * ser processado como um stream. O Provider Bouncy Castle é utilizado.
	 * 
	 * @param eContentType O tipo do documento que será assinado. Ex: id-data
	 * @param contentToBeSigned  {@link InputStream} que representa o arquivo que contém
	 *            conteúdo que será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 */
	public CadesContentToBeSigned(String eContentType,
			InputStream contentToBeSigned, SignatureModeCAdES signatureMode) {
		this(eContentType, contentToBeSigned, signatureMode, "BC");
	}

	/**
	 * Este construtor é usado quando se quer construir um
	 * {@link CadesContentToBeSigned} com o conteúdo assinado grande que deve
	 * ser processado como um stream.
	 * 
	 * @param eContentType O tipo do documento que será assinado. Ex: id-data
	 * @param contentToBeSigned {@link InputStream} que representa o arquivo que contém
	 *            conteúdo que será assinado
	 * @param signatureMode O modo de assinatura DEVE ser <code>DETACHED</code> ou
	 *            <code>ATTACHED</code>
	 * @param provider O Provider que deve ser utilizado
	 */
	public CadesContentToBeSigned(String eContentType,
			InputStream contentToBeSigned, SignatureModeCAdES signatureMode,
			String provider) {
		this.eContentType = eContentType;
		this.signatureMode = signatureMode;
		this.signatureProvider = provider;

		this.contentStreamToBeSigned = contentToBeSigned;
	}

	/**
	 * Retorna o modo de assinatura do conteúdo
	 * @return O modo de assinatura do conteúdo
	 */
	public SignatureModeCAdES getSignatureMode() {
		return this.signatureMode;
	}

	/**
	 * Retorna os bytes do conteúdo que será assinado
	 * @return Os bytes do conteúdo que será assinado
	 */
	public byte[] getContentToBeSigned() {
		return this.contentToBeSigned;
	}

	/**
	 * Retorna o identificador do tipo do conteúdo que será assinado
	 * @return O identificador do tipo do conteúdo que será assinado
	 */
	public String geteContentType() {
		return this.eContentType;
	}

	/**
	 * Retorna o provedor de assinatura. Por exemplo "BC" do Bouncy Castle.
	 * @return O provedor de assinatura
	 */
	public String getSigProvider() {
		return this.signatureProvider;
	}

	/**
	 * Informa se o conteúdo deve ser tratado como potencialmente grande demais
	 * para caber na memória
	 * @return Indica se o conteúdo é muito grande para ser mantido inteiro em memória
	 */
	public boolean isStreamed() {
		boolean isStreamed = this.contentFileToBeSigned != null
				|| this.contentStreamToBeSigned != null;
		return isStreamed;
	}

	/**
	 * Retorna o conteúdo na forma de {@link File}. Ideal para arquivos grandes,
	 * pois só com o {@link File} que é possível o uso de Streaming para
	 * assinar. Porém esse construtor só estará disponível se algum dos
	 * construtores que possuem {@link File} for usado.
	 * @return O conteúdo a ser assinado
	 */
	public File getContentToBeSignedAsFile() {
		return this.contentFileToBeSigned;
	}

	/**
	 * Retorna o conteúdo a ser assinado como um Stream
	 * @return O conteudo a ser assinado como um Stream
	 * @throws FileNotFoundException Exceção caso o arquivo do conteúdo não exista
	 */
	public InputStream getContentToBeSignedAsStream()
			throws FileNotFoundException {
		if (this.contentStreamToBeSigned != null) {
			return this.contentStreamToBeSigned;
		} else if (this.contentFileToBeSigned != null) {
			return new FileInputStream(this.contentFileToBeSigned);
		} else {
			return null;
		}
	}

	/**
	 * Atribue o valor de hash do conteúdo
	 * @param hash O valor de hash do conteúdo a ser assinado
	 */
	public void setHash(byte[] hash) {
		this.contentHash = hash;
	}

	/**
	 * Retorna o valor de hash do conteúdo
	 * @return O valor de hash do conteúdo a ser assinado
	 */
	public byte[] getHash() {
		if (this.contentHash == null) {
			throw new NullPointerException("The content digest was not set or calculated.");
		}
		return this.contentHash;
	}
}
