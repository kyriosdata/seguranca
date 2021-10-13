package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.security.MessageDigest;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERSet;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesContentToBeSigned;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo message digest é usado para guardar o resumo criptográfico do
 * conteúdo assinado. Para a assinatura ser válida, o resumo criptográfico
 * calculado deve ser o mesmo do atributo message digest. Este atributo é
 * obrigatório para todas as políticas do Padrão Brasileiro de Assinatura
 * Digital. Mais informações: http://www.ietf.org/rfc/rfc3852.txt
 * 
 * Oid e esquema do atributo id-messageDigest retirado da RFC 3852:
 * 
 * id-messageDigest OBJECT IDENTIFIER ::= { iso(1) member-body(2) us(840)
 * rsadsi(113549) pkcs(1) pkcs9(9) 4 }
 * 
 * MessageDigest ::= OCTET STRING
 * 
 * Para otimizar o processo de geração de hash nesta classe, deve ser modificado
 * o código do construtor, usando um buffer para carregar o conteúdo em partes
 * separadas na classe {@link MessageDigest}. Assim, o conteúdo não é carregado
 * inteiro na memória. É recomendado usar este processo para assinar arquivos
 * muito grandes. Exemplo de código:
 *
 * {@link FileInputStream} file = new {@link FileInputStream}("caminhoDoArquivo/arquivo");
 * {@link BufferedInputStream} buffer = new {@link BufferedInputStream}(file);
 * {@link MessageDigest} messageDigest = {@link MessageDigest#getInstance(String)};
 * byte[] byteRead = new byte[1024];
 * while((content = buffer.read(byteRead)) {@code > } 0){
 *     messageDigest(byteRead);
 * }
 * byte[] result = messageDigest.digest();
 *
 */
public class IdMessageDigest implements SignatureAttribute {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.pkcs_9_at_messageDigest.getId();
	/**
	 * O valor de hash do conteúdo assinado
	 */
	protected byte[] signedContentHash;
	/**
	 * Conteúdo a ser assinado
	 */
	private CadesContentToBeSigned signedContent;

    /***
     * Construtor não implementado, pois sua verificação ocorre dentro da classe
     * de validação e não nessa classe de forma separada.
	 * @param signatureVerifier Usado para criar e verificar o atributo
	 * @param index Este índide deve ser 0 para este atributo
     */
    public IdMessageDigest(AbstractVerifier signatureVerifier, Integer index) {
    }

    /**
     * Cria o atributo id-messageDigest a partir do resumo criptográfico do
     * conteúdo assinado.
     * @param signedContentHash O resumo criptográfico do conteúdo assinado
     */
    public IdMessageDigest(byte[] signedContentHash) {
        this.signedContentHash = signedContentHash;
    }

	/**
	 * Cria o atributo id-messageDigest a partir do conteúdo a ser assinado
	 * @param content O conteúdo a ser assinado
	 */
	public IdMessageDigest(CadesContentToBeSigned content) {
    	if (content == null) {
    		throw new NullPointerException("Content cannot be null.");
    	}
    	this.signedContent = content; 
    }

	/**
	 * Constrói um objeto {@link IdMessageDigest}
	 * @param attributeEncoded O atributo codificado
	 */
    public IdMessageDigest(Attribute attributeEncoded) throws SignatureAttributeException {
        decode(attributeEncoded);
    }

	/**
	 * Constrói um objeto {@link IdMessageDigest}
	 * @param attributeEncoded O atributo codificado
	 */
    private void decode(Attribute attributeEncoded) throws SignatureAttributeException {
        DEROctetString octetString = (DEROctetString) attributeEncoded.getAttrValues().getObjectAt(0);
        this.signedContentHash = octetString.getOctets();
    }

	/**
	 * Retorna o atributo codificado
	 * @return O atributo em formato ASN1
	 * @throws SignatureAttributeException
	 */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
    	byte[] digest = null;
    	if (this.signedContentHash != null) {
	        digest = this.signedContentHash;
    	} else {
    		digest = this.signedContent.getHash();
    	}
    	Attribute messageDigest = new Attribute(PKCSObjectIdentifiers.pkcs_9_at_messageDigest, new DERSet(new DEROctetString(
                digest)));
        return messageDigest;
    }

	/**
	 * Retorna o identificador do atributo
	 * @return O identificador do atributo
	 */
    @Override
    public String getIdentifier() {
        return IdMessageDigest.IDENTIFIER;
    }

	/**
	 * Informa se o atributo é assinado
	 * @return Indica se o atributo é assinado
	 */
    @Override
    public boolean isSigned() {
        return true;
    }

	/**
	 * Retorna o valor de hash do conteúdo assinado
	 * @return O hash do conteúdo assinado
	 */
	public byte[] getSignedContentHash() {
        return this.signedContentHash;
    }

    /**
     * Essa validação é realizada no momento da verificação da integridade da
     * assinatura.
     */
    @Override
    public void validate() throws SignatureAttributeException {
    }

	/**
	 * Verifica se o atributo deve ter apenas uma instância na assinatura
	 * @return Indica se o atributo deve ter apenas uma instância na assinatura
	 */
    @Override
    public boolean isUnique() {
        return false;
    }
}
