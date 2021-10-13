package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.HashMap;
import java.util.Map;

import javax.xml.crypto.dsig.DigestMethod;

import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.tsp.TSPException;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe engloba métodos em comum entre Creators de atributos
 */
public abstract class Creator {

	/**
	 * Gerenciador de atributos CAdES
	 */
	 protected CadesAttributeIncluder cadesAttributeIncluder;
	/**
	 * Mapa que relaciona o identificador ao algoritmo de hash que ele representa
	 */
	 private Map<String, String> mapAlgorithm;

	/**
	 * Construtor
	 * @param cadesSigner Assinador CAdES
	 */
	public Creator(CadesAttributeIncluder cadesSigner){
             this.cadesAttributeIncluder = cadesSigner;
             this.mapAlgorithm = new HashMap<>();
             
             initializeMap();
     }

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 * @throws SignatureAttributeException Exceção caso ocorra algum erro durante
	 * a construção do objeto
	 */
     public abstract SignatureAttribute getAttribute() throws NoSuchAlgorithmException, IOException, AlgorithmException, EncodingException, SignatureAttributeException, CertificateEncodingException, PbadException, TSPException;

	/**
	 * Inicializa os valores no mapa
	 */
	private void initializeMap() {
    	 mapAlgorithm.put(DigestMethod.SHA1, CMSSignedDataGenerator.DIGEST_SHA1);
    	 mapAlgorithm.put(DigestMethod.SHA256,CMSSignedDataGenerator.DIGEST_SHA256);
    	 mapAlgorithm.put(DigestMethod.SHA512,CMSSignedDataGenerator.DIGEST_SHA512);
     }

	/**
	 * Busca no mapa o algoritmo correspondente ao identificador
	 * @param alg O OID do algoritmo
	 * @return O algoritmo correspondente
	 */
	protected String getCorrespondentAlgorithm(String alg) {
    	 return mapAlgorithm.get(alg);
     }
     
}
