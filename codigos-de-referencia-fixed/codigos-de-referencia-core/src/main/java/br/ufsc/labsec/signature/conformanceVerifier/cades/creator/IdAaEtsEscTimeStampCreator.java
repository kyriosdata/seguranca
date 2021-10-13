package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.List;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;

import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsEscTimeStamp;
import br.ufsc.labsec.signature.exceptions.PbadException;


/**
 * Esta classe é responsável pela criação do atributo IdAaEtsEscTimeStampCreator
 */
public class IdAaEtsEscTimeStampCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaEtsEscTimeStampCreator(CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() throws NoSuchAlgorithmException,
			IOException, CertificateEncodingException, PbadException,
			TSPException {

		SignatureAttribute attribute = null;

		String algorithmOid = cadesAttributeIncluder.getComponent().getApplication()
				.getComponentParam(cadesAttributeIncluder.getComponent(), "algorithmOid");
		String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmOid);
		byte[] digest = cadesAttributeIncluder.getSignature()
				.getSignatureValueHash(algorithm);
		byte[] timeStamp = cadesAttributeIncluder.getComponent().timeStamp
				.getTimeStamp(digest);
		TimeStampResponse response = new TimeStampResponse(timeStamp);

		byte[] toAddAttribute = response.getTimeStampToken().toCMSSignedData().toASN1Structure().getEncoded();

		List<String> attributes = cadesAttributeIncluder.getUnsignedAttributesForTimeStamp();

		byte[] withAttributes = cadesAttributeIncluder.addAttributesTimeStamp(
				toAddAttribute, attributes);

		attribute = new IdAaEtsEscTimeStamp(ContentInfo.getInstance((ASN1Sequence) ASN1Sequence.fromByteArray(withAttributes)));

		return attribute;
	}

}
