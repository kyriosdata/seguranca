package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.util.List;
import java.util.logging.Level;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsArchiveTimeStampV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsCertValues;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsRevocationValues;
import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe é responsável pela criação do atributo IdAaEtsArchiveTimeStampV2Creator
 */
public class IdAaEtsArchiveTimeStampV2Creator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaEtsArchiveTimeStampV2Creator(CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() throws NoSuchAlgorithmException,
			IOException, PbadException, CertificateEncodingException, TSPException {
		SignatureAttribute attribute;
			
			String algorithmOid = cadesAttributeIncluder.getComponent().getApplication().getComponentParam(
			        cadesAttributeIncluder.getComponent(), "algorithmOid");
			String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmOid);
			List<String> attrs = cadesAttributeIncluder.getSignature().getAttributeList();
			
			if(!attrs.contains(IdAaEtsCertValues.IDENTIFIER)) {
				Creator creator = new IdAaEtsCertValuesCreator(cadesAttributeIncluder);
				cadesAttributeIncluder.getSignature().addUnsignedAttribute(creator.getAttribute());
				Application.logger.log(Level.FINE,
                        "O atributo " + IdAaEtsArchiveTimeStampV2.IDENTIFIER +
                        " necessita do atributo " +
						IdAaEtsCertValues.IDENTIFIER + "para sua criação, esta atributo foi criado.");
			}
			
			if(!attrs.contains(IdAaEtsRevocationValues.IDENTIFIER)) {
				Creator creator = new IdAaEtsRevocationValuesCreator(cadesAttributeIncluder);
				cadesAttributeIncluder.getSignature().addUnsignedAttribute(creator.getAttribute());
				Application.logger.log(Level.FINE,
                        "O atributo " + IdAaEtsArchiveTimeStampV2.IDENTIFIER + " necessita do atributo " +
						IdAaEtsRevocationValues.IDENTIFIER + "para sua criação, esta atributo foi criado.");
			}
			
			
			byte[] digest = cadesAttributeIncluder.getSignature().getArchiveTimeStampHashValue(algorithm);

			byte[] timeStamp = cadesAttributeIncluder.getComponent().timeStamp.getTimeStamp(digest);
			
			TimeStampResponse response = new TimeStampResponse(timeStamp);
			
			byte[] toAddAttribute = response.getTimeStampToken().toCMSSignedData().toASN1Structure().getEncoded();
			
			List<String> attributes = cadesAttributeIncluder.getUnsignedAttributesForTimeStamp();
			
			byte[] withAttributes = cadesAttributeIncluder.addAttributesTimeStamp(toAddAttribute, attributes);
			
			attribute = new IdAaEtsArchiveTimeStampV2(ContentInfo.getInstance(
			        ASN1Sequence.fromByteArray(withAttributes)));
		
		return attribute;
	}
	
	

}
