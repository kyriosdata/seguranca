package br.ufsc.labsec.signature.conformanceVerifier.cades.creator;

import java.io.IOException;
import java.util.List;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;

import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesAttributeIncluder;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaSignatureTimeStampToken;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;
import br.ufsc.labsec.signature.tsa.TimeStampComponent;

/**
 * Esta classe é responsável pela criação do atributo IdAaSignatureTimeStampCreator
 */
public class IdAaSignatureTimeStampCreator extends Creator {

	/**
	 * Construtor
	 * @param cadesAttributeIncluder Gerenciador de atributos CAdES
	 */
	public IdAaSignatureTimeStampCreator(CadesAttributeIncluder cadesAttributeIncluder) {
		super(cadesAttributeIncluder);
		// TODO Auto-generated constructor stub
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 */
	@Override
	public SignatureAttribute getAttribute() throws IOException, TSPException, EncodingException, PbadException {

		SignatureAttribute attribute = null;
		
		Component timeStampComponent = cadesAttributeIncluder.getComponent().getApplication().getComponent(TimeStampComponent.class.getName());
			
			String algorithmOid = cadesAttributeIncluder.getComponent().getApplication().getComponentParam(timeStampComponent, "algorithmOid");
			String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmOid);
			byte[] digest = cadesAttributeIncluder.getSignature().getSignatureValueHash(algorithm);
			byte[] timeStamp = cadesAttributeIncluder.getComponent().timeStamp.getTimeStamp(digest);
						
			TimeStampResponse response = new TimeStampResponse(timeStamp);
			
			byte[] toAddAttribute = response.getTimeStampToken().toCMSSignedData().toASN1Structure().getEncoded();
			
			List<String> attributes = cadesAttributeIncluder.getUnsignedAttributesForTimeStamp();
			
			byte[] withAttributes = cadesAttributeIncluder.addAttributesTimeStamp(toAddAttribute, attributes);
			
			attribute = new IdAaSignatureTimeStampToken(ContentInfo.getInstance((ASN1Sequence) ASN1Sequence.fromByteArray(withAttributes)));				
			
		return attribute;
		
	}

}
