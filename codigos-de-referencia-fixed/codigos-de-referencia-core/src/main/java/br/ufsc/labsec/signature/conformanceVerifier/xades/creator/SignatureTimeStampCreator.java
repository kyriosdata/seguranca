package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TimeStampResponse;

import br.ufsc.labsec.component.Component;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.SignatureTimeStamp;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.tsa.TimeStampComponent;

/**
 * Esta classe é responsável pela criação do atributo SignatureTimeStamp
 */
public class SignatureTimeStampCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public SignatureTimeStampCreator(AbstractXadesSigner xadesSigner) {
		super(xadesSigner);
	}

	/**
	 * Retorna o atributo
	 * @return Um objeto do atributo
	 * @throws SignatureAttributeException Exceção caso ocorra algum erro durante
	 * a construção do objeto
	 */
	@Override
	public SignatureAttribute getAttribute() throws SignatureAttributeException {

		SignatureAttribute attribute = null;
		Component timeStampComponent = this.xadesSigner.getComponent().getApplication().getComponent(
				TimeStampComponent.class.getName());
		
		try {
			String algorithmOid = this.xadesSigner.getComponent().getApplication().getComponentParam(
					timeStampComponent, "algorithmOid");
			byte[] digest = xadesSigner.getSignature().getSignatureValueHash(algorithmOid);
			byte[] timeStamp = xadesSigner.getComponent().timeStamp.getTimeStamp(digest);
						
			TimeStampResponse response = new TimeStampResponse(timeStamp);
			
			byte[] toAddAttribute = response.getTimeStampToken().toCMSSignedData().toASN1Structure().getEncoded();
			
			List<String> attributes = xadesSigner.getUnsignedAttributes();
			List<String> cadesAttributes = new ArrayList<>();
			
			for (String att : attributes) {
				String attName = super.getCadesAttributeName(att);
				if(attName != null)
					cadesAttributes.add(attName);
			}

			byte[] withAttributes = xadesSigner.getComponent().timeStampAttributeIncluder.addAttributesTimeStamp(toAddAttribute, cadesAttributes);
			
			ContentInfo content = ContentInfo.getInstance((ASN1Sequence) ASN1Sequence.fromByteArray(withAttributes));
			attribute = new SignatureTimeStamp(content);				

		} catch (Exception e) {
			throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + SignatureTimeStamp.IDENTIFIER, e);
		}

		return attribute;
	}

}
