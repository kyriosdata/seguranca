package br.ufsc.labsec.signature.conformanceVerifier.xades.creator;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.tsp.TimeStampResponse;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.conformanceVerifier.xades.AbstractXadesSigner;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.ArchiveTimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.CertificateValues;
import br.ufsc.labsec.signature.conformanceVerifier.xades.attributes.unsigned.RevocationValues;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * Esta classe é responsável pela criação do atributo de carimbo de tempo
 * de arquivamento
 */
public class ArchiveTimeStampCreator extends Creator {

	/**
	 * Construtor
	 * @param xadesSigner Assinador XAdES
	 */
	public ArchiveTimeStampCreator(AbstractXadesSigner xadesSigner) {
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
		
		try { 
			
			String algorithmOid = xadesSigner.getComponent().getApplication().getComponentParam(xadesSigner.getComponent(), "algorithmOid");
			String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmOid);
			List<String> atts = xadesSigner.getSignature().getAttributeList();
			
			if(!atts.contains(CertificateValues.IDENTIFIER)) {
				Creator creator = new CertificateValuesCreator(xadesSigner);
				xadesSigner.getSignature().addUnsignedAttribute(creator.getAttribute());
				Application.logger.log(Level.FINE, "O attributo " + ArchiveTimeStamp.IDENTIFIER + " necessita do attributo " +
						CertificateValues.IDENTIFIER + "para sua criação, esta atributo foi criado.");
			}
			
			if(!atts.contains(RevocationValues.IDENTIFIER)) {
				Creator creator = new RevocationValuesCreator(xadesSigner);
				xadesSigner.getSignature().addUnsignedAttribute(creator.getAttribute());
				Application.logger.log(Level.FINE, "O attributo " + ArchiveTimeStamp.IDENTIFIER + " necessita do attributo " +
						RevocationValues.IDENTIFIER + "para sua criação, esta atributo foi criado.");
			}
			
			
			byte[] digest = xadesSigner.getSignature().getArchiveTimeStampHashValue(algorithm);
			byte[] timeStamp = xadesSigner.getComponent().timeStamp.getTimeStamp(digest);
			
			TimeStampResponse response = new TimeStampResponse(timeStamp);
			
			byte[] toAddAttribute = response.getTimeStampToken().toCMSSignedData().toASN1Structure().getEncoded();
			
			List<String> attributes = xadesSigner.getUnsignedAttributes();
			List<String> cadesAttributes = new ArrayList<>();
			
			for (String att : attributes) {
				String a = super.getCadesAttributeName(att);
				if(a != null)
					cadesAttributes.add(super.getCadesAttributeName(att));
			}
		
			
			byte[] withAttributes = xadesSigner.getComponent().timeStampAttributeIncluder.addAttributesTimeStamp(toAddAttribute, cadesAttributes);
			
			attribute = new ArchiveTimeStamp(ContentInfo.getInstance((ASN1Sequence) ASN1Sequence.fromByteArray(withAttributes)));
			
			
		} catch (Exception e) {
			throw new SignatureAttributeException(SignatureAttributeException.ATTRIBUTE_BUILDING_FAILURE + ArchiveTimeStamp.IDENTIFIER, e);
		}
		
		
		
		return attribute;
		
	}

}
