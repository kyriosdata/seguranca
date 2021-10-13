package br.ufsc.labsec.signature.conformanceVerifier.cms.attributes.signed;

import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SignatureAttribute;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.esf.OtherRevVals;
import org.bouncycastle.asn1.esf.RevocationValues;
import org.bouncycastle.asn1.ocsp.OCSPResponse;
import org.bouncycastle.asn1.x509.CertificateList;
import java.util.Enumeration;

/**
 * Representa os valores de revogação (LCRs ou respostas OCSP) de uma
 * assinatura. Atributo utilizado pela Adobe.
 * <p>
 *
 * Oid e esquema do atributo adbe-revinfoarchival retirado de
 * https://www.adobe.com/devnet-docs/acrobatetk/tools/DigSigDC/oids.html
 * e da ISO 32000-1, p. 740 (PDF Reference sixth edition,
 * Adobe® Portable Document Format, Version 1.7, November 2006)
 * <p>
 *
 * <pre>
 * RevocationValues ::= SEQUENCE {
 * 	crlVals
 * 	[0] EXPLICIT SEQUENCE OF CertificateList OPTIONAL,
 * 	ocspVals
 * 	[1] EXPLICIT SEQUENCE OF OCSPResponse OPTIONAL,
 * 	OtherRevInfo
 * 	[2] EXPLICIT SEQUENCE of OtherRevInfo OPTIONAL}
 *
 * OhterRevInfo ::= SEQUENCE {
 *  Type  OBJECT IDENTIFIER
 *  ValValue OCTET STRING
 * }
 * </pre>
 */
public class RevocationInfoArchival implements SignatureAttribute {

	public static final String IDENTIFIER = "1.2.840.113583.1.1.8";

	protected AbstractVerifier signatureVerifier;

	 /**
	 * Lista de CRLs
	 */
	private ASN1Sequence crlVals;
	 /**
	 * Lista de respostas OCSP
	 */
	private ASN1Sequence ocspVals;
	 /**
	 * Algoritmo de cálculo de hash
	 */
	private OtherRevVals otherRevVals;

	private int index;

	/**
	 * Construtor
	 * @param signatureVerifier Usado para criar e verificar o atributo
	 * @param index Índice usado para selecionar o atributo
	 * @throws SignatureAttributeException
	 */
	public RevocationInfoArchival(AbstractVerifier signatureVerifier, Integer index) throws SignatureAttributeException {
		this.signatureVerifier = signatureVerifier;
		this.index = index;
		Attribute genericEncoding = signatureVerifier.getSignature().getEncodedAttribute(IDENTIFIER, index);
		ASN1Set asn1SetRevocationValues = genericEncoding.getAttrValues();
		ASN1Sequence revocationValuesSequence = (ASN1Sequence) asn1SetRevocationValues.getObjectAt(0);

		this.decode(revocationValuesSequence);
	}
	/**
	 * Valida o atributo
	 */
	@Override
	public void validate() throws SignatureAttributeException {
		// atributo não consta em normativos da ICP-Brasil, então apenas uma validação sintática é feita
	}

	@Override
	public Attribute getEncoded() throws SignatureAttributeException {
		return signatureVerifier.getSignature().getEncodedAttribute(IDENTIFIER, index);
	}

	protected RevocationValues decode(ASN1Sequence revocationValuesSequence) throws SignatureAttributeException {
		if (revocationValuesSequence.size() > 3) {
			throw new SignatureAttributeException("Tamanho de sequência inválido: "
					+ revocationValuesSequence.size());
		} else if (revocationValuesSequence.size() == 0) {
			return new RevocationValues(null, null, null);
		} else {
			Enumeration e = revocationValuesSequence.getObjects();
			while (e.hasMoreElements()) {
				ASN1TaggedObject o = (ASN1TaggedObject) e.nextElement();
				switch (o.getTagNo()) {
					case 0:
						ASN1Sequence crlValsSeq = (ASN1Sequence) o.getObject();
						Enumeration crlValsEnum = crlValsSeq.getObjects();
						while (crlValsEnum.hasMoreElements()) {
							try {
								CertificateList.getInstance(crlValsEnum.nextElement());
							} catch (IllegalArgumentException ignored) {
								throw new SignatureAttributeException("LCR inválida");
							}
						}
						this.crlVals = crlValsSeq;
						break;
					case 1:
						ASN1Sequence ocspValsSeq = (ASN1Sequence) o.getObject();
						Enumeration ocspValsEnum = ocspValsSeq.getObjects();
						while (ocspValsEnum.hasMoreElements()) {
							try {
								OCSPResponse.getInstance(ocspValsEnum.nextElement());
							} catch (IllegalArgumentException ignored) {
								throw new SignatureAttributeException("OCSPResponse inválida");
							}
						}
						this.ocspVals = ocspValsSeq;
						break;
					case 2:
						try {
							this.otherRevVals = OtherRevVals.getInstance(o.getObject());
						} catch (IllegalArgumentException | IllegalStateException ignored) {
							throw new SignatureAttributeException("OtherRevInfo inválida");
						}
						break;
					default:
						throw new SignatureAttributeException("Tag inválida encontrada");
				}
			}
		}

		return new RevocationValues(null, null, null);
	}

	/**
	 * Informa se o atributo é assinado
	 * @return Indica se o atributo é assinado
	 */
	@Override
	public boolean isSigned() {
		return true;
	}

	@Override
	public boolean isUnique() {
		return false;
	}

	/**
	 * Retorna o identificador do atributo
	 * @return O identificador do atributo
	 */
	@Override
	public String getIdentifier() {
		return RevocationInfoArchival.IDENTIFIER;
	}

}
