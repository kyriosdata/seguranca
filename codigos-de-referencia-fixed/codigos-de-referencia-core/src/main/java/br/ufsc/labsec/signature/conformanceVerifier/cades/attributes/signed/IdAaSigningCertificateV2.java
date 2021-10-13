/*

Desenvolvido pelo LaboratÃ³rio de SeguranÃ§a em ComputaÃ§Ã£o (LabSEC) do Departamento de InformÃ¡tica e EstatÃ­stica (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: ColÃ©gio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da InformaÃ§Ã£o (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed;

import java.io.IOException;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.ess.ESSCertID;
import org.bouncycastle.asn1.ess.ESSCertIDv2;
import org.bouncycastle.asn1.nist.NISTObjectIdentifiers;
import org.bouncycastle.asn1.oiw.OIWObjectIdentifiers;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cms.SignerId;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.AbstractVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.AlgorithmException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.MandatedCertRefException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SigningCertificateException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.TACException;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignerRules.CertRefReq;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;

/**
 * O atributo IdAaSigningCertificateV2 é designado para previnir o ataque de
 * substituição, e para permitir um conjunto restrito de certificados a serem
 * usados na verificação da assinatura.
 * <p>
 * Esta versão representa uma referência do certificado do signatário
 * utilizando qualquer algoritmo de hash, exceto o SHA-1.
 *
 * <pre>
 * SigningCertificateV2 ::= SEQUENCE {
 * 	certs SEQUENCE OF ESSCertIDv2,
 * 	policies SEQUENCE OF PolicyInformation OPTIONAL
 * }
 * </pre>
 *
 * @see <a href="http://tools.ietf.org/html/rfc5035">RFC 5035</a>
 */
public class IdAaSigningCertificateV2 implements SigningCertificateInterface {

    public static final String IDENTIFIER = PKCSObjectIdentifiers.id_aa_signingCertificateV2.getId();
	/**
	 * Lista de identificadores dos certificados
	 */
    protected List<ESSCertIDv2> certs;
	/**
	 * Objeto de verificador
	 */
    protected AbstractVerifier verifier;

    /**
     * Deve-se utilizar este construtor no momento de validação do atributo.
     * Este método decodifica todos os certificados que foram adicionados no
     * atributo SigningCertificate, ou seja, ele funciona para os casos
     * SignerOnly e FullPath.
	 * @param verifier Usado para criar e verificar o atributo
	 * @param index Este índide deve ser 0 para este atributo
     * @throws SignatureAttributeException
     */
    public IdAaSigningCertificateV2(AbstractVerifier verifier, Integer index) throws SignatureAttributeException {
        this.verifier = verifier;
        Attribute encoding = verifier.getSignature().getEncodedAttribute(this.getIdentifier(), index);
        this.decode(encoding);
    }

    /**
     * Constrói um objeto {@link IdAaSigningCertificateV2}
     * @param genericEncoding O atributo codificado
     * @throws SignatureAttributeException
     */
    public IdAaSigningCertificateV2(Attribute genericEncoding) throws SignatureAttributeException {
        this.decode(genericEncoding);
    }

    /**
     * Cria o atributo id-aa-signingCertificate a partir do identificador do
     * agoritmo de hash e de uma lista de certificados
     * @param algorithm Identificador do algoritmo de hash
     * @param certificates Lista de certificados
     * @throws AlgorithmException
     * @throws EncodingException
     * @throws SignatureAttributeException
     */
    public IdAaSigningCertificateV2(String algorithm, List<X509Certificate> certificates) throws AlgorithmException, EncodingException,
            SignatureAttributeException {
        if (algorithm.equals(OIWObjectIdentifiers.idSHA1.getId())) {
            throw new SignatureAttributeException(SignatureAttributeException.WRONG_ALGORITHM);
        } else {

            if (certificates == null || certificates.size() == 0) {
                throw new SignatureAttributeException(
                        "Para construção do id-aa-signingCertificate é necessário passar ao menos o certificado do assinante");
            } else {
                this.certs = new ArrayList<ESSCertIDv2>();
                ASN1ObjectIdentifier oid = new ASN1ObjectIdentifier(algorithm);
                AlgorithmIdentifier algorithmIdentifier = new AlgorithmIdentifier(oid);
                MessageDigest digester = null;
                try {
                    digester = MessageDigest.getInstance(AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithm));
                } catch (NoSuchAlgorithmException e) {
                    throw new AlgorithmException(e);
                }
                for (X509Certificate cert : certificates) {
                    byte[] digestValue = null;
                    try {
                        digestValue = digester.digest(cert.getEncoded());
                    } catch (CertificateEncodingException e) {
                        throw new EncodingException(e);
                    }
                    IssuerSerial issuerSerial = this.getIssuerSerial(cert.getIssuerX500Principal().toString(), cert.getSerialNumber());
                    ESSCertIDv2 essCertIdv2 = new ESSCertIDv2(algorithmIdentifier, digestValue, issuerSerial);
                    this.certs.add(essCertIdv2);
                }
            }
        }
    }

	/**
	 * Constrói um objeto {@link IdAaSigningCertificateV2}
	 * @param genericEncoding O atributo codificado
	 * @throws SignatureAttributeException
	 */
	private void decode(Attribute genericEncoding) throws SignatureAttributeException {
		try {

			this.certs = new ArrayList<ESSCertIDv2>();
			Attribute idAaSigningCertificateAttribute = null;
			idAaSigningCertificateAttribute = genericEncoding;

			ASN1Object asn1Object = idAaSigningCertificateAttribute.toASN1Primitive();
			ASN1Sequence asn1Sequence = (ASN1Sequence) asn1Object;

			ASN1Set asn1Set = (ASN1Set) asn1Sequence.getObjectAt(1);
			ASN1Sequence signingCertificateSequence = (ASN1Sequence) asn1Set.getObjectAt(0);

			ASN1Sequence certsSequence = (ASN1Sequence) signingCertificateSequence.getObjectAt(0);
			for (int i = 0; i < certsSequence.size(); i++) {
				ASN1Sequence certIdSequence = (ASN1Sequence) certsSequence.getObjectAt(i);
				// precisa ser v2 no signingCertificateV2, veja estrutura ASN.1 na RFC 5035
				decodeESSCertIdv2(certIdSequence);
			}

		} catch (Exception e) {
			throw new SignatureAttributeException(e.getMessage());
		}
	}

	/**
	 * Adiciona à lista de certificados o certificado no objeto ASN.1 dado
	 * @param certIdSequence O certificado no formato ASN.1
	 */
	private void decodeESSCertIdv2(ASN1Sequence certIdSequence) throws IOException {

		AlgorithmIdentifier hashAlgorithmIdentifier;
		byte[] certHash;
		boolean hasAlgId = false;

		try {
			hashAlgorithmIdentifier = AlgorithmIdentifier.getInstance(certIdSequence.getObjectAt(0));
			certHash = ((DEROctetString) certIdSequence.getObjectAt(1)).getOctets();
			hasAlgId = true;
		} catch (IllegalArgumentException e) {
			hashAlgorithmIdentifier = new AlgorithmIdentifier(NISTObjectIdentifiers.id_sha256);
			certHash = ((DEROctetString) certIdSequence.getObjectAt(0)).getOctets();
		}

		ESSCertIDv2 eSSCertIDv2;
		if (this.hasIssuerSerial(certIdSequence, hasAlgId)) {
			IssuerSerial issuerSerial = decodeIssuerSerial(certIdSequence, certIdSequence.size() - 1);
			eSSCertIDv2 = new ESSCertIDv2(hashAlgorithmIdentifier, certHash, issuerSerial);
		} else {
			eSSCertIDv2 = new ESSCertIDv2(hashAlgorithmIdentifier, certHash);
		}
		this.certs.add(eSSCertIDv2);

	}

	/**
	 * Cria um objeto {@link IssuerSerial} através de um objeto ASN.1
	 * @param certIdSequence O objeto ASN.1 que contém as informações
	 * @param index O índice do certificado no objeto ASN.1
	 * @return O objeto {@link IssuerSerial} criado
	 */
	private IssuerSerial decodeIssuerSerial(ASN1Sequence certIdSequence, int index) throws IOException {
		ASN1Sequence issuerSerialSequence = (ASN1Sequence) certIdSequence.getObjectAt(index);

		ASN1Sequence generalNamesSequence = (ASN1Sequence) issuerSerialSequence.getObjectAt(0);

		ASN1TaggedObject taggedGeneralName = (ASN1TaggedObject) generalNamesSequence.getObjectAt(0);
		ASN1Sequence gnSequence = (ASN1Sequence) taggedGeneralName.getObjectParser(15, true);

		GeneralName generalName = new GeneralName(taggedGeneralName.getTagNo(), gnSequence);
		GeneralNames generalNames = new GeneralNames(generalName);

		ASN1Integer serialNumber = (ASN1Integer) issuerSerialSequence.getObjectAt(1);

		return new IssuerSerial(generalNames, serialNumber);
	}

	/**
	 * Retorna o identificador do atributo
	 * @return O identificador do atributo
	 */
	@Override
	public String getIdentifier() {
		return IdAaSigningCertificateV2.IDENTIFIER;
	}

	/**
	 * Compara os valores de hash dos certificados
	 * @param signerCertificate O certificado do assinante
	 * @param essCertIDv2 O certificado a ser comparado
	 * @throws SignatureAttributeException Exceção caso os valores de hash não sejam iguais
	 */
	private void compareHash(X509Certificate signerCertificate, ESSCertIDv2 essCertIDv2) throws SignatureAttributeException {
        byte[] expected = essCertIDv2.getCertHash();
        byte[] obtained;
        try {
            obtained = this.getCertHash(essCertIDv2.getHashAlgorithm(), signerCertificate);
        } catch (CertificateEncodingException e) {
            throw new SignatureAttributeException(SignatureAttributeException.NOT_GOT_HASH);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureAttributeException(SignatureAttributeException.UNKNOW_ATTRIBUTE);
        }

        if (!Arrays.equals(expected, obtained)) {
            throw new SignatureAttributeException(SigningCertificateException.INVALID_CERTIFICATE_HASH);
        }
    }

    /**
	 * Valida as informações do emissor
	 * @param si Informações do assinante
	 * @param attrCerts Coleção de certificados do atributo
	 * @return Indica se as informações são válidas
	 * @throws SignatureAttributeException
	 */
    private boolean validateIssuerSerial(SignerInformation si, Collection<ESSCertIDv2> attrCerts) throws SignatureAttributeException {
        SignerId certSID = si.getSID();
        GeneralNames certIssuer = new GeneralNames(new GeneralName(certSID.getIssuer()));
        ASN1Integer certSerial = new ASN1Integer(certSID.getSerialNumber());

        boolean correct = false, partiallyCorrect = false;
        for (ESSCertIDv2 attrCert : attrCerts) {
            IssuerSerial is = attrCert.getIssuerSerial();
            try {
                this.compareHash(this.verifier.getSignerCert(), attrCert);

                if (is == null) {
                    // IssuerSerial is optional according to RFC 5035, page 6
                    correct = partiallyCorrect = true;
                    continue;
                }
            } catch (SignatureAttributeException e) {
                // keep trying with other ESSCertIDv2
                continue;
            }

            GeneralName[] attrGNs = is.getIssuer().getNames();
            if (attrGNs.length > 1) {
                // won't ever match to the certIssuer constructed above
                correct = partiallyCorrect = false;
                break;
            }

            /*
             * To compare the IssuerSerial structure, the order of RDNs matters according to RFC 5280, section 7.1.
             * However it was decided by the working group that a warning should be given instead, otherwise all
             * digitally signed driver's licenses would be invalid. So we cast the issuer names to strings, because
             * casting to sets is a huge pain of deserializing ASN.1 nested objects and has already introduced a bug
             * in the past.
             */

            // substring removes the tag prefix from the ASN.1 object
            String certGN = certIssuer.getNames()[0].toString().substring(3);
            String attrGN = attrGNs[0].toString().substring(3);

            correct |= is.getSerial().equals(certSerial) && certGN.equals(attrGN);

            HashSet<String> certRDN = new HashSet<>(Arrays.asList(certGN.split(",")));
            HashSet<String> attrRDN = new HashSet<>(Arrays.asList(attrGN.split(",")));

            partiallyCorrect |= is.getSerial().equals(certSerial) && certRDN.equals(attrRDN);
        }

        if (!correct && partiallyCorrect) {
            throw new SignatureAttributeException(SignatureAttributeException.WRONG_DISTINGUISHED_NAME_ORDER);
        }

        return correct;
    }

	/**
	 * Valida o atributo de acordo com suas regras específicas
	 * @throws SignatureAttributeException
	 */
	@Override
	public void validate() throws SignatureAttributeException {

		SignaturePolicyInterface signaturePolicy = this.verifier.getSignaturePolicy();
		CertRefReq certRefReq = signaturePolicy.getSigningCertRefReq();
		Collection<SignerInformation> signerInfos = this.verifier.getSignature().getSignedData().getSignerInfos()
				.getSigners();
        boolean atLeastOne = false;
        for (SignerInformation signerInfo : signerInfos) {
		    if (signerInfo.getVersion() == 1) {
                atLeastOne |= this.validateIssuerSerial(signerInfo, this.certs);
            } else if (signerInfo.getVersion() == 3) {
                 // TODO implementar os outros métodos de hash recomendados pela RFC 5280 (página 28, seção 4.2.1.2)
                X509Certificate cert = this.verifier.getSignerCert();
                byte[] expected = (new SubjectKeyIdentifier(cert.getPublicKey().getEncoded())).getKeyIdentifier();
                byte[] obtained = signerInfo.getSID().getSubjectKeyIdentifier();
                atLeastOne |= Arrays.equals(expected, obtained);
            }
        }

        if (!atLeastOne) {
            throw new SignatureAttributeException(SigningCertificateException.INVALID_ISSUER_SERIAL);
        } else if ((this.verifier.isTimeStamp() && this.certs.size() > 1)) {
            throw new TACException("O SigningCertificateV2 contém referências não verificadas a certificados.");
		}

        if (certRefReq != null) {
            if (certRefReq.equals(CertRefReq.SIGNER_ONLY) && this.certs.size() != 1) {
                throw new SignatureAttributeException(MandatedCertRefException.ISNT_SIGNER_ONLY);
            } else if (certRefReq.equals(CertRefReq.FULL_PATH) && this.certs.size() == 1) {
                throw new SignatureAttributeException(MandatedCertRefException.ISNT_FULL_PATH);
            }
        }
	}

	/**
	 * Retorna o atributo codificado
	 * @return O atributo em formato ASN.1
	 */
    @Override
    public Attribute getEncoded() throws SignatureAttributeException {
        ASN1EncodableVector certsEncoded = new ASN1EncodableVector();
        for (ESSCertIDv2 essCertIDv2 : this.certs) {
            ASN1EncodableVector essCertIDEncoded = this.encodeEssCertId(essCertIDv2);
            certsEncoded.add(new DERSequence(essCertIDEncoded));
        }
        ASN1EncodableVector encodedSigningCertificate = new ASN1EncodableVector();
        encodedSigningCertificate.add(new DERSequence(certsEncoded));
        DERSequence signingCertificateSequence = new DERSequence(encodedSigningCertificate);
        Attribute signingCertificateAttribute = new Attribute(new ASN1ObjectIdentifier(this.getIdentifier()), new DERSet(
                signingCertificateSequence));
        return signingCertificateAttribute;
    }

	/**
	 * Gera um objeto ASN.1 com o certificado dado
	 * @param essCertIDv2 O certificado ESSCertIDv2
	 * @return O objeto ASN.1 criado
	 */
	private ASN1EncodableVector encodeEssCertId(ESSCertIDv2 essCertIDv2) {
        ASN1EncodableVector essCertIDEncoded = new ASN1EncodableVector();

        essCertIDEncoded.add(essCertIDv2.getHashAlgorithm());
        essCertIDEncoded.add(new DEROctetString(essCertIDv2.getCertHash()));
        essCertIDEncoded.add(encodeIssuerSerial(essCertIDv2.getIssuerSerial()));

        return essCertIDEncoded;
    }

	/**
	 * Gera um objeto ASN1 com o IssuerSerial dado
	 * @param issuerSerial O IssuerSerial
	 * @return O objeto ASN1 criado
	 */
	private DERSequence encodeIssuerSerial(IssuerSerial issuerSerial) {
        ASN1EncodableVector issuerSerialEncoded = new ASN1EncodableVector();

        issuerSerialEncoded.add(encodeGeneralNames(issuerSerial.getIssuer()));
        issuerSerialEncoded.add(issuerSerial.getSerial());

        return new DERSequence(issuerSerialEncoded);
    }

	/**
	 * Gera um objeto ASN1 com os nomes dados
	 * @param generalNames Os nomes a serem colocados no objeto
	 * @return O objeto ASN1 criado
	 */
	private DERSequence encodeGeneralNames(GeneralNames generalNames) {
        ASN1EncodableVector generalNamesVector = new ASN1EncodableVector();

        generalNamesVector.add(encodeGeneralName(generalNames.getNames()));

        DERSequence generalNamesSequence = new DERSequence(generalNamesVector);
        return generalNamesSequence;
    }

	/**
	 * Gera um objeto ASN1 com o array de nomes dado
	 * @param generalName O Array de {@link GeneralName}
	 * @return O objeto ASN1 criado
	 */
	private DERTaggedObject encodeGeneralName(GeneralName[] generalName) {
        DERTaggedObject nameTag = new DERTaggedObject(4, generalName[0].getName());
        return nameTag;
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
	 * Calcula o hash do certificado
	 * @param hashAlgorithmId O algoritmo a ser utilizado no cálculo
	 * @param certificate O certificado
	 * @return O Hash do certificado
	 * @throws SignatureAttributeException Caso ocorra algum erro relativo aos atributos da assinatura.
	 */
    private byte[] getCertHash(AlgorithmIdentifier hashAlgorithmId, X509Certificate certificate) throws NoSuchAlgorithmException,
        CertificateEncodingException {
        MessageDigest digester = MessageDigest.getInstance(
                AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(hashAlgorithmId.getAlgorithm().getId()),
                new BouncyCastleProvider());
        return digester.digest(certificate.getEncoded());
    }

	/**
	 * Verifica se o certificado dado é o mesmo que está no atributo
	 * @param certificate O certificado a ser comparado
	 * @return Indica se o certificado dado é o mesmo que está no atributo
	 */
    @Override
    public boolean match(Certificate certificate) {
        boolean match = false;
        boolean error = false;
        X509Certificate x509Certificate = (X509Certificate) certificate;
        String x509IssuerName = x509Certificate.getIssuerX500Principal().toString();
        //IssuerSerial x509IssuerSerial = this.getIssuerSerial(x509IssuerName, x509Certificate.getSerialNumber());
//        ESSCertIDv2 essCertId = null;
        byte[] certHash = null;
        AlgorithmIdentifier algorithmIdentifier = this.certs.get(0).getHashAlgorithm();
        try {
            certHash = this.getCertHash(algorithmIdentifier, (X509Certificate) certificate);
        } catch (CertificateEncodingException e) {
            error = true;
            e.printStackTrace();
        } catch (NoSuchAlgorithmException e) {
            error = true;
            e.printStackTrace();
        }

        if (!error) {
            boolean matchTest = true;
            byte[] obtainedHash = null;
            try {
                obtainedHash = this.getCertHash(algorithmIdentifier, x509Certificate);
            } catch (CertificateEncodingException e) {
                e.printStackTrace();
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            byte[] signerHash = this.certs.get(0).getCertHash();
            int i = 0;
            while (matchTest && i < obtainedHash.length) {
                matchTest = obtainedHash[i] == signerHash[i++];
            }

            match = matchTest;
        }
        return match;
    }

	/**
	 * Faz uma cópia deste objeto
	 * @return Uma cópia do objeto
	 */
    @Override
    public CertSelector clone() {
        return null;
    }

    /**
     * Obtém todos os certificados que foram guardados no atributo signing
     * certificate da assinatura.
     * @return A lista de certificados {@link ESSCertIDv2}.
     */
    public List<ESSCertIDv2> getESSCertIdV2() {
        return this.certs;
    }

    /**
     * <pre>
     * ESSCertID ::= SEQUENCE {
     * hashAlgorithm AlgorithmIdentifier DEFAULT {algorithm id-sha256},
     * certHash Hash,
     * issuerSerial IssuerSerial OPTIONAL
     * }
     * </pre>
     *
     * Como o terceiro item do ESSCertIDv2 é opcional, então é necessário testar
     * se o issuerSerial foi incluído, implicando que o sequence do ESSCertID
     * terá tamanho 3.
     *
     * @param certSequence O objeto ASN.1 que representa um {@link ESSCertID}
     *
     * @return Indica se o tamanho do sequence é adequado
     */
    private boolean hasIssuerSerial(ASN1Sequence certSequence, boolean hasDefault) {
        if (hasDefault) {
            return certSequence.size() == 3;
        } else {
            return certSequence.size() == 2;
        }
    }

	/**
	 * Cria um objeto {@link IssuerSerial} com as informações dadas
	 * @param issuerDirName Nome do emissor do certificado
	 * @param subjectSerial Número de série do certificado emitido
	 * @return O {@link IssuerSerial} criado
	 */
    private IssuerSerial getIssuerSerial(String issuerDirName, BigInteger subjectSerial) {
        X500Name x500Name = new X500Name(issuerDirName);
        GeneralNames generalNames = new GeneralNames(new GeneralName(x500Name));
        ASN1Integer serial = new ASN1Integer(subjectSerial);
        return new IssuerSerial(generalNames, serial);
    }

	/**
	 * Verifica se o atributo deve ter apenas uma instância na assinatura
	 * @return Indica se o atributo deve ter apenas uma instância na assinatura
	 */
    @Override
    public boolean isUnique() {
        return true;
    }

	/**
	 * Obtém todos os certificados que foram guardados no atributo signing
	 * certificate da assinatura.
	 * @return A lista de certificados {@link ESSCertID}.
	 */
	@Override
    public List<ESSCertID> getESSCertID() {
        ESSCertID essCertId;
        List<ESSCertID> essCertIdList = new ArrayList<ESSCertID>();

        for (ESSCertIDv2 cert : this.certs) {
            byte[] certHash = cert.getCertHash();
            IssuerSerial issuerSerial = cert.getIssuerSerial();
            essCertId = new ESSCertID(certHash, issuerSerial);
            essCertIdList.add(essCertId);
        }
        return essCertIdList;
    }
}
