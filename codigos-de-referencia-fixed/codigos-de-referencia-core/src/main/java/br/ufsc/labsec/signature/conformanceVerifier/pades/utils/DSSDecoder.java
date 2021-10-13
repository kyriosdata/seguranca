package br.ufsc.labsec.signature.conformanceVerifier.pades.utils;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.CertificateValidation;
import br.ufsc.labsec.signature.RevocationInformation;
import br.ufsc.labsec.signature.RevocationInformation.CRLResult;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.BrExtDss;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.CertificateTrustPoint;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.PdfEntry;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.VriDictionary;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.exceptions.CertificationPathException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.apache.pdfbox.cos.*;
import org.bouncycastle.asn1.ASN1Enumerated;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.util.encoders.Hex;

import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.sql.Time;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe é responsável pela decodificação do dicionário DSS.
 */
public class DSSDecoder {

    private static final String DSS_CERTS = "Certs";
    private static final String DSS_POLICYARTIFACTS = "PBAD_PolicyArtifacts";
    private static final String DSS_LPAARTIFACTS = "PBAD_LpaArtifacts";
    private static final String DSS_LPASIGNATURES = "PBAD_LpaSignatures";
    /* valores para ValidationValues:
     *    crlsOnly (0), -- indica que apenas a entrada CRLs/CRL pode ser usada
     *    ocspsOnly (1), -- indica que apenas a entrada OCSPs/OCSP pode ser usada
     *    either (2), -- indica que podem ser usadas LCRs ou OCSPs no DSS/VRI
     *    both (3) -- indica que devem ser usadas LCRs e OCSPs no DSS/VRI
     */
    private static final String DSS_VALIDATIONVALUES = "ValidationValues";
    private static final String VRI = "VRI";
    private static final String VRI_CERT = "Cert";
    private static final String VRI_POLICYARTIFACT = "PBAD_PolicyArtifact";
    private static final String VRI_LPAARTIFACT = "PBAD_LpaArtifact";
    private static final String VRI_LPASIGNATURE = "PBAD_LpaSignature";

    /**
     * Componente de assinatura PAdES
     */
    private PadesSignatureComponent padesComponent;
    /**
     * Dicionário DSS
     */
    private COSDictionary dss;
    /**
     * Tipo do dicionário
     */
    private String type;
    /**
     * Mapa que relaciona os certificados e seus índices
     */
    private Map<Certificate, Integer> certs;
    /**
     * Mapa que relaciona os artefatos de PA e seus índices
     */
    private Map<ByteArrayWrapper, Integer> policyArtifacts;
    /**
     * Mapa que relaciona os artefatos da LPA e seus índices
     */
    private Map<ByteArrayWrapper, Integer> lpaArtifacts;
    /**
     * Mapa que relaciona as assinaturas da LPA e seus índices
     */
    private Map<ByteArrayWrapper, Integer> lpaSignatures;
    /**
     * Mapa que relaciona os as CRLs e seus índices
     */
    private Map<CRL, Integer> validationValues;

    /**
     * Construtor
     * @param dss O dicionário DSS
     * @param padesComponent Componente de assinatura PAdES
     */
    public DSSDecoder(COSDictionary dss, PadesSignatureComponent padesComponent) {

        this.padesComponent = padesComponent;
        this.certs = new HashMap<Certificate, Integer>();
        this.policyArtifacts = new HashMap<ByteArrayWrapper, Integer>();
        this.lpaArtifacts = new HashMap<ByteArrayWrapper, Integer>();
        this.lpaSignatures = new HashMap<ByteArrayWrapper, Integer>();
        this.validationValues = new HashMap<CRL, Integer>();

        if (dss != null) {
            this.dss = dss;
            this.type = ((COSName) dss.getDictionaryObject("Type")).getName();

            COSArray cosArrayCerts = (COSArray) dss.getDictionaryObject(DSS_CERTS);
            this.certs.putAll(getCertificatesFromCOSArray(cosArrayCerts));

            COSArray cosArrayPolicyArtifacts = (COSArray) dss.getDictionaryObject(DSS_POLICYARTIFACTS);
            this.policyArtifacts.putAll(extractArtifacts(cosArrayPolicyArtifacts));

            COSArray cosArrayLpaArtifacts = (COSArray) dss.getDictionaryObject(DSS_LPAARTIFACTS);
            this.lpaArtifacts.putAll(extractArtifacts(cosArrayLpaArtifacts));

            COSArray cosArrayLpaSignatures = (COSArray) dss.getDictionaryObject(DSS_LPASIGNATURES);
            this.lpaSignatures.putAll(extractArtifacts(cosArrayLpaSignatures));

            COSArray cosArrayValidationValues = (COSArray) dss.getDictionaryObject(DSS_VALIDATIONVALUES);
            this.validationValues.putAll(getValidationValuesFromCOSArray(cosArrayValidationValues));

        }
    }

    /**
     * Retorna o dicionário DSS
     * @return O dicionário DSS
     */
    public COSDictionary getDSS() {
        return dss;
    }

    /**
     * Atribue valor aos atributos de acordo com as informações da assinatura
     * e constrói o dicionário DSS
     * @param sigPolProxy A política de assinatura
     * @param extDss DSS da política de assinatura
     * @param contents Conteúdo da assinatura
     * @param certificate Certificado do assinante
     */
    public void setNewSignature(SignaturePolicyProxy sigPolProxy, BrExtDss extDss, byte[] contents,
                                Certificate certificate) {
        try {
            if (this.dss == null) {
                this.dss = new COSDictionary();
                buildFirstDss(sigPolProxy, extDss, contents, certificate);
            } else {
                buildDss(sigPolProxy, extDss, contents, certificate);
            }
            this.dss.setNeedToBeUpdated(true);
        } catch (CertificationPathException | SignatureAttributeException e) {
            Application.logger.log(Level.SEVERE, "Erro ao construir o DSS. " + e.getMessage());
        }
    }

    /**
     * Constrói o dicionário DSS de acordo com as informações da assinatura. Utilizado
     * quando o dicionário está vazio.
     * Como o Assinador de Referência somente comporta a criação de DSS/VRI com CRLs, então os únicos valores aceitos
     * para o validationValues são os inteiros 0 e 2.
     * @param sigPolProxy A política de assinatura
     * @param extDss DSS da política de assinatura
     * @param contents Conteúdo da assinatura
     * @param signerCertificate Certificado do assinante
     */
    private void buildFirstDss(SignaturePolicyProxy sigPolProxy, BrExtDss extDss,
                               byte[] contents, Certificate signerCertificate) throws CertificationPathException, SignatureAttributeException {

        COSArray certsEntry = new COSArray();
        certsEntry.setNeedToBeUpdated(true);
        certsEntry.setDirect(true);

        COSArray paArtifactsEntry = new COSArray();
        paArtifactsEntry.setNeedToBeUpdated(true);
        paArtifactsEntry.setDirect(true);

        COSArray lpaArtifactsEntry = new COSArray();
        lpaArtifactsEntry.setNeedToBeUpdated(true);
        lpaArtifactsEntry.setDirect(true);

        COSArray lpaSignaturesEntry = new COSArray();
        lpaSignaturesEntry.setNeedToBeUpdated(true);
        lpaSignaturesEntry.setDirect(true);

        COSArray validationValuesEntry = new COSArray();
        validationValuesEntry.setNeedToBeUpdated(true);
        validationValuesEntry.setDirect(true);

        for (PdfEntry pdfEntry : extDss.getDssDicEntries()) {
            String entryId = pdfEntry.getPdfEntryID();
            switch (entryId) {
                case "Type":
                    DERUTF8String temp = null;
                    try {
                        temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntry.getPdfEntryValue());
                    } catch (IOException e) {
                        Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                    }
                    this.type = temp.getString();
                    this.dss.setName(entryId, this.type);
                    break;

                case DSS_CERTS:
                    Set<Certificate> certificates = generateCerts(sigPolProxy, signerCertificate);
                    int i = 0;
                    for (Certificate certificate : certificates) {
                        try {
                            addStreamToCOSArray(certsEntry, certificate.getEncoded());
                        } catch (CertificateEncodingException e) {
                            e.printStackTrace();
                        }
                        this.certs.put(certificate, i++);
                    }

                    this.dss.setItem(entryId, certsEntry);
                    break;

                case DSS_POLICYARTIFACTS:
                    byte[] bytesPA = sigPolProxy.getSignaturePolicy().getEncoded();
                    addStreamToCOSArray(paArtifactsEntry, bytesPA);
                    this.policyArtifacts.put(new ByteArrayWrapper(bytesPA), 0);
                    this.dss.setItem(entryId, paArtifactsEntry);
                    break;

                case DSS_LPAARTIFACTS:
                    byte[] bytesLPA = sigPolProxy.getLpa().getLpaBytes();
                    addStreamToCOSArray(lpaArtifactsEntry, bytesLPA);
                    this.lpaArtifacts.put(new ByteArrayWrapper(bytesLPA), 0);
                    this.dss.setItem(entryId, lpaArtifactsEntry);
                    break;

                case DSS_LPASIGNATURES:
                    String sigUrl = sigPolProxy.getSigURL(SignaturePolicyInterface.AdESType.PAdES);
                    byte[] bytesLPASignature = sigPolProxy.getLpa().getSignatureBytes(sigUrl);
                    addStreamToCOSArray(lpaSignaturesEntry, bytesLPASignature);
                    this.lpaSignatures.put(new ByteArrayWrapper(bytesLPASignature), 0);
                    this.dss.setItem(entryId, lpaSignaturesEntry);
                    break;

                case DSS_VALIDATIONVALUES:
                    int validationValueType = DSSDecoder.getValidationValue(pdfEntry.getPdfEntryValue()).intValue();
                    if (validationValueType != 0 && validationValueType != 2) {
                        throw new SignatureAttributeException("DSS Validation Values não suportado");
                    }
                    Set<CRL> crls = generateValidationValues(sigPolProxy,
                            validationValueType, signerCertificate);
                    entryId = "CRLs";
                    int j = 0;
                    for (CRL crl : crls) {
                        try {
                            addStreamToCOSArray(validationValuesEntry, ((X509CRL) crl).getEncoded());
                        } catch (CRLException e) {
                            e.printStackTrace();
                        }
                        this.validationValues.put(crl, j++);
                    }
                    this.dss.setItem(entryId, validationValuesEntry);
                    break;
                default:
                    break;
            }
        }


        VriDictionary extVri = extDss.getVriDictionary();
        if (extVri != null) {
            COSDictionary vriDictionary = new COSDictionary();

            vriDictionary.setNeedToBeUpdated(true);
            vriDictionary.setDirect(true);


            for (PdfEntry pdfEntry : extVri.getSequenceOfPdfEntry()) {
                String entryId = pdfEntry.getPdfEntryID();
                switch (entryId) {
                    case "Type":
                        DERUTF8String temp = null;
                        try {
                            temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntry.getPdfEntryValue());
                        } catch (IOException e) {
                            Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no VRI.");
                        }
                        vriDictionary.setName(entryId, temp.getString());
                        break;

                    case VRI_CERT:
                        vriDictionary.setItem(entryId, certsEntry);
                        break;

                    case VRI_POLICYARTIFACT:
                        vriDictionary.setItem(entryId, paArtifactsEntry);
                        break;

                    case VRI_LPAARTIFACT:
                        vriDictionary.setItem(entryId, lpaArtifactsEntry);
                        break;

                    case VRI_LPASIGNATURE:
                        vriDictionary.setItem(entryId, lpaSignaturesEntry);
                        break;

                    case DSS_VALIDATIONVALUES:
                        int validationValueType = DSSDecoder.getValidationValue(pdfEntry.getPdfEntryValue()).intValue();
                        if (validationValueType != 0 && validationValueType != 2) {
                            throw new SignatureAttributeException("DSS 'Validation Values' não suportado");
                        }
                        entryId = "CRLs";
                        vriDictionary.setItem(entryId, validationValuesEntry);
                        break;
                    default:
                        break;
                }
            }

            byte[] bytes = null;
            try {
                MessageDigest md = MessageDigest.getInstance("SHA-1");
                md.update(contents);
                bytes = md.digest();
            } catch (NoSuchAlgorithmException e) {
                Application.logger.log(Level.SEVERE, "Erro ao gerar o resumo para usar como chave do VRI.");
            }

            COSDictionary vri_sigs = new COSDictionary();
            String hash = new String(Hex.encode(bytes)).toUpperCase();
            vri_sigs.setItem(COSName.getPDFName(hash), vriDictionary);
            this.dss.setItem(COSName.getPDFName("VRI"), vri_sigs);
        }
    }

    /**
     *  Constrói o dicionário DSS de acordo com as informações da assinatura.
     *  Utilizado quando o dicionário já possui conteúdo.
     *  Como o Assinador de Referência somente comporta a criação de DSS/VRI com CRLs, então os únicos valores aceitos
     *  para o validationValues são os inteiros 0 e 2.
     * @param sigPolProxy A política de assinatura
     * @param extDss DSS da política de assinatura
     * @param contents Conteúdo da assinatura
     * @param signerCertificate Certificado do assinante
     */
    private void buildDss(SignaturePolicyProxy sigPolProxy,
                          BrExtDss extDss, byte[] contents, Certificate signerCertificate) throws CertificationPathException, SignatureAttributeException {
        byte[] bytes = null;

        try {
            MessageDigest md = MessageDigest.getInstance("SHA-1");
            md.update(contents);
            bytes = md.digest();
        } catch (NoSuchAlgorithmException e) {
            Application.logger.log(Level.SEVERE, "Erro ao gerar o resumo para usar como chave do VRI.");
        }
        String hash = new String(Hex.encode(bytes)).toUpperCase();
        COSDictionary vriDictionary = (COSDictionary) this.dss.getDictionaryObject(VRI);
        COSDictionary vriSigs = (COSDictionary) vriDictionary.getDictionaryObject(hash);

        if (vriSigs != null) {
            return;
        }

        COSArray certsEntry = new COSArray();
        certsEntry.setNeedToBeUpdated(true);
        certsEntry.setDirect(true);
        COSArray certsDss = (COSArray) this.dss.getDictionaryObject(DSS_CERTS);
        certsDss.setNeedToBeUpdated(true);

        COSArray paArtifactsEntry = new COSArray();
        paArtifactsEntry.setNeedToBeUpdated(true);
        paArtifactsEntry.setDirect(true);
        COSArray paArtifactsDss = (COSArray) this.dss.getDictionaryObject(DSS_POLICYARTIFACTS);
        certsDss.setNeedToBeUpdated(true);

        COSArray lpaArtifactsEntry = new COSArray();
        lpaArtifactsEntry.setNeedToBeUpdated(true);
        lpaArtifactsEntry.setDirect(true);
        COSArray lpaArtifactsDss = (COSArray) this.dss.getDictionaryObject(DSS_LPAARTIFACTS);
        lpaArtifactsDss.setNeedToBeUpdated(true);

        COSArray lpaSignaturesEntry = new COSArray();
        lpaSignaturesEntry.setNeedToBeUpdated(true);
        lpaSignaturesEntry.setDirect(true);
        COSArray lpaSignaturesDss = (COSArray) this.dss.getDictionaryObject(DSS_LPASIGNATURES);
        lpaSignaturesDss.setNeedToBeUpdated(true);

        COSArray validationValuesEntry = new COSArray();
        validationValuesEntry.setNeedToBeUpdated(true);
        validationValuesEntry.setDirect(true);
        COSArray validationValuesDss = (COSArray) this.dss.getDictionaryObject(DSS_VALIDATIONVALUES);
        validationValuesDss.setNeedToBeUpdated(true);

        VriDictionary extVri = extDss.getVriDictionary();

        if (extVri != null) {
            vriSigs = new COSDictionary();

            vriSigs.setNeedToBeUpdated(true);
            vriSigs.setDirect(true);

            for (PdfEntry pdfEntry : extVri.getSequenceOfPdfEntry()) {
                String entryId = pdfEntry.getPdfEntryID();
                switch (entryId) {
                    case "Type":
                        DERUTF8String temp = null;
                        try {
                            temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntry.getPdfEntryValue());
                        } catch (IOException e) {
                            Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no VRI.");
                        }
                        vriSigs.setName(entryId, temp.getString());
                        break;

                    case DSS_CERTS:
                        Set<Certificate> newCerts = generateCerts(sigPolProxy, signerCertificate);
                        for (Certificate certificate : newCerts) {
                            if (this.certs.containsKey(certificate)) {
                                int index = this.certs.get(certificate);
                                certsEntry.add(certsDss.get(index));
                            } else {
                                try {
                                    addStreamToCOSArray(certsEntry, certificate.getEncoded());
                                } catch (CertificateEncodingException e) {
                                    e.printStackTrace();
                                }
                                certsDss.add(certsEntry.get(certsEntry.size() - 1));
                                this.certs.put(certificate, this.certs.values().size());
                            }
                        }
                        vriSigs.setItem(entryId, certsEntry);
                        break;

                    case VRI_POLICYARTIFACT:
					    ByteArrayWrapper newPaArtifacts =
                                new ByteArrayWrapper(sigPolProxy.getSignaturePolicy().getEncoded());
                        if (this.policyArtifacts.containsKey(newPaArtifacts)) {
                            int index = this.policyArtifacts.get(newPaArtifacts);
                            paArtifactsEntry.add(paArtifactsDss.get(index));
                        } else {
                            addStreamToCOSArray(paArtifactsEntry, newPaArtifacts.getByteArray());
                            paArtifactsDss.add(paArtifactsEntry.get(paArtifactsEntry.size() - 1));
                            this.policyArtifacts.put(newPaArtifacts, this.policyArtifacts.values().size());
                        }
                        vriSigs.setItem(entryId, paArtifactsEntry);
                        break;

                    case VRI_LPAARTIFACT:
					    ByteArrayWrapper newLpaArtifacts =
                                new ByteArrayWrapper(sigPolProxy.getLpa().getLpaBytes());
                        if (this.lpaArtifacts.containsKey(newLpaArtifacts)) {
                            int index = this.lpaArtifacts.get(newLpaArtifacts);
                            lpaArtifactsEntry.add(lpaArtifactsDss.get(index));
                        } else {
                            addStreamToCOSArray(lpaArtifactsEntry, newLpaArtifacts.getByteArray());
                            lpaArtifactsDss.add(lpaArtifactsEntry.get(lpaArtifactsEntry.size() - 1));
                            this.lpaArtifacts.put(newLpaArtifacts, this.lpaArtifacts.values().size());
                        }
                        vriSigs.setItem(entryId, lpaArtifactsEntry);
                        break;

                    case VRI_LPASIGNATURE:
                        String sigUrl = sigPolProxy.getSigURL(SignaturePolicyInterface.AdESType.PAdES);
                        byte[] bytesLPASignature = sigPolProxy.getLpa().getSignatureBytes(sigUrl);
					    ByteArrayWrapper newLpaSignatures = new ByteArrayWrapper(bytesLPASignature);
                        if (this.lpaSignatures.containsKey(newLpaSignatures)) {
                            int index = this.lpaSignatures.get(newLpaSignatures);
                            lpaSignaturesEntry.add(lpaSignaturesDss.get(index));
                        } else {
                            addStreamToCOSArray(lpaSignaturesEntry, newLpaSignatures.getByteArray());
                            lpaSignaturesDss.add(lpaSignaturesEntry.get(lpaSignaturesEntry.size() - 1));
                            this.lpaSignatures.put(newLpaSignatures, this.lpaSignatures.size());
                        }
                        vriSigs.setItem(entryId, lpaSignaturesEntry);
                        break;

                    case DSS_VALIDATIONVALUES:
                        int validationValueType = DSSDecoder.getValidationValue(pdfEntry.getPdfEntryValue()).intValue();
                        if (validationValueType != 0 && validationValueType != 2) {
                            throw new SignatureAttributeException("DSS Validation Value não suportado");
                        }
                        entryId = "CRLs";
                        Set<CRL> newCrls = generateValidationValues(sigPolProxy, validationValueType, signerCertificate);

                        for (CRL crl : newCrls) {
                            if (this.validationValues.containsKey(crl)) {
                                int index = this.validationValues.get(crl);
                                validationValuesEntry.add(validationValuesDss.get(index));
                            } else {
                                try {
                                    addStreamToCOSArray(validationValuesEntry, ((X509CRL) crl).getEncoded());
                                } catch (CRLException e) {
                                    e.printStackTrace();
                                }
                                validationValuesDss.add(validationValuesEntry.get(validationValuesEntry.size() - 1));
                                this.validationValues.put(crl, this.validationValues.size());
                            }
                        }
                        vriSigs.setItem(entryId, validationValuesEntry);
                        break;
                    default:
                        break;
                }
            }
            COSDictionary vri = (COSDictionary) this.dss.getDictionaryObject(VRI);
            vri.setNeedToBeUpdated(true);
            vri.setItem(COSName.getPDFName(hash), vriSigs);

        }
    }

    /**
     * Cria os 'ValidationValue' do dicionário
     * @param sigPolProxy A política de assinatura
     * @param validationType Tipo de validação
     * @param cert Certificado do assinante
     * @return O conjunto de CRLs criado
     */
    private Set<CRL> generateValidationValues(SignaturePolicyProxy sigPolProxy,
                                              int validationType, Certificate cert) throws CertificationPathException {

        Set<CRL> crls = new HashSet<CRL>();

        if (validationType == 0 || validationType == 2) {
            // Seleciona o certPath
            Time time = new Time(new Date(SystemTime.getSystemTime()).getTime());
            CertificateValidation certValidation =
                    this.padesComponent.getCadesSignatureComponent().certificateValidation;

			CertPath certPath = certValidation.generateCertPath(cert, sigPolProxy.getSigningTrustAnchors(), time);

			if (certPath == null) {
			    throw new CertificationPathException("Caminho de certificação inválido");
			}
            List<RevocationInformation> revocation = this.padesComponent.getCadesSignatureComponent().revocationInformation;
            @SuppressWarnings("unchecked")
            List<Certificate> certificates = (List<Certificate>) certPath.getCertificates();

            for (Certificate certificate : certificates) {
                CRLResult temp = null;
                X509CRL crl = null;
                int i = 0;

                while (temp == null && i < revocation.size()) {
                    temp = revocation.get(i).getCRLFromCertificate(certificate);
                    i++;
                }

                if (temp != null) {
                    // Monta o crls
                    crl = (X509CRL) temp.crl;
                    crls.add(crl);
                }
            }
        } else {
            //TODO nao implementado
        }
        return crls;
    }

    /**
     * Gera o conjunto de certificados do dicionário
     * @param sigPolProxy A política de assinatura
     * @param cert Certificado do assinante
     * @return O conjunto de certificados criado
     */
    private Set<Certificate> generateCerts(SignaturePolicyProxy sigPolProxy, Certificate cert) {
        Time time = new Time(new Date(SystemTime.getSystemTime()).getTime());
        CertificateValidation certValidation = this.padesComponent.getCadesSignatureComponent().certificateValidation;

		CertPath certPath = certValidation.generateCertPath(cert, sigPolProxy.getSigningTrustAnchors(), time);

        List<Certificate> certificates = new ArrayList<Certificate>(certPath.getCertificates());

        X509Certificate last = (X509Certificate) certificates.get(certificates.size() - 1);
        CertificateTrustPoint trutsPoint = sigPolProxy.getTrustPoint(last.getIssuerX500Principal());
        Certificate trustAnchor = trutsPoint.getTrustPoint();
        certificates.add(trustAnchor);

        Set<Certificate> setCertificates = new HashSet<Certificate>(certificates);
        return setCertificates;

    }

    /**
     * Adiciona o array de bytes ao COSArray
     * @param array Array de objetos de um documento PDF
     * @param bytes Array de bytes a ser adicionado
     */
    private void addStreamToCOSArray(COSArray array, byte[] bytes) {
        COSStream stream = new COSStream();
        stream.setNeedToBeUpdated(true);
        try (OutputStream unfilteredStream = stream.createOutputStream()) {
            unfilteredStream.write(bytes);
            array.add(stream);
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, "Erro ao adicionar os Certificados no DSS.");
        }
    }

    /**
     * Transforma os valores de um COSArray em um mapa de certificados e índices
     * @param certs O objeto {@link COSArray} que contém os certificados
     * @return Um mapa que relaciona certificados e seus índices
     */
    private HashMap<X509Certificate, Integer> getCertificatesFromCOSArray(COSArray certs) {
        HashMap<X509Certificate, Integer> certificatesList = new HashMap<X509Certificate, Integer>();

        for (int i = 0; i < certs.size(); i++) {
            COSObject certificatesIndirectStream = (COSObject) certs.get(i);
            COSStream certificateStream = (COSStream) certificatesIndirectStream.getObject();
            byte[] certificate = extractDataFromCOSStream(certificateStream);
            ByteArrayInputStream bis = new ByteArrayInputStream(certificate);

            try {
                CertificateFactory fac = CertificateFactory.getInstance("x509");
                Certificate xCert = fac.generateCertificate(bis);
                certificatesList.put((X509Certificate) xCert, i);

            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }
        return certificatesList;
    }

    /**
     * Transforma os valores de um COSArray em um mapa de {@link ByteArrayWrapper} e índices
     * @param cosArray O objeto {@link COSArray} que contém os artefatos
     * @return Um mapa que relaciona {@link ByteArrayWrapper} e seus índices
     */
    private Map<ByteArrayWrapper, Integer> extractArtifacts(COSArray cosArray) {
        Map<ByteArrayWrapper, Integer> artifacts = new HashMap<ByteArrayWrapper, Integer>();

        int i = 0;
        for (COSBase cosBase : cosArray) {
            COSObject indirectStream = (COSObject) cosBase;
            COSStream stream = (COSStream) indirectStream.getObject();
            byte[] bytes = extractDataFromCOSStream(stream);
            ByteArrayWrapper byteArrayWrapper = new ByteArrayWrapper(bytes);
            artifacts.put(byteArrayWrapper, i++);
        }

//		for(int i = 0; i < cosArray.size(); i++){
//			COSBase lpaSigIndirectStream = cosArray.get(i);
//			COSStream lpaSigStram = (COSStream) lpaSigIndirectStream.getCOSObject();
//			byte[] lpaSigBytes = extractDataFromCOSStream(lpaSigStram);
//			ByteArrayWrapper byteArrayWrapper = new ByteArrayWrapper(lpaSigBytes);
//			artifacts.put(byteArrayWrapper, i);
//		}

        return artifacts;
    }

    /**
     * Transforma os valores de um COSArray em um mapa de CRLs e índices
     * @param validationValues O objeto {@link COSArray} que contém as CRLs
     * @return Um mapa que relaciona CRLs e seus índices
     */
    private HashMap<X509CRL, Integer> getValidationValuesFromCOSArray(COSArray validationValues) {
        HashMap<X509CRL, Integer> validationValuesList = new HashMap<X509CRL, Integer>();

        for (int i = 0; i < validationValues.size(); i++) {
            COSObject indirectStream = (COSObject) validationValues.get(i);
            COSStream cosStream = (COSStream) indirectStream.getObject();
            byte[] validationValue = extractDataFromCOSStream(cosStream);
            ByteArrayInputStream bis = new ByteArrayInputStream(validationValue);

            try {
                CertificateFactory fac = CertificateFactory.getInstance("x509");
                CRL xCrl = fac.generateCRL(bis);
                validationValuesList.put((X509CRL) xCrl, i);
            } catch (CRLException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }

        return validationValuesList;
    }

    /**
     * Transforma o valor de um {@link COSStream} em um array de bytes
     * @param stream O {@link COSStream} que contém os dados a serem transformados
     * @return O array de bytes com os dados do {@link COSStream}
     */
    public static byte[] extractDataFromCOSStream(COSStream stream) {
        byte[] data = null;
        try {
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] memory = new byte[25];
            InputStream filteredInputStream = stream.createRawInputStream();
            int readBytes = 0;
            while ((readBytes = filteredInputStream.read(memory)) >= 0) {
                buffer.write(memory, 0, readBytes);
            }

            data = buffer.toByteArray();
        } catch (IOException e) {
            e.printStackTrace();
        }
        return data;
    }

    /**
     * Retorna o valor do array de bytes
     * @param value O array de bytes. Deve ser um valor ASN1
     * @return O valor do array de bytes como um {@link BigInteger}
     */
    public static BigInteger getValidationValue(byte[] value) {
        ASN1Enumerated enumerated = null;
        try {
            enumerated = (ASN1Enumerated) ASN1Enumerated.fromByteArray(value);
        } catch (IOException e) {
            e.printStackTrace();
        }
        return Objects.requireNonNull(enumerated, "Invalid ASN1Value").getValue();
    }
}
