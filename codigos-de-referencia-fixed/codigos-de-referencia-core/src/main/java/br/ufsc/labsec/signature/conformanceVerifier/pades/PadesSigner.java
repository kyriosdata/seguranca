package br.ufsc.labsec.signature.conformanceVerifier.pades;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.*;
import br.ufsc.labsec.signature.conformanceVerifier.cades.*;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureAttributeNotFoundException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SigningCertificateException;
import br.ufsc.labsec.signature.conformanceVerifier.pades.exceptions.DictionaryException;
import br.ufsc.labsec.signature.conformanceVerifier.pades.utils.DSSDecoder;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.BrExtDss;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.BrExtMandatedDocTSEntries;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.BrExtMandatedPdfSigDicEntries;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.PdfEntry;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;
import br.ufsc.labsec.signature.signer.signatureSwitch.SignatureDataWrapperGenerator;
import br.ufsc.labsec.signature.signer.signatureSwitch.SwitchHelper;
import br.ufsc.labsec.signature.tsa.TimeStamp;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.cos.COSName;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureOptions;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.ContentInfo;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.*;
import java.util.*;
import java.util.logging.Level;

/**
 * Esta classe cria uma assinatura PAdES em um documento.
 * Implementa {@link Signer}.
 */
public class PadesSigner extends SignatureDataWrapperGenerator implements Signer {

    private static final String DSS = "DSS";
    public static final String TYPE = "Sig";
    public static final String FILTER = "PBAD_SignatureHandle";
    public static final String SUBFILTER = "PBAD.CAdES.detached";
    public static final int CMS_LENGHT = 1500;

    private Certificate certificate;
    private PrivateKey privateKey;
    private SignerType SignerType;

    /**
     * O documento a ser assinado
     */
    private PDDocument pdfDocument;
    /**
     * Componente de assinatura PAdES
     */
    private PadesSignatureComponent padesComponent;
    /**
     * Stream do PDF assinado
     */
    private ByteArrayOutputStream pdfOutputStream;
    /**
     * Bytes do conteúdo assinado
     */
    private byte[] conteudo;
    /**
     * Resultado intermediário do documento assinado
     */
    private File tempFile;
    /**
     * Auxiliar na criação da assinatura
     */
    private PadesSignatureImp sigImp;
    /**
     * Suite da assinature
     */
    private String suite;

    /**
     * Construtor
     * @param padesComponent Componente de assinatura PAdES
     */
    public PadesSigner(PadesSignatureComponent padesComponent) {
        this.padesComponent = padesComponent;
    }

    /*
     * Verificar necessidade de implementar outros atributos do dicinonário de
     * assinatura: {"Reference", "Changes", "R", "V", "Prop_Build"}
     *
     * @param attributesList é verificado para decidir a inclusão de "M" e "Location"
     * @param byteRange      é um arranjo de inteiros, identificando os offset's de
     *                       assinatura
     * @return PDSignature, que é um dicionário de assinatura
     * @throws DictionaryException
     */
    /**
     * Cria o objeto de assinatura junto com seu dicionário de acordo com a PA
     * @return O objeto de assinatura criado
     * @throws DictionaryException Exceção em caso de erro na criação do dicionário
     */
    private PDSignature createSignDicionary() throws DictionaryException {

        PDSignature signature = new PDSignature();
        SignaturePolicyProxy sigPolProxy = this.padesComponent
                .getSignaturePolicy();
        BrExtMandatedPdfSigDicEntries pol = sigPolProxy
                .signerRulesGetBrExtMandatedPdfSigDicEntries();
        List<PdfEntry> sigDicEntries = pol.getMandatedPdfSigDicEntries();

        for (PdfEntry pdfEntry : sigDicEntries) {
            addDicAtributes(signature, pdfEntry.getPdfEntryID(),
                    pdfEntry.getPdfEntryValue());
        }

        return signature;
    }

    /**
     * Adiciona uma entrada ao dicionário da assinatura
     * @param signature A assinatura onde a entrada será adicionada
     * @param pdfEntryID O identificador da entrada
     * @param pdfEntryValue O valor da entrada
     * @throws DictionaryException Exceção em caso de erro na manipulação do dicionário
     */
    private void addDicAtributes(PDSignature signature, String pdfEntryID,
                                 byte[] pdfEntryValue) throws DictionaryException {
        DERUTF8String temp = null;
        switch (pdfEntryID) {
            case "Type":
                try {
                    temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntryValue);
                } catch (IOException e) {
                    Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                }
                signature.setType(COSName.getPDFName(temp.getString()));
                break;
            case "Filter":
                try {
                    temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntryValue);
                } catch (IOException e) {
                    Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                }
                signature.setFilter(COSName.getPDFName(temp.getString()));
                break;
            case "SubFilter":
                try {
                    temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntryValue);
                } catch (IOException e) {
                    Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                }
                signature.setSubFilter(COSName.getPDFName(temp.getString()));
                break;
            case "Contents":
                break;
            case "Cert":
                throw new DictionaryException("Entrada" + pdfEntryID
                        + " é proibida.");
            case "ByteRange":
                break;
            case "Reference":
                // PDSignature não tem um setReference
                break;
            case "Changes":
                // PDSignature não tem um setChanges
                break;
            case "Name":
                // signature.setName(new String(pdfEntryValue));
                break;
            case "M":
                // arrumar para o formato certo da data
                // signature.setSignDate();
                break;
            case "Location":
                // signature.setLocation(new String(pdfEntryValue));
                break;
            case "Reason":
                // signature.setReason(new String(pdfEntryValue));
                break;
            case "ContactInfo":
                // signature.setContactInfo(new String(pdfEntryValue));
                break;
            case "R":
                throw new DictionaryException("Entrada" + pdfEntryID
                        + " é proibida.");
            case "V":
                // PDSignature não tem um setV (The version of the signature
                // dictionary format.)
                // Deve ser 0, de acordo com o DOC-ICP 15.03
                break;
            case "Prop_Build":
                // signature.setPropBuild(new PDPropBuild());
                break;
            case "Prop_AuthTime":
                // PDSignature não tem um setProp_AuthTime
                break;
            default:
                throw new DictionaryException("Entrada" + pdfEntryID
                        + " é inválida.");
        }
    }

    /**
     * Cria um objeto {@link SignatureOptions}
     * @return O objeto criado
     */
    private SignatureOptions createSignatureOptions() {
        return null;
    }

    public void selectInformation(KeyStore keyStore, String password) {
        String alias = SwitchHelper.getAlias(keyStore);
        this.privateKey = SwitchHelper.getPrivateKey(keyStore, alias, password.toCharArray());
        this.certificate = SwitchHelper.getCertificate(keyStore, alias);
        PrivateInformation privateInformation = new SimplePrivateInformation(this.certificate, this.privateKey);
        ((CadesSigner) this.padesComponent.cadesSigner).selectInformation(privateInformation);
    }

    /**
     * Inicializa os atributos e o gerador de assinatura
     * @param target O arquivo que será assinado
     * @param policyOid OID da política de assinatura utilizada
     */
    @Override
    public void selectTarget(InputStream target, String policyOid) {
        InputStream contentForPDF = null;

        try {

            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            byte[] buf = new byte[1024];
            int n = 0;

            while ((n = target.read(buf)) >= 0) {
                baos.write(buf, 0, n);
            }
            byte[] bytes = baos.toByteArray();

            this.conteudo = bytes;
            contentForPDF = new ByteArrayInputStream(bytes);

            this.pdfDocument = PDDocument.load(contentForPDF);

            CadesSigner cadesSignature = (CadesSigner) padesComponent.getCadesSigner();
            SimplePrivateInformation privateInformation = new SimplePrivateInformation(certificate, privateKey);
            cadesSignature.selectInformation(privateInformation);

            SignaturePolicyProxy sigPolProxy = this.padesComponent.getSignaturePolicy();
            sigPolProxy.setActualPolicy(policyOid, null, SignaturePolicyInterface.AdESType.PAdES);

            sigImp = new PadesSignatureImp(padesComponent.getCadesSigner(), policyOid, suite);

        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }

    }

    /**
     * Inicializa os atributos e o gerador de assinatura
     * @param target  Endereço do arquivo a ser assinado
     * @param policyOid OID da política de assinatura utilizada
     */
    @Override
    public void selectTarget(String target, String policyOid) {
        this.padesComponent.getCadesSigner().selectTarget(target, policyOid);
    }

    /**
     * Realiza a assinatura
     * @return Indica se o processo de assinatura foi concluído com sucesso
     */
    @Override
    public boolean sign() {
        if (this.pdfDocument == null) {
            Application.logger.log(Level.SEVERE, "Documento não selecionado.");
            return false;
        }
        PDSignature signature = null;

        try {
            signature = createSignDicionary();
            signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
            signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
            signature.setSignDate(Calendar.getInstance());
        } catch (DictionaryException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }

        SignatureOptions sigOptions = createSignatureOptions();
        signature.getCOSObject().setNeedToBeUpdated(true);

        try {
            if (sigOptions == null) {
                this.pdfDocument.addSignature(signature, this.sigImp);
            } else {
                this.pdfDocument.addSignature(signature, this.sigImp, sigOptions);
            }

        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, "Erro ao gerar assinatura.");
            return false;
        }

        try {
            this.pdfOutputStream = new ByteArrayOutputStream();
            this.pdfDocument.saveIncremental(this.pdfOutputStream);
            this.pdfDocument.close();
        } catch (IOException e) {
            e.printStackTrace();
            Application.logger.log(Level.SEVERE,
                    "Erro ao gerar o stream da assinatura.");
            return false;
        }

        //FINAL DA ASSINATURA NORMAL

        SignaturePolicyProxy sigPolProxy = this.padesComponent.getSignaturePolicy();
        boolean hasDss = sigPolProxy.signerRulesExtensionExists(BrExtDss.IDENTIFIER);
        boolean hasTS = sigPolProxy.signerRulesExtensionExists(BrExtMandatedDocTSEntries.IDENTIFIER);

        // cria o DSS e o VRI
        byte[] updatedStream = pdfOutputStream.toByteArray();
        PDDocument pdfwithoutDSS = null;
        if (hasDss) {
            byte[] contents = null;
            BrExtDss extDss = sigPolProxy.signerRulesGetBrExtDss();

            try {
                pdfwithoutDSS = PDDocument.load(updatedStream);
                List<PDSignature> signatures = pdfwithoutDSS.getSignatureDictionaries();
                PDDocumentCatalog catalog = pdfwithoutDSS.getDocumentCatalog();
                COSDictionary oldDss = (COSDictionary) catalog.getCOSObject().getDictionaryObject(DSS);
                DSSDecoder dssDecoder = new DSSDecoder(oldDss, this.padesComponent);

                while (!signatures.isEmpty()) {
                    PDSignature lastSignature = getLastSignature(signatures);
                    contents = lastSignature.getContents(updatedStream);
                    oldDss = buildDSS(sigPolProxy, extDss, contents, oldDss, this.certificate, dssDecoder);
                    oldDss.setNeedToBeUpdated(true);
                }
                catalog.getCOSObject().setItem(COSName.getPDFName(DSS), oldDss);
                catalog.getCOSObject().setNeedToBeUpdated(true);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }

        if (hasTS) {
            CadesSignatureComponent cadesComponent = this.padesComponent.getCadesSignatureComponent();
            TimeStamp timeStamp = cadesComponent.timeStamp;
            String algorithmOid = cadesComponent.getApplication().getComponentParam(cadesComponent, "algorithmOid");
            String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(algorithmOid);
            byte[] digest = updatedStream;
            SignatureInterface timeStampSignatureImp = new PadesTimeStampSignatureImp(timeStamp, digest, this, algorithm);
            PDSignature tsDictionary = new PDSignature();
            BrExtMandatedDocTSEntries policyDocTS = sigPolProxy.signerRulesGetBrExtMandatedDocTSEntries();
            buildDocTimeStamp(sigPolProxy, policyDocTS, tsDictionary, timeStampSignatureImp, pdfwithoutDSS);
            tsDictionary.getCOSObject().setNeedToBeUpdated(true);
        }

        if (hasTS || hasDss) {
            try {
                ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
                pdfwithoutDSS.saveIncremental(byteArrayOutputStream);
                this.pdfOutputStream = byteArrayOutputStream;
                pdfwithoutDSS.getDocument().close();
            } catch (IOException e) {
                Application.logger.log(Level.SEVERE,
                        "Erro ao gerar o stream da assinatura com timestamp ou DSS.", e);
                return false;
            }
        }
        return true;
    }

    /**
     * Salva a assinatura intermediária em formato .pdf
     * @param pdfwithoutDSS O documento de assinatura intermediário
     */
    private void saveIncrementalPdf(PDDocument pdfwithoutDSS) {
        try {
            FileInputStream fis = new FileInputStream(this.tempFile);
            File newtempFile = File.createTempFile("aux", ".pdf");
            FileOutputStream fos = new FileOutputStream(newtempFile);

            byte[] buffer = new byte[10 * 1024];
            int c;
            while ((c = fis.read(buffer)) != -1) {
                fos.write(buffer, 0, c);
            }

            pdfwithoutDSS.saveIncremental(fos);
            this.tempFile = newtempFile;

        } catch (IOException e) {
            Application.logger
                    .log(Level.SEVERE,
                            "Erro ao gerar o stream da assinatura do carimbo do tempo.");
        }

    }

    /**
     * Retorna o certificado do assinante
     * @param signature A assinatura feita
     * @param contents O conteúdo assinado
     * @return O certificado do assinante ou nulo caso não seja possível identificá-lo
     */
    private Certificate getSignerCertificate(PDSignature signature, byte[] contents) {
        COSName cosNameType = (COSName) signature.getCOSObject().getDictionaryObject("Type");
        String typeDic = cosNameType.getName();
        IdAaSigningCertificateV2 signingCertificateInterface = null;

        if (typeDic.equals("Sig")) {
            try {
                CadesSignatureContainer cadesSignatureContainer = new CadesSignatureContainer(contents);
                CadesSignature sig = cadesSignatureContainer.getSignatureAt(0);
                Attribute temp = sig.getEncodedAttribute(IdAaSigningCertificateV2.IDENTIFIER);
                signingCertificateInterface = new IdAaSigningCertificateV2(temp);
                for (CertificateCollection certificateCollection : this.padesComponent.certificateCollection) {
                    Certificate certificate = certificateCollection.getCertificate(signingCertificateInterface);
                    if (certificate != null) {
                        return certificate;
                    }
                }
            } catch (CadesSignatureException e) {
                e.printStackTrace();
            } catch (EncodingException e) {
                e.printStackTrace();
            } catch (SignatureAttributeNotFoundException e) {
                e.printStackTrace();
            } catch (SigningCertificateException e) {
                e.printStackTrace();
            } catch (SignatureAttributeException e) {
                e.printStackTrace();
            }
        } else if (typeDic.equals("DocTimeStamp")) {
            ContentInfo contentInfo = null;
            try {
                contentInfo = ContentInfo.getInstance(ASN1Sequence.fromByteArray(contents));
                CMSSignedData cmsSignedData = new CMSSignedData(contentInfo);
                CadesSignatureContainer container = new CadesSignatureContainer(cmsSignedData);
                CadesSignature sig = container.getSignatureAt(0);
                List<X509Certificate> certs = sig.getCertificates();
                this.padesComponent.certificateCollection.get(0).addCertificates(certs);

                for (X509Certificate cert : certs) {
                    List<X509Certificate> certificates = ValidationDataService.downloadCertChainFromAia(cert);
                    this.padesComponent.certificateCollection.get(0).addCertificates(certificates);
                }

                Attribute temp = sig.getEncodedAttribute(IdAaSigningCertificateV2.IDENTIFIER);
                signingCertificateInterface = new IdAaSigningCertificateV2(temp);
                for (CertificateCollection certificateCollection : this.padesComponent.certificateCollection) {
                    Certificate certificate = certificateCollection.getCertificate(signingCertificateInterface);
                    if (certificate != null) {
                        return certificate;
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } catch (CMSException e) {
                e.printStackTrace();
            } catch (EncodingException e) {
                e.printStackTrace();
            } catch (SignatureAttributeNotFoundException e) {
                e.printStackTrace();
            } catch (SignatureAttributeException e) {
                e.printStackTrace();
            } catch (CertificateException e) {
                e.printStackTrace();
            } catch (AIAException e) {
                e.printStackTrace();
            }

        }


        return null;
    }

    /**
     * Gera um carimbo de tempo
     * @param sigPolProxy A política da assinatura
     * @param policyDocTS A política do carimbo
     * @param tsDictionary O carimbo de tempo
     * @param timeStampSignatureImp Auxiliar para a geração do carimbo
     * @param pdfwithoutDSS O documento assinado intermediário, sem dicionário DSS
     */
    private void buildDocTimeStamp(SignaturePolicyProxy sigPolProxy,
                                   BrExtMandatedDocTSEntries policyDocTS, PDSignature tsDictionary,
                                   SignatureInterface timeStampSignatureImp, PDDocument pdfwithoutDSS) {

        for (PdfEntry pdfEntry : policyDocTS.getMandatedDocTSEntries()) {
            String entryId = pdfEntry.getPdfEntryID();
            DERUTF8String temp = null;
            switch (entryId) {
                case "Type":
                    try {
                        temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntry.getPdfEntryValue());
                    } catch (IOException e) {
                        Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                    }
                    tsDictionary.setType(COSName.getPDFName(temp.getString()));
                    break;
                case "SubFilter":
                    try {
                        temp = (DERUTF8String) DERUTF8String.fromByteArray(pdfEntry.getPdfEntryValue());
                    } catch (IOException e) {
                        Application.logger.log(Level.SEVERE, "Erro ao adicionar Type no DSS.");
                    }
                    tsDictionary.setSubFilter(COSName.getPDFName(temp.getString()));
                    break;

                case "Contents":
                    try {
                        pdfwithoutDSS.addSignature(tsDictionary, timeStampSignatureImp);
                    } catch (IOException e) {
                        Application.logger.log(Level.SEVERE,
                                "Erro ao gerar assinatura do carimbo do tempo.");
                    }
                    break;

                default:
                    break;
            }
        }
    }

    /**
     * Retorna a última assinatura presente na lista de assinaturas
     * @param signatures A lista de assinaturas
     * @return A última assinatura presente na lista de assinaturas
     */
    private PDSignature getLastSignature(List<PDSignature> signatures) {

        PDSignature last = signatures.get(0);
        int[] lastByteRange = last.getByteRange();
        int index = 0;

        for (int i = 1; i < signatures.size(); i++) {
            PDSignature toCompare = signatures.get(i);
            int[] toCompareByteRange = toCompare.getByteRange();
            if (toCompareByteRange[1] > lastByteRange[1]) {
                last = toCompare;
                lastByteRange = toCompareByteRange;
                index = i;
            }
        }
        signatures.remove(index);
        return last;
    }

    /**
     * Gera o dicionário DSS e o VRI
     * @param sigPolProxy A política de assinatura
     * @param extDss
     * @param contents O conteúdo assinado
     * @param oldDss Dicionário DSS antigo da assinatura
     * @param certificate O certificado do assinante
     * @param dssDecoder O decodificador de DSS
     * @return O dicionário DSS gerado
     */
    private COSDictionary buildDSS(SignaturePolicyProxy sigPolProxy, BrExtDss extDss,
                                   byte[] contents, COSDictionary oldDss, Certificate certificate, DSSDecoder dssDecoder) {
        dssDecoder.setNewSignature(sigPolProxy, extDss, contents, certificate);
        return dssDecoder.getDSS();
    }

    /**
     * Retorna o arquivo assinado
     * @return O {@link InputStream} do arquivo assinado
     */
    @Override
    public InputStream getSignatureStream() {
        if (pdfOutputStream != null) {
            byte[] bytes = pdfOutputStream.toByteArray();
            return new ByteArrayInputStream(bytes);
        }
        return null;
    }

    /**
     * Salva a assinatura gerada em formato .pdf
     * @return Indica se a assinatura foi salva com sucesso
     */
    @Override
    public boolean save() {
        return false;
    }

    /**
     * Adiciona um atributo à assinatura
     * @param attribute O atributo a ser selecionado
     */
    @Override
    public void selectAttribute(String attribute) {
        this.padesComponent.getCadesSigner().selectAttribute(attribute);
    }

    /**
     * Remove um atributo da assinatura
     * @param attribute O atributo a ser removido
     */
    @Override
    public void unselectAttribute(String attribute) {
        this.padesComponent.getCadesSigner().unselectAttribute(attribute);
    }

    /**
     * Retorna a lista de atributos da assinatura
     * @return A lista de atributos da assinatura
     */
    @Override
    public List<String> getAttributesAvailable() {
        return null;
    }

    /**
     * Retorna a lista dos tipos de assinatura disponíveis
     * @return Lista dos tipos de assinatura disponíveis
     */
    @Override
    public List<String> getAvailableModes() {
        return Collections.singletonList("Destacada");
    }

    /**
     * Retorna a lista de atributos assinados obrigatórios da assinatura
     * @return A lista de atributos assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedSignedAttributeList() {
        List<String> attributesAvailable = new ArrayList<String>();

        attributesAvailable.add(AttributeFactory.id_aa_ets_signerLocation);
        attributesAvailable.add(AttributeFactory.id_contentType);
        attributesAvailable.add(AttributeFactory.id_aa_contentHint);
        attributesAvailable.add(AttributeFactory.id_signingTime);
        attributesAvailable.add(AttributeFactory.id_messageDigest);
        attributesAvailable.add(AttributeFactory.id_aa_signingCertificate);

        return attributesAvailable;
    }

    /**
     * Atribue o tipo de assinatura, anexada ou destacada
     * @param mode O tipo da assinatura
     */
    @Override
    public void setMode(FileFormat mode, String suite) {
        this.suite = suite;
    }

    /**
     * Retorna a lista de atributos assinados da assinatura
     * @return A lista de atributos assinados da assinatura
     */
    @Override
    public List<String> getSignedAttributesAvailable() {
        return this.padesComponent.getCadesSigner()
                .getSignedAttributesAvailable();
    }

    /**
     * Retorna a lista de atributos não assinados da assinatura
     * @return A lista de atributos não assinados da assinatura
     */
    @Override
    public List<String> getUnsignedAttributesAvailable() {
        return this.padesComponent.getCadesSigner()
                .getUnsignedAttributesAvailable();
    }

    /**
     * Retorna a lista de políticas de assinatura disponiveis
     * @return A lista de políticas de assinatura
     */
    @Override
    public List<String> getPoliciesAvailable() {
        return this.padesComponent.getCadesSigner().getPoliciesAvailable();
    }

    /**
     * Retorna a lista de atributos não assinados obrigatórios da assinatura
     * @return A lista de atributos não assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedUnsignedAttributeList() {
        return this.padesComponent.getCadesSigner()
                .getMandatedUnsignedAttributeList();
    }

    @Override
    public boolean supports(InputStream target, br.ufsc.labsec.signature.signer.SignerType signerType) throws CertificationPathException, SignerException {
        try {
            PDDocument.load(target);
            target.reset();
        } catch (IOException e) {
            throw new SignerException(SignerException.MALFORMED_TBS_FILE);
        }
        return this.padesComponent.cadesSigner.supports(target, signerType);
    }

    /**
     * Retorna o componente de assinatura PAdES
     * @return O componente de assinatura PAdES
     */
    public PadesSignatureComponent getPadesComponent() {
        return padesComponent;
    }


    @Override
    public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyOid) {
        selectTarget(target, policyOid.toString());
        if (sign()) {
            InputStream stream = getSignatureStream();
            SignatureDataWrapper signature = new SignatureDataWrapper(stream, null, filename);
            return signature;
        }
        return null;
    }
}
