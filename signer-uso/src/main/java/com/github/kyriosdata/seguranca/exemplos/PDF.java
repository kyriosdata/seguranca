package com.github.kyriosdata.seguranca.exemplos;

import org.apache.pdfbox.io.*;
import org.apache.pdfbox.pdfparser.PDFParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.encryption.SecurityProvider;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.COSFilterInputStream;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.util.Hex;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.cms.CMSAttributes;
import org.bouncycastle.asn1.cms.Time;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessable;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampToken;
import org.bouncycastle.util.Store;
import org.demoiselle.signer.core.CertificateLoader;
import org.demoiselle.signer.core.CertificateLoaderImpl;
import org.demoiselle.signer.cryptography.DigestAlgorithmEnum;
import org.demoiselle.signer.policy.impl.cades.SignatureInformations;
import org.demoiselle.signer.policy.impl.cades.SignerAlgorithmEnum;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESChecker;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESSigner;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;

/**
 * Verifica conformidade de um arquivo PDF assinado com certificado ICP-Brasil.
 *
 * FALTA FAZER:
 * (a) criar função (library) que recebe InputStream do arquivo PDF e retorna
 * resultado da verificação.
 * (b) criar aplicativo via linha de comandos que realiza esta operação para um arquivo fornecido como argumento.
 */
public final class PDF {

    public static final String SRC_PDF = "src/main/resources/arquivo-signer-teste.pdf";
    public static final String SGN_PDF = "src/main/resources/arquivo-signer-teste_assinado.pdf";

    /**
     * Extrai assinatura e deposita em arquivo prório.
     *
     * @param args Caminho do arquivo PDF cuja assinatura será extraída.
     * @throws IOException If there is an error reading the file.
     */
    public static void main2(String[] args) throws IOException, OperatorCreationException, GeneralSecurityException, TSPException, CMSException {
        Security.setProperty("crypto.policy", "unlimited");

        PDF pdf = new PDF();
        final File infile = new File(SGN_PDF);
        PdfData dados = pdf.extraiDados(SGN_PDF, "", infile, new FileInputStream(infile));

        validaICPBrasil(dados.assinatura, dados.dadosAssinados);
    }

    public static void main(String[] args) throws IOException, OperatorCreationException, GeneralSecurityException, TSPException, CMSException {
        Security.setProperty("crypto.policy", "unlimited");

        PDF pdf = new PDF();
        pdf.signPdf();
    }

    public void signPdf() throws IOException, KeyStoreException, UnrecoverableKeyException, NoSuchAlgorithmException, NoSuchProviderException, CertificateException {
        byte[] content = new FileInputStream(SRC_PDF).readAllBytes();

        String certificadoArquivo = System.getenv("CERTIFICADO_TESTE");
        String password = System.getenv("CERTIFICADO_SENHA");
        String alias = System.getenv("CERTIFICADO_ALIAS");

        File certificado = new File(certificadoArquivo);
        PAdESSigner signer = new PAdESSigner();

        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new FileInputStream(certificado), password.toCharArray());

        signer.setCertificates(store.getCertificateChain(alias));

        signer.setPrivateKey((PrivateKey) store.getKey(alias, password.toCharArray()));

        byte [] assinatura = signer.doDetachedSign(content);
        System.out.println("Total de bytes: " + assinatura.length);
    }

    private PdfData extraiDados(String arquivo, String password, File infile, InputStream is) throws IOException, OperatorCreationException, GeneralSecurityException, TSPException, CMSException {
        byte[] conteudo = is.readAllBytes();
        InputStream bis = new ByteArrayInputStream(conteudo);

        System.out.println("Arquivo a ser analisado: " + arquivo);
        PdfData resposta = new PdfData();

        RandomAccessRead raFile = new RandomAccessReadBuffer(bis);
        PDFParser parser = new PDFParser(raFile, password);
        try (PDDocument document = parser.parse(false)) {
            List<PDSignature> signatureDictionaries = document.getSignatureDictionaries();
            if (signatureDictionaries.isEmpty()) {
                throw new RuntimeException("Arquivo não contém assinatura.");
            }

            for (PDSignature sig : signatureDictionaries) {
                byte[] assinatura = sig.getContents();

                resposta.assinatura = assinatura;

                if (sig.getSignDate() != null) {
                    SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
                    resposta.dataAssinatura = sdf.format(sig.getSignDate().getTime());
                }

                resposta.subfilter = sig.getSubFilter();
                if (resposta.subfilter == null) {
                    throw new RuntimeException("subfilter não encontrado?!");
                }

                bis.reset();
                InputStream signedContentAsStream = new COSFilterInputStream(bis, sig.getByteRange());

                try {
                    resposta.dadosAssinados = signedContentAsStream.readAllBytes();
                } catch (Exception exp) {
                    throw new RuntimeException("erro ao carregar conteúdo assinado...");
                }

                //verifyPKCS7(signedContentAsStream, assinatura, sig);

                int[] byteRange = sig.getByteRange();
                if (byteRange.length != 4) {
                    System.err.println("Deveria conter 4 inteiros??!!!");
                } else {
                    long fileLen = infile.length();
                    long rangeMax = byteRange[2] + (long) byteRange[3];
                    // multiply content length with 2 (because it is in hex in the PDF) and add 2 for < and >
                    int contentLen = assinatura.length * 2 + 2;
                    // a false result doesn't necessarily mean that the PDF is a fake
                    // see this answer why:
                    // https://stackoverflow.com/a/48185913/535646
                    resposta.todoPdfContemplado =
                            fileLen == rangeMax && byteRange[0] == 0 && byteRange[1] + contentLen == byteRange[2];
                    checkContent(raFile, byteRange, assinatura);
                }
            }
        }

        return resposta;
    }

    private void checkContent(RandomAccessRead raf, int[] byteRange, byte[] contents) throws IOException {
        // https://stackoverflow.com/questions/55049270
        // comment by mkl: check whether gap contains a hex value equal
        // byte-by-byte to the Content value, to prevent attacker from using a literal string
        // to allow extra space
        raf.seek(byteRange[1]);
        int c = raf.read();
        if (c != '<') {
            System.err.println("'<' expected at offset " + byteRange[1] + ", but got " + (char) c);
        }
        byte[] contentFromFile = new byte[byteRange[2] - byteRange[1] - 2];
        int contentLength = contentFromFile.length;
        int contentBytesRead = raf.read(contentFromFile);
        while (contentBytesRead > -1 && contentBytesRead < contentLength) {
            contentBytesRead += raf.read(contentFromFile,
                    contentBytesRead,
                    contentLength - contentBytesRead);
        }
        byte[] contentAsHex = Hex.getString(contents).getBytes(StandardCharsets.US_ASCII);
        if (contentBytesRead != contentAsHex.length) {
            System.err.println("Raw content length from file is " +
                    contentBytesRead +
                    ", but internal content string in hex has length " +
                    contentAsHex.length);
        }
        // Compare the two, we can't do byte comparison because of upper/lower case
        // also check that it is really hex
        for (int i = 0; i < contentBytesRead; ++i) {
            try {
                if (Integer.parseInt(String.valueOf((char) contentFromFile[i]), 16) !=
                        Integer.parseInt(String.valueOf((char) contentAsHex[i]), 16)) {
                    System.err.println("Possible manipulation at file offset " +
                            (byteRange[1] + i + 1) + " in signature content");
                    break;
                }
            } catch (NumberFormatException ex) {
                System.err.println("Incorrect hex value");
                System.err.println("Possible manipulation at file offset " +
                        (byteRange[1] + i + 1) + " in signature content");
                break;
            }
        }
        c = raf.read();
        if (c != '>') {
            System.err.println("'>' expected at offset " + byteRange[2] + ", but got " + (char) c);
        }
    }

    private static void validaICPBrasil(byte[] assinatura, byte[] conteudoAssinado) throws IOException {
        PAdESChecker checker = new PAdESChecker();

        MessageDigest md = null;
        try {
            md = MessageDigest.getInstance(DigestAlgorithmEnum.SHA_256.getAlgorithm());
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        byte[] hash = md.digest(conteudoAssinado);

        List<SignatureInformations> signaturesInfo = checker.checkSignatureByHash(SignerAlgorithmEnum.SHA256withRSA.getOIDAlgorithmHash(), hash, assinatura);

        // TODO Ver exemplo de como exibir o resultado exemplo em
        // https://www.frameworkdemoiselle.gov.br/v3/signer/docs/policy-impl-pades-funcionalidades.html
        System.out.println(signaturesInfo.size());
    }

    private static void validaICPBrasilPeloConteudo(byte[] assinatura, byte[] conteudoAssinado) throws IOException {
        PAdESChecker checker = new PAdESChecker();

        List<SignatureInformations> signaturesInfo = checker.checkDetachedSignature(conteudoAssinado, assinatura);

        // TODO Ver exemplo de como exibir o resultado exemplo em
        // https://www.frameworkdemoiselle.gov.br/v3/signer/docs/policy-impl-pades-funcionalidades.html
        System.out.println("Assinatura válida: " + !signaturesInfo.get(0).isInvalidSignature());
    }

    /**
     * Verify a PKCS7 signature.
     *
     * @param signedContentAsStream the byte sequence that has been signed
     * @param contents              the /Contents field as a COSString
     * @param sig                   the PDF signature (the /V dictionary)
     * @throws CMSException
     * @throws OperatorCreationException
     * @throws GeneralSecurityException
     */
    private void verifyPKCS7(InputStream signedContentAsStream, byte[] contents, PDSignature sig)
            throws CMSException, OperatorCreationException,
            GeneralSecurityException,
            TSPException, IOException {
        // inspiration:
        // http://stackoverflow.com/a/26702631/535646
        // http://stackoverflow.com/a/9261365/535646
        CMSProcessable signedContent = new CMSProcessableInputStream(signedContentAsStream);
        CMSSignedData signedData = new CMSSignedData(signedContent, contents);
        Store<X509CertificateHolder> certificatesStore = signedData.getCertificates();
        if (certificatesStore.getMatches(null).isEmpty()) {
            throw new IOException("No certificates in signature");
        }
        Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
        if (signers.isEmpty()) {
            throw new IOException("No signers in signature");
        }
        SignerInformation signerInformation = signers.iterator().next();
        @SuppressWarnings("unchecked")
        Collection<X509CertificateHolder> matches =
                certificatesStore.getMatches(signerInformation.getSID());
        if (matches.isEmpty()) {
            throw new IOException("Signer '" + signerInformation.getSID().getIssuer() +
                    ", serial# " + signerInformation.getSID().getSerialNumber() +
                    " does not match any certificates");
        }
        X509CertificateHolder certificateHolder = matches.iterator().next();
        X509Certificate certFromSignedData = new JcaX509CertificateConverter().getCertificate(certificateHolder);
        System.out.println("certFromSignedData: " + certFromSignedData);

        SigUtils.checkCertificateUsage(certFromSignedData);

        // Embedded timestamp
        TimeStampToken timeStampToken = SigUtils.extractTimeStampTokenFromSignerInformation(signerInformation);
        if (timeStampToken != null) {
            // tested with QV_RCA1_RCA3_CPCPS_V4_11.pdf
            // https://www.quovadisglobal.com/~/media/Files/Repository/QV_RCA1_RCA3_CPCPS_V4_11.ashx
            // also 021496.pdf and 036351.pdf from digitalcorpora
            SigUtils.validateTimestampToken(timeStampToken);
            X509Certificate certFromTimeStamp = SigUtils.getCertificateFromTimeStampToken(timeStampToken);
            // merge both stores using a set to remove duplicates
            HashSet<X509CertificateHolder> certificateHolderSet = new HashSet<>();
            certificateHolderSet.addAll(certificatesStore.getMatches(null));
            certificateHolderSet.addAll(timeStampToken.getCertificates().getMatches(null));

            SigUtils.checkTimeStampCertificateUsage(certFromTimeStamp);

            // compare the hash of the signature with the hash in the timestamp
            byte[] tsMessageImprintDigest = timeStampToken.getTimeStampInfo().getMessageImprintDigest();
            String hashAlgorithm = timeStampToken.getTimeStampInfo().getMessageImprintAlgOID().getId();
            byte[] sigMessageImprintDigest = MessageDigest.getInstance(hashAlgorithm).digest(signerInformation.getSignature());
            if (Arrays.equals(tsMessageImprintDigest, sigMessageImprintDigest)) {
                System.out.println("timestamp signature verified");
            } else {
                System.err.println("timestamp signature verification failed");
            }
        }

        try {
            if (sig.getSignDate() != null) {
                certFromSignedData.checkValidity(sig.getSignDate().getTime());
                System.out.println("Certificate valid at signing time");
            } else {
                System.err.println("Certificate cannot be verified without signing time");
            }
        } catch (CertificateExpiredException ex) {
            System.err.println("Certificate expired at signing time");
        } catch (CertificateNotYetValidException ex) {
            System.err.println("Certificate not yet valid at signing time");
        }

        // usually not available
        if (signerInformation.getSignedAttributes() != null) {
            // From SignedMailValidator.getSignatureTime()
            Attribute signingTime = signerInformation.getSignedAttributes().get(CMSAttributes.signingTime);
            if (signingTime != null) {
                Time timeInstance = Time.getInstance(signingTime.getAttrValues().getObjectAt(0));
                try {
                    certFromSignedData.checkValidity(timeInstance.getDate());
                    System.out.println("Certificate valid at signing time: " + timeInstance.getDate());
                } catch (CertificateExpiredException ex) {
                    System.err.println("Certificate expired at signing time");
                } catch (CertificateNotYetValidException ex) {
                    System.err.println("Certificate not yet valid at signing time");
                }
            }
        }

        if (signerInformation.verify(new JcaSimpleSignerInfoVerifierBuilder().
                setProvider(SecurityProvider.getProvider()).build(certFromSignedData))) {
            System.out.println("Signature verified");
        } else {
            System.out.println("Signature verification failed");
        }

        System.out.println("Certificate is not self-signed");

        if (sig.getSignDate() != null) {
            System.out.println("it has sign date");
        } else {
            System.err.println("Certificate cannot be verified without signing time");
        }
    }

}