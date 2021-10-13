package br.ufsc.labsec.signature.signer.signatureSwitch.pdfSigner;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.AlgorithmIdentifierMapper;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PDFSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.PdfSignatureComponent;
import br.ufsc.labsec.signature.signer.suite.SingletonSuiteMapper;
import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.CMSSignedDataGenerator;
import org.bouncycastle.cms.jcajce.JcaSignerInfoGeneratorBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.logging.Level;

public final class SignatureContainerGenerator {

    /**
     * Componente de assinatura PDF
     */
    private PdfSignatureComponent pdfSignatureComponent;
    /**
     * Chave privada do assinante
     */
    private final PrivateKey privateKey;
    /**
     * Cadeia de certificados do assinante
     */
    private final Certificate[] certificateChain;
    /**
     * Algoritmo utilizado na assinatura
     */
    private String signatureSuite = SingletonSuiteMapper.getDefaultSignatureSuite();

    /**
     * Construtor
     * @param pdfSignatureComponent Componente de assinatura PDF
     * @param privateKey Chave privada do assinante
     * @param certificateChain Cadeia de certificados do assinante
     */
    public SignatureContainerGenerator(PdfSignatureComponent pdfSignatureComponent, PrivateKey privateKey, Certificate[] certificateChain) {
        this.pdfSignatureComponent = pdfSignatureComponent;
        this.privateKey = privateKey;
        this.certificateChain = certificateChain;
    }

    /**
     * Esta classe representa uma assinatura PDF
     */
    private class PdfSignature implements SignatureInterface {
        /**
         * Implementation of the method sign() of a given class that implements the SignatureInterface interface,
         * following the standard procedure for getting CMS data using the BouncyCastle API.
         *
         * @param  is Input stream holding the document to be signed.
         * @return The signed document bytes.
         */
        @Override
        public byte[] sign(InputStream is) {
            byte[] signature = null;

            try {
                CMSSignedDataGenerator generator = new CMSSignedDataGenerator();
                X509Certificate cert = (X509Certificate) certificateChain[0];
                String algorithm = AlgorithmIdentifierMapper.getAlgorithmNameFromIdentifier(signatureSuite);
                ContentSigner shaSigner = new JcaContentSignerBuilder(algorithm).build(privateKey);
                generator.addCertificate(
                        new X509CertificateHolder(cert.getEncoded()));
                generator.addSignerInfoGenerator(
                        new JcaSignerInfoGeneratorBuilder(
                                new JcaDigestCalculatorProviderBuilder().build()).build(shaSigner, cert)
                );

                byte[] bytes = IOUtils.toByteArray(is);

                CMSProcessableByteArray byteArray = new CMSProcessableByteArray(bytes);
                CMSSignedData signedData = generator.generate(byteArray, false);

                signature = signedData.getEncoded();
            } catch (IOException | OperatorCreationException | CMSException | CertificateEncodingException e) {
                Application.logger.log(Level.SEVERE, e.getMessage(), e);
            }
            return signature;
        }
    }

    public void setSignatureSuite(String signatureSuite) {
        this.signatureSuite = signatureSuite;
    }

    /**
     * Gera o contêiner de assinatura PDF
     * @param pdfInputStream O arquivo assinado
     * @param location
     * @param reason
     * @return O contêiner de assinatura PDF
     */
    public PDFSignatureContainer generate(InputStream pdfInputStream, String location, String reason) {
        PDDocument pdDocument = null;
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        try {
            byte[] pdfBytes = PdfHandler.handlesBytes(pdfInputStream);

            pdDocument = PdfHandler.handlesDocument(pdfBytes);
            PdfSignature pdfSignature = new PdfSignature();
            PdfHandler.appendSignature(pdDocument, location, reason, pdfSignature);
            PdfHandler.writeDoc(pdDocument, out);
        } catch (IOException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        return new PDFSignatureContainer(pdfSignatureComponent, out.toByteArray(), pdDocument);
    }

}
