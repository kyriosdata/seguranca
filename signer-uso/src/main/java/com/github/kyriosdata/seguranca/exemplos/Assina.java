package com.github.kyriosdata.seguranca.exemplos;

import org.apache.pdfbox.Loader;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.ExternalSigningSupport;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.demoiselle.signer.policy.impl.pades.pkcs7.impl.PAdESSigner;

import java.io.*;
import java.security.*;
import java.util.Arrays;
import java.util.Calendar;

import static com.github.kyriosdata.seguranca.exemplos.PDF.SRC_PDF;

/**
 * Veja referência em
 * https://svn.apache.org/viewvc/pdfbox/trunk/examples/src/main/java/org/apache/pdfbox/examples/signature/CreateSignature.java?revision=1899086&view=markup
 */
public class Assina {

    public static void signDetached(PDDocument document, OutputStream output, byte[] assinatura)
            throws IOException {

        int accessPermissions = SigUtils.getMDPPermission(document);
        if (accessPermissions == 1) {
            throw new IllegalStateException("No changes to the document are permitted due to DocMDP transform parameters dictionary");
        }

        // create signature dictionary
        PDSignature signature = new PDSignature();
        signature.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        signature.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        signature.setName("Example User");
        signature.setLocation("Los Angeles, CA");
        signature.setReason("Testing");

        // TODO extract the above details from the signing certificate? Reason as a parameter?

        // the signing date, needed for valid signature
        signature.setSignDate(Calendar.getInstance());

        // Optional: certify
        if (accessPermissions == 0) {
            SigUtils.setMDPPermission(document, signature, 2);
        }

        document.addSignature(signature);
        ExternalSigningSupport externalSigning =
                document.saveIncrementalForExternalSigning(output);

        // set signature bytes received from the service
        externalSigning.setSignature(assinatura);
    }

    public static byte[] sign(String password, String alias, KeyStore store) throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableKeyException, IOException {
        PAdESSigner signer = new PAdESSigner();
        signer.setCertificates(store.getCertificateChain(alias));

        signer.setPrivateKey((PrivateKey) store.getKey(alias, password.toCharArray()));

        byte[] content = new FileInputStream(SRC_PDF).readAllBytes();
        byte [] assinatura = signer.doDetachedSign(content);
        return assinatura;
    }

    public static void main(String[] args) throws IOException, GeneralSecurityException {
        String certificadoArquivo = System.getenv("CERTIFICADO_TESTE");
        String password = System.getenv("CERTIFICADO_SENHA");
        String alias = System.getenv("CERTIFICADO_ALIAS");

        KeyStore store = KeyStore.getInstance("PKCS12");
        store.load(new FileInputStream(certificadoArquivo), password.toCharArray());

        // TODO alias command line argument

        File outFile = new File("assinado_signed.pdf");

        byte[] assinatura = sign(password, alias, store);

        PDDocument doc = Loader.loadPDF(new FileInputStream(SRC_PDF).readAllBytes());
        signDetached(doc, new FileOutputStream(outFile), assinatura);
    }
}
