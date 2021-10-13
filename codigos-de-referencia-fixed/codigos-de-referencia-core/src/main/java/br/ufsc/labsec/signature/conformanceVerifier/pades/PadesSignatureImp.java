/**
 *
 */
package br.ufsc.labsec.signature.conformanceVerifier.pades;

import java.io.IOException;
import java.io.InputStream;

import br.ufsc.labsec.signature.signer.FileFormat;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import br.ufsc.labsec.signature.Signer;

/**
 * Esta classe implementa métodos para auxiliar na criação de uma assinatura PAdES.
 */
public class PadesSignatureImp implements SignatureInterface {

    /**
     * Assinador PAdES
     */
    private Signer signer;
    /**
     * Política de assinatura
     */
    private String policyOid;
    /**
     * Bytes da assinatura
     */
    private byte[] savedBuffer;
    /**
     *  Suite da assinatura
     */
    private String signatureSuite;

    /**
     * Construtor
     * @param signer Assinador PAdES
     * @param policyOid Política de assinatura
     */
    public PadesSignatureImp(Signer signer, String policyOid, String signatureSuite) {
        this.signer = signer;
        this.policyOid = policyOid;
        this.signatureSuite = signatureSuite;
    }

    /**
     * Realiza a assinatura
     * @param content Stream do documento a ser assinado
     * @return Os bytes da assinatura
     * @throws IOException
     */
    @Override
    public byte[] sign(InputStream content) throws
            IOException {

        byte[] buffer = null;

        signer.selectTarget(content, policyOid);
        signer.setMode(FileFormat.DETACHED, signatureSuite);

        if (signer.sign()) {
            InputStream signatureStream = signer.getSignatureStream();
            buffer = IOUtils.toByteArray(signatureStream);

        }
        this.savedBuffer = buffer;

        return buffer;
    }

    /**
     * Retorna os bytes da assinatura
     * @return Os bytes da assinatura
     */
    public byte[] getSavedBuffer() {
        return savedBuffer;
    }

}
