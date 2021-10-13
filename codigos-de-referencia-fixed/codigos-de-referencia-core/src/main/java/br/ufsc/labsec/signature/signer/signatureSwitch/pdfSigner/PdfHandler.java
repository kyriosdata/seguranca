package br.ufsc.labsec.signature.signer.signatureSwitch.pdfSigner;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.PDDocumentUtils;
import org.apache.commons.io.IOUtils;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Calendar;

public final class PdfHandler {

    public static byte[] handlesBytes(InputStream pdf) throws IOException {
        return IOUtils.toByteArray(pdf);
    }

    public static PDDocument handlesDocument(byte[] pdf) throws IOException {
        return PDDocumentUtils.openPDDocument(pdf);
    }

    /**
     * Saves the user's .PDF incrementally in the memory. Note that saving incrementally
     * is important in order to not overwrite the document's whole content.
     *
     * @param  pdd         The PDDocument object holding a given .PDF file.
     * @param  out         A output stream of any kind.
     * @throws IOException In case the output stream cannot be closed properly.
     */
    public static void writeDoc(PDDocument pdd, OutputStream out) throws IOException{
            pdd.saveIncremental(out);
            out.close();
    }

    /**
     * Adds a PDSignature object to a given PDDocument object.
     *
     * @param pdd    PDDocument representation of a .PDF.
     * @param place  The location in which the signature occurs.
     * @param reason The reason for the signature process.
     */
    public static void appendSignature(PDDocument pdd,
                                       String place,
                                       String reason,
                                       SignatureInterface signature) throws IOException {
        pdd.addSignature(setFields(place, reason), signature);
    }

    /**
     * Sets the fields of a PDSignature according to the below parameters.
     *
     * @param  place  Where the signature occurs.
     * @param  reason for the signature process.
     * @return        A PDSignature object to be added to a PDDocument object.
     */
    protected static PDSignature setFields(String place, String reason) {
        PDSignature pds = new PDSignature();
        pds.setFilter(PDSignature.FILTER_ADOBE_PPKLITE);
        pds.setSubFilter(PDSignature.SUBFILTER_ADBE_PKCS7_DETACHED);
        pds.setSignDate(Calendar.getInstance());
        if (place != null) {
            pds.setLocation(place);
        }
        if (reason != null) {
            pds.setReason(reason);
        }
        return pds;
    }
}
