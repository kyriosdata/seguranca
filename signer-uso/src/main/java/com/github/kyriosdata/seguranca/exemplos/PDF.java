package com.github.kyriosdata.seguranca.exemplos;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.io.IOUtils;
import org.apache.pdfbox.io.RandomAccessReadBufferedFile;
import org.apache.pdfbox.pdfparser.PDFParser;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentCatalog;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;
import org.apache.pdfbox.util.Hex;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.List;

/**
 * Extrai a assinatura digital do docmento PDF fornecido.
 */
public final class PDF {

    /**
     * Extrai assinatura e deposita em arquivo prório.
     *
     * @param args Caminho do arquivo PDF cuja assinatura será extraída.
     * @throws IOException If there is an error reading the file.
     */
    public static void main(String[] args) throws IOException {
        PDF show = new PDF();
        show.extraiAssinatura("d:/downloads/assinado.pdf");
    }

    private void extraiAssinatura(String arquivo) throws IOException {
        System.out.println("Arquivo a ser analisado: " + arquivo);
        String password = "";
        File infile = new File(arquivo);

        RandomAccessReadBufferedFile raFile = new RandomAccessReadBufferedFile(infile);
        PDFParser parser = new PDFParser(raFile, password);
        try (PDDocument document = parser.parse(false)) {
            List<PDSignature> signatureDictionaries = document.getSignatureDictionaries();
            if (signatureDictionaries.isEmpty()) {
                System.out.println("Arquivo não contém assinatura.");
                return;
            }

            System.out.println("Assinatura presente no arquivo.");
            System.out.println("Total de assinaturas: " + signatureDictionaries.size());
            for (PDSignature sig : signatureDictionaries) {
                byte[] contents = sig.getContents();

                Path path = Paths.get(arquivo + ".p7s");
                Files.write(path, contents);

                if (sig.getName() != null) {
                    System.out.println("Name:     " + sig.getName());
                }
                if (sig.getSignDate() != null) {
                    SimpleDateFormat sdf = new SimpleDateFormat("dd.MM.yyyy HH:mm:ss");
                    System.out.println("Data da assinatura: " + sdf.format(sig.getSignDate().getTime()));
                }
                String subFilter = sig.getSubFilter();
                if (subFilter != null) {
                    System.out.println("Subfilter: " + subFilter);
                } else {
                    System.out.println("Subfilter não encontrado?... ");
                    return;
                }

                int[] byteRange = sig.getByteRange();
                if (byteRange.length != 4) {
                    System.err.println("Deveria conter 4 inteiros??!!!");
                } else {
                    long fileLen = infile.length();
                    long rangeMax = byteRange[2] + (long) byteRange[3];
                    // multiply content length with 2 (because it is in hex in the PDF) and add 2 for < and >
                    int contentLen = contents.length * 2 + 2;
                    if (fileLen != rangeMax || byteRange[0] != 0 || byteRange[1] + contentLen != byteRange[2]) {
                        // a false result doesn't necessarily mean that the PDF is a fake
                        // see this answer why:
                        // https://stackoverflow.com/a/48185913/535646
                        System.out.println("Assinatura NÃO contempla todo o documento.");
                    } else {
                        System.out.println("Assinatura contempla todo o documento.");
                    }
                    checkContentValueWithFile(infile, byteRange, contents);
                }
            }
            analyseDSS(document);
        }
    }

    private void checkContentValueWithFile(File file, int[] byteRange, byte[] contents) throws IOException {
        // https://stackoverflow.com/questions/55049270
        // comment by mkl: check whether gap contains a hex value equal
        // byte-by-byte to the Content value, to prevent attacker from using a literal string
        // to allow extra space
        try (RandomAccessReadBufferedFile raf = new RandomAccessReadBufferedFile(file)) {
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
    }

    /**
     * Analyzes the DSS-Dictionary (Document Security Store) of the document. Which is used for signature validation.
     * The DSS is defined in PAdES Part 4 - Long Term Validation.
     *
     * @param document PDDocument, to get the DSS from
     */
    private void analyseDSS(PDDocument document) throws IOException {
        PDDocumentCatalog catalog = document.getDocumentCatalog();
        COSBase dssElement = catalog.getCOSObject().getDictionaryObject("DSS");

        if (dssElement instanceof COSDictionary) {
            COSDictionary dss = (COSDictionary) dssElement;
            System.out.println("DSS Dictionary: " + dss);
            COSBase certsElement = dss.getDictionaryObject("Certs");
            if (certsElement instanceof COSArray) {
                printStreamsFromArray((COSArray) certsElement, "Cert");
            }
            COSBase ocspsElement = dss.getDictionaryObject("OCSPs");
            if (ocspsElement instanceof COSArray) {
                printStreamsFromArray((COSArray) ocspsElement, "Ocsp");
            }
            COSBase crlElement = dss.getDictionaryObject("CRLs");
            if (crlElement instanceof COSArray) {
                printStreamsFromArray((COSArray) crlElement, "CRL");
            }
            // TODO: go through VRIs (which indirectly point to the DSS-Data)
        }
    }

    /**
     * Go through the elements of a COSArray containing each an COSStream to print in Hex.
     *
     * @param elements    COSArray of elements containing a COS Stream
     * @param description to append on Print
     * @throws IOException
     */
    private void printStreamsFromArray(COSArray elements, String description) throws IOException {
        for (COSBase baseElem : elements) {
            COSObject streamObj = (COSObject) baseElem;
            if (streamObj.getObject() instanceof COSStream) {
                COSStream cosStream = (COSStream) streamObj.getObject();
                try (InputStream is = cosStream.createInputStream()) {
                    byte[] streamBytes = IOUtils.toByteArray(is);
                    System.out.println(description + " (" + elements.indexOf(streamObj) + "): "
                            + Hex.getString(streamBytes));
                }
            }
        }
    }
}