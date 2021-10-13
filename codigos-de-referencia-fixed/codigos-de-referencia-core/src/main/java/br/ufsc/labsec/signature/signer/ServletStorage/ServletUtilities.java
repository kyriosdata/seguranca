package br.ufsc.labsec.signature.signer.ServletStorage;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.Constants;
import br.ufsc.labsec.signature.SystemTime;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.signer.SignerType;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.Part;
import org.apache.pdfbox.io.IOUtils;
import java.io.*;
import java.nio.file.Paths;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.logging.Level;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Esta classe contém métodos auxiliares utilizados em {@link br.ufsc.labsec.signature.signer.SignerServlet}
 */
public final class ServletUtilities {

    /**
     * Construtor
     */
    private ServletUtilities() {}

    /**
     * Escreve os bytes no {@link OutputStream} dado
     * @param out O {@link OutputStream} a ser escrito
     * @param file Os bytes a serem copiados
     */
    public static void writeFile(OutputStream out, byte[] file) {
        try {
            out.write(file);
            out.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    /**
     * Preenche a estrutura com os arquivos assinados
     * @param zipOut Mapa que relaciona o nome dos arquivos com seu conteúdo
     * @param signatureDataWrappers Arquivos assinados
     */
    public static void fillZip(ZipOutputStream zipOut, List<SignatureDataWrapper> signatureDataWrappers) {

        for (SignatureDataWrapper dataWrapper : signatureDataWrappers) {
            try {
                byte[] signature;
                if (dataWrapper.det() != null) {
                    signature = IOUtils.toByteArray(dataWrapper.det());
                } else {
                    signature = IOUtils.toByteArray(dataWrapper.sig());
                }
                prepareToClose(zipOut, dataWrapper.name(), signature);
            } catch (IOException e) {
                Application.logger.log(Level.SEVERE,
                        "Não foi possível adicionar o arquivo de assinatura à resposta.", e);
            }
        }

        try {
            zipOut.close();
        } catch (IOException e) {
            Application.logger.log(Level.SEVERE, e.getMessage(), e);
        }
    }

    public static void isFieldEmpty(HttpServletRequest req, HttpServletResponse resp, String str) {
        if (str != null && str.equals("")) {
            try {
                resp.sendRedirect(req.getContextPath());
            } catch (IOException e) {
                Application.logger.log(Level.WARNING, e.getMessage(), e);
            }
        }
    }

    /**
     * Preenche o Header de resposta com os dados de saída do Assinador quando a resposta é um arquivo ZIP
     * @param req A requisição HTTP
     * @param resp A resposta HTTP
     */
    public static void turnOnPreamble(HttpServletRequest req, HttpServletResponse resp){
        try {
            req.setCharacterEncoding("UTF-8");
        } catch (UnsupportedEncodingException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        resp.setContentType("application/zip");
        SimpleDateFormat dateFormat = new SimpleDateFormat("yyyyMMdd_hhmmss");
        String filename = "assinaturas-" + dateFormat.format(new Date(SystemTime.getSystemTime())) + ".zip";
        resp.setHeader("Content-Disposition", String.format("attachment; filename=%s", filename));
    }

    /**
     * Preenche o Header de resposta com os dados de saída do Assinador quando a resposta é um arquivo
     * @param req A requisição HTTP
     * @param resp A resposta HTTP
     * @param filename O nome do arquivo
     */
    public static void turnOnPreamble(HttpServletRequest req, HttpServletResponse resp, String filename){
        try {
            req.setCharacterEncoding("UTF-8");
        } catch (UnsupportedEncodingException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        resp.setContentType("application/octet-stream");
        resp.setHeader("Content-Disposition", String.format("attachment; filename=%s", filename));
    }

    /**
     * Retorna a lista de partes da requisição HTTP
     * @param req A requisição HTTP
     * @return A lista de partes da requisição
     */
    public static List<Part> getPartsFromRequest(HttpServletRequest req) {
        try {
            return req.getParts().stream().filter(
                    part -> "file_tbs".equals(part.getName()) && part.getSize() > 0).collect(Collectors.toList());
        } catch (IOException | ServletException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        return null;
    }

    /**
     * Retorna o algoritmo utilizado para a assinatura
     * @param frontpageIdentifier Dados da assinatura
     * @return O algoritmo utilizado para a assinatura ou 'Sha256withRSA' caso o algoritmo esteja vazio
     */
    private static String resolveSignatureSuite(FrontpageIdentifier frontpageIdentifier) {
        String signatureSuite = frontpageIdentifier.getSignatureSuite();
        if (signatureSuite.isEmpty()) {
            signatureSuite = "Sha256withRSA";
        }
        return signatureSuite;
    }

    /**
     * Retorna a versão do Assinador
     * @return A versão do Assinador
     */
    public static String getVersion() {
        return Constants.SOFTWARE_VERSION;
    }

    /**
     * Replaces the "https://" from a given URL. Without his operation,
     * the signature state of a URL will be said as "Indeterminate".
     */
    public static String makeFileNameForXML(String xmlUrl, String fileFormat) {
        xmlUrl = xmlUrl.replaceAll("https://", "");
        xmlUrl = xmlUrl.replaceAll("/", "_");
        return xmlUrl + fileFormat;
    }

    /**
     * @return A Key Store that has been initialized.
     */
    public static KeyStore keyStoreInitializer() {
        try {
            return KeyStore.getInstance("PKCS12");
        } catch (KeyStoreException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
        return null;
    }

    /**
     * Preenche o {@link KeyStore} dado com as informações dadas
     * @param ks {@link KeyStore} a ser preenchido
     * @param p12InputStream O P12 que contém os dados do assinante
     * @param password A senha do P12
     * @throws IOException Exceção em caso de erro na leitura do P12
     */
    public static void loadKeyStore(KeyStore ks, InputStream p12InputStream, char[] password) throws IOException {
        try {
            ks.load(p12InputStream, password);
        } catch (CertificateException | NoSuchAlgorithmException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
    }

    /**
     * Puts the next file, already signed, to be zipped inside a list of .zip files.
     * @param zipOut The output stream responsible for zipping all the wanted-to-be-
     *               -signed files together in a single .zip file, which will
     *               be returned to the user.
     */
    public static void addToZip(ZipOutputStream zipOut, String fileName) {
        ZipEntry ze = new ZipEntry(fileName);
        try {
            zipOut.putNextEntry(ze);
        } catch (IOException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
    }

    /**
     * As we are handling an OutputStream object, we must ensure it is closed properly after its use.
     * @param zipOut         The
     * @param signatureBytes A container that holds the signature inside it. We must encode it and
     *                       write it to our ZipOutputStream object.
     * @throws IOException   Thrown if we are not capable of close the given ZipOutputStream object.
     */
    public static void closeZip(ZipOutputStream zipOut, byte[] signatureBytes) throws IOException {
        zipOut.write(signatureBytes);
        zipOut.closeEntry();
    }

    /**
     * Adiciona a nova entrada ao {@link ZipOutputStream} e fecha o objeto {@link OutputStream}
     * @param zipOut Estrutura que mapeia o nome do arquivo ao seus bytes
     * @param fileName O nome do arquivo ao qual os bytes pertencem
     * @param signatureBytes Os bytes a serem adicionados
     */
    public static void prepareToClose(ZipOutputStream zipOut,
                                      String fileName,
                                      byte[] signatureBytes) {
        addToZip(zipOut, fileName);
        try {
            closeZip(zipOut, signatureBytes);
        } catch (IOException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
    }

    /**
     * We need to get the file name, so we can return the signature to the user
     * with the same file name plus the signature extension
     * @param part To be signed file, uploaded using a form
     * @return     File name, as saved in the user computer
     */
    public static String getFileName(Part part) {
       String submittedFileName = part.getSubmittedFileName();
       if (submittedFileName != null) {
           String filename = Paths.get(part.getSubmittedFileName()).getFileName().toString();
           return replaceFileExtension(filename);
       }
       return null;
    }

    /**
     * Remove a extensão do nome do arquivo a ser assinado
     * @param fileWithExtension O nome do arquivo com extensão
     * @return O nome do arquivo sem extensão
     */
    public static String replaceFileExtension(String fileWithExtension) {
        String forReplacingFileExtension = "/\\.[^.]*$/";
        return fileWithExtension.replace(forReplacingFileExtension, "");
    }

    /**
     * Retorna a extensão de arquivo relacionada com o tipo de assinatura
     * @param sigPol A política da assinatura
     * @return A extensão de arquivo
     */
    public static String fileExtension(SignerType sigPol) {
        switch (sigPol) {
            case CMS:
            case CAdES:
                return "_assinado.p7s";
            case XML:
            case XAdES:
                return "_assinado.xml";
            default: // PDF e PAdES
                return "_assinado.pdf";
        }
    }

    public abstract static class ErrorHandler {
        protected Exception error;

        public void setError(Exception error) {
            this.error = error;
        }

        public boolean hasError() {
            return error != null;
        }

        public abstract void handleError();
    }

    public static class ServletSignatureErrorHandler extends ErrorHandler {
        public boolean isCertPathError() {
            return error instanceof CertificationPathException;
        }

        public boolean isMalformedFileError() {
            return error instanceof SignerException
            && error.getMessage().contains(SignerException.MALFORMED_TBS_FILE);
        }

        @Override
        public void handleError() { }
    }

    public static class ServletAlgorithmErrorHandler extends ErrorHandler {

        @Override
        public void handleError() { }
    }
}
