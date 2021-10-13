package br.ufsc.labsec.signature.conformanceVerifier.pades.utils;

import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.pades.exceptions.DictionaryException;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.SignaturePolicyProxy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.PdfEntry;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.SignaturePolicy;
import br.ufsc.labsec.signature.conformanceVerifier.signaturePolicy.decoder.VriDictionary;
import org.apache.pdfbox.cos.*;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

/**
 * Esta classe é responsável pela validação do dicionário VRI.
 */
public class VRIValidator {
    public static final String VRI_NOT_FOUND_MESSAGE = "Não encontrado VRI identificado com o hash da assinatura.\n";
    /**
     * Dicionário VRI da assinatura
     */
    private final COSDictionary vri;
    /**
     * Dicionário VRI da política de assinatura
     */
    private final VriDictionary policyVRI;

    /**
     * Construtor
     * @param signatureVRI O dicionário VRI da assinatura
     * @param policyVRI  O dicionário VRI da política de assinatura
     */
    public VRIValidator(COSDictionary signatureVRI, VriDictionary policyVRI) {
        this.vri = signatureVRI;
        this.policyVRI = policyVRI;
    }

    /**
     * Valida o dicionário VRI da assinatura
     * @param verifier O Verifer de assinaturas PAdES
     * @return Lista de entradas obrigatórias que não estão presentes
     * @throws DictionaryException
     */
    public List<String> validation(PadesSignatureVerifier verifier) throws DictionaryException {
            List<String> remainingEntries = new ArrayList<>();

            if (vri == null) {
                throw new DictionaryException(VRI_NOT_FOUND_MESSAGE);
            } else {
                List<PdfEntry> policyVRIEntries = policyVRI.getSequenceOfPdfEntry();
                for (PdfEntry pdfEntry : policyVRIEntries)
                    validateEntriesAndSetValues(pdfEntry, vri, remainingEntries, verifier);
            }

            return remainingEntries;
    }

    /**
     * Valida o valor da entrada do dicionário
     * @param pdfEntry A entrada a ser validada
     * @param sigVRI O dicionário VRI da assinatura
     * @param remainingEntries Lista de entradas obrigatórias que não estão presentes
     * @param verifier O Verifer de assinaturas PAdES
     */
    private void validateEntriesAndSetValues(PdfEntry pdfEntry, COSDictionary sigVRI, List<String> remainingEntries,
                                             PadesSignatureVerifier verifier) {
        if (pdfEntry.getPdfEntryID().equals(VRIEntries.Type.name()))
            addRemainingEntry(remainingEntries, VRIEntries.Type);

        if (pdfEntry.getPdfEntryID().equals(VRIEntries.Cert.name())) {
            if (!addRemainingEntry(remainingEntries, VRIEntries.Cert))
                setCerts(verifier);
            else
                remainingEntries.add("Cert(s)");
        }

        if (pdfEntry.getPdfEntryID().equals("ValidationValues")) {
            this.validateValidationValuesEntries(remainingEntries, pdfEntry, verifier);
        }

        String lpaArtifactAttr = VRIEntries.PBAD_LpaArtifact.name();
        if (pdfEntry.getPdfEntryID().equals(lpaArtifactAttr) && !sigVRI.containsKey(lpaArtifactAttr)) {
            remainingEntries.add(lpaArtifactAttr);
        }

        String lpaSignatureAttr = VRIEntries.PBAD_LpaSignature.name();
        if (pdfEntry.getPdfEntryID().equals(lpaSignatureAttr) && !sigVRI.containsKey(lpaSignatureAttr)) {
            remainingEntries.add(lpaSignatureAttr);
        }

        String policyArtifactAttr = VRIEntries.PBAD_PolicyArtifact.name();
        if (pdfEntry.getPdfEntryID().equals(policyArtifactAttr) && !sigVRI.containsKey(policyArtifactAttr)) {
            remainingEntries.add(policyArtifactAttr);
        }
    }

    /**
     * Verifica os valores de uma entrada 'ValidationValues'
     * @param remainingEntries Lista de entradas obrigatórias no dicionário
     * @param vv A entrada no dicionário cujo 'ValidationValues' será verificado
     * @param verifier O Verifer de assinaturas PAdES
     */
    private void validateValidationValuesEntries(List<String> remainingEntries, PdfEntry vv,
                                                 PadesSignatureVerifier verifier) {
        int value = DSSDecoder.getValidationValue(vv.getPdfEntryValue()).intValue();
        VRIEntries crl = VRIEntries.CRL;
        VRIEntries ocsp = VRIEntries.OCSP;
        String crlsStr = crl.name() + "s";

        switch (value) {
            case 0:
                if (!addRemainingEntry(remainingEntries, crl) && !addRemainingEntry(remainingEntries, crlsStr))
                    setCRL(verifier);
                break;
            case 1:
                if (!addRemainingEntry(remainingEntries, ocsp))
                    setOCSP(verifier);
                break;
            case 2:
                if (!(vri.containsKey(crl.name()) || vri.containsKey(crlsStr)) && !vri.containsKey(ocsp.name())) {
                    remainingEntries.add(crl + " ou " + ocsp);
                } else {
                    boolean valid2 = !vri.containsKey(VRIEntries.CRL.name()) || !vri.containsKey( crlsStr);
                    if (valid2)
                        setCRL(verifier);
                    else
                        remainingEntries.add(crl.name() + "(s)");

                    if (vri.containsKey(ocsp.name()))
                        setOCSP(verifier);
                    else if (!valid2)
                        remainingEntries.add(ocsp.name());
                }
                break;
            case 3:
                if (!(addRemainingEntry(remainingEntries, crl) || addRemainingEntry(remainingEntries, crlsStr))
                        && !addRemainingEntry(remainingEntries, ocsp)) {
                    setCRL(verifier);
                    setOCSP(verifier);
                }
                break;
        }
    }

    /**
     * Atualiza o componentes CAdES com as informações de CRLs do VRI
     * @param verifier O Verifer de assinaturas PAdES
     */
    private void setCRL(PadesSignatureVerifier verifier) {
        COSArray crls = (COSArray) vri.getDictionaryObject(VRIEntries.CRL.name());
        if (crls == null)
            crls = (COSArray) vri.getDictionaryObject("CRLs");
        List<X509CRL> crlList = new ArrayList<>();

        for (COSBase crl1 : crls) {
            COSObject crlIndirectStream = (COSObject) crl1;
            COSStream crlStream = (COSStream) crlIndirectStream.getObject();
            byte[] crl = this.decoderGetBytes(crlStream);
            ByteArrayInputStream bis = new ByteArrayInputStream(crl);

            try {
                CertificateFactory fac = CertificateFactory.getInstance("x509");
                CRL xCrl = fac.generateCRL(bis);
                crlList.add((X509CRL) xCrl);
            } catch (CRLException | CertificateException e) {
                e.printStackTrace();
            }
        }

        CadesSignatureComponent cadesComponent = verifier.getCadesSignatureComponent();
        cadesComponent.getSignatureIdentityInformation().addCrl(null, crlList);
    }

    /**
     * Atualiza o componentes CAdES com as informações de OCSP
     * @param verifier O Verifer de assinaturas PAdES
     */
    private void setOCSP(PadesSignatureVerifier verifier) {
    }

    /**
     * Atualiza o componentes CAdES com as informações de certificados do VRI
     * @param verifier O Verifer de assinaturas PAdES
     */
    private void setCerts(PadesSignatureVerifier verifier) {
        COSArray certificates = (COSArray) vri.getDictionaryObject(VRIEntries.Cert.name());
        List<X509Certificate> certificatesList = new ArrayList<>();

        for (COSBase cosBaseCertificate : certificates) {
            COSObject certificatesIndirectStream = (COSObject) cosBaseCertificate;
            COSStream certificateStream = (COSStream) certificatesIndirectStream.getObject();
            byte[] certificate = this.decoderGetBytes(certificateStream);
            ByteArrayInputStream bis = new ByteArrayInputStream(certificate);

            try {
                CertificateFactory fac = CertificateFactory.getInstance("x509");
                Certificate xCert = fac.generateCertificate(bis);
                certificatesList.add((X509Certificate) xCert);
            } catch (CertificateException e) {
                e.printStackTrace();
            }
        }
        CadesSignatureComponent cadesComponent = verifier.getCadesSignatureComponent();
        cadesComponent.getSignatureIdentityInformation().addCertificates(certificatesList);
    }

    /**
     * Adiciona um novo elemento no dicionário do atributo
     * @param remainingEntries A lista onde o nome da entrada será adicionado
     * @param e A entrada cujo nome será adicionado à lista
     * @return Indica se o elemento foi adicionado a lista. Caso o elemento já estiver
     * presente na lista, o retorno é falso
     */
    private boolean addRemainingEntry(List<String> remainingEntries, VRIEntries e) {
        boolean added = false;
        if (!vri.containsKey(e.name())) {
            remainingEntries.add(e.name());
            added = true;
        }
        return added;
    }

    /**
     * Adiciona um novo elemento no dicionário do atributo
     * @param remainingEntries A lista onde a entrada será adicionada
     * @param e A entrada que será adicionado à lista
     * @return Indica se o elemento foi adicionado a lista. Caso o elemento já estiver
     * presente na lista, o retorno é falso
     */
    private boolean addRemainingEntry(List<String> remainingEntries, String e) {
        boolean added = false;
        if (!vri.containsKey(e)) {
            remainingEntries.add(e);
            added = true;
        }
        return added;
    }

    /**
     * Decodifica a Stream para um array de bytes
     * @param stream A stream a ser decodificada
     * @return O array de bytes de dados extraídos da Stream
     */
    private byte[] decoderGetBytes(COSStream stream) {
        return DSSDecoder.extractDataFromCOSStream(stream);
    }
}
