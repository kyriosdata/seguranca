package br.ufsc.labsec.signature.conformanceVerifier.pades;

import br.ufsc.labsec.signature.tsa.TimeStamp;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.SigningCertificateInterface;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificate;
import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.signed.IdAaSigningCertificateV2;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.ValidationDataService;
import br.ufsc.labsec.signature.exceptions.AIAException;
import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.SignatureInterface;
import org.bouncycastle.asn1.cms.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.tsp.TSPException;
import org.bouncycastle.tsp.TimeStampResponse;
import org.bouncycastle.util.Store;
import java.io.IOException;
import java.io.InputStream;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * Esta classe adiciona um TimeStamp à uma assinatura PAdES.
 */
public class PadesTimeStampSignatureImp implements SignatureInterface {

    /**
     * Carimbo de tempo
     */
    private final TimeStamp timeStamp;

    /**
     * Resumo criptográfico do carimbo
     */
    private final byte[] digest;

    /**
     * Assinador PAdES
     */
    private final PadesSigner parent;

    /**
     * Construtor
     * @param timeStamp Carimbo de tempo
     * @param bytes Bytes do carimbo de tempo
     * @param parent Assinador PAdES
     */
    public PadesTimeStampSignatureImp(TimeStamp timeStamp, byte[] bytes, PadesSigner parent, String algorithm) {
        this.timeStamp = timeStamp;
        this.digest = doHash(bytes, algorithm);
        this.parent = parent;
    }

    /**
     * Constrói um carimbo de tempo
     * @param content Stream do conteúdo do carimbo
     * @return Os bytes do carimbo criado
     * @throws IOException Exceção em caso de erro na criação do carimbo
     */
    @Override
    public byte[] sign(InputStream content) throws
            IOException {

        byte[] bytes = null;
        try {

            byte[] timeStamp = this.timeStamp.getTimeStamp(digest);
            TimeStampResponse response = new TimeStampResponse(timeStamp);
            byte[] toAddAttribute = response.getTimeStampToken().getEncoded();

            X509Certificate certificate = getCertificatesFromTS(response);

            assert certificate != null;
            List<X509Certificate> certificates = ValidationDataService.downloadCertChainFromAia(certificate);
            CadesSignatureComponent cadesComponent = this.parent.getPadesComponent().getCadesSignatureComponent();
            cadesComponent.getSignatureIdentityInformation().addCertificates(certificates);

            bytes = toAddAttribute;

        } catch (TSPException | AIAException e) {
            e.printStackTrace();
        }

        return bytes;
    }

    /**
     * Retorna o certificado do assinante do carimbo de tempo
     * @param response O carimbo de tempo
     * @return O certificado do assinante do carimbo ou nulo caso não seja possível
     * identificar o certificado
     */
    private X509Certificate getCertificatesFromTS(TimeStampResponse response) {
        CMSSignedData cms = response.getTimeStampToken().toCMSSignedData();
        Collection<SignerInformation> signersInfo = cms.getSignerInfos().getSigners();
        if (signersInfo.size() == 0) {
            return null;
        }

        for (SignerInformation signerInformation : signersInfo) {
            Attribute attr;
            SigningCertificateInterface sigCert = null;

            try {
                attr = signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificate);
                if (attr != null) {
                    sigCert = new IdAaSigningCertificate(attr);
                } else {
                    attr = signerInformation.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_signingCertificateV2);
                    sigCert = new IdAaSigningCertificateV2(attr);
                }
            } catch (SignatureAttributeException e) {
                e.printStackTrace();
            }
            Store certStore = cms.getCertificates();

            ArrayList<X509CertificateHolder> certificateHolders = (ArrayList<X509CertificateHolder>) certStore.getMatches(null);
            for (X509CertificateHolder certificate : certificateHolders) {

                try {
                    X509Certificate toCompare = new JcaX509CertificateConverter().getCertificate(certificate);
                    if (sigCert.match(toCompare)) {
                        return toCompare;
                    }
                } catch (CertificateException e) {
                    e.printStackTrace();
                }
            }

        }
        return null;
    }

    /**
     * Calcula o resumo criptográfico dos bytes dados com o algoritmo especificado
     * @param arg Os bytes cujo resumo será calculado
     * @param algorithm O algoritmo utilizado para o cálculo
     * @return O resumo criptográfico dos bytes ou nulo em caso de erro no cálculo
     */
    private byte[] doHash(byte[] arg, String algorithm) {

        MessageDigest messageDigest;
        try {
            messageDigest = MessageDigest.getInstance(algorithm);
            messageDigest.update(arg);
            return messageDigest.digest();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return null;

    }

}