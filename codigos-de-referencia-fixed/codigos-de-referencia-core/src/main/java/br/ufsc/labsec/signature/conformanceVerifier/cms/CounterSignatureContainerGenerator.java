package br.ufsc.labsec.signature.conformanceVerifier.cms;

import br.ufsc.labsec.signature.conformanceVerifier.cades.attributes.unsigned.IdAaEtsArchiveTimeStampV2;
import br.ufsc.labsec.signature.signer.exceptions.CmsSignerException;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cms.*;
import org.bouncycastle.util.Store;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.PrivateKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

/**
 * Esta classe gera contêineres para contra-assinaturas no formato CMS.
 */
public class CounterSignatureContainerGenerator extends SignatureContainerGenerator {

    /**
     * O conteúdo assinado
     */
    private CMSSignedData signedData;

    /**
     * Inicia um gerador de contêineres de assinaturas.
     * @param cmsSignatureComponent Componente de assinatura CMS
     * @param target Arquivo assinado
     */
    public CounterSignatureContainerGenerator(CmsSignatureComponent cmsSignatureComponent, InputStream target) {
        super(cmsSignatureComponent, target);
    }

    /**
     * Constrói um objeto {@link Store} com o certificado dado
     * @param cert O certificado
     * @return Um objeto {@link Store}
     * @throws CertificateEncodingException Exceção no caso de erro na criação do {@link Store}
     */
    @Override
    public Store getCertificateStore(X509Certificate cert) throws CertificateEncodingException {

        List<Certificate> result = new ArrayList<>();
        Store<?> certStore = signedData.getCertificates();
        SignerInformationStore signers = signedData.getSignerInfos();
        Iterator<SignerInformation> it = signers.getSigners().iterator();
        try {
            result.add(new JcaX509CertificateConverter().getCertificate(new X509CertificateHolder(cert.getEncoded())));
        } catch (IOException | CertificateException e) {

        }
        while (it.hasNext()) {
            SignerInformation signer = it.next();
            Collection<?> certCollection = certStore.getMatches(signer.getSID());
            Iterator<?> certIt = certCollection.iterator();
            X509CertificateHolder certificateHolder = (X509CertificateHolder) certIt.next();
            try {
                result.add(new JcaX509CertificateConverter().getCertificate(certificateHolder));
            } catch (CertificateException e) {
                // Ignore and continue
            }
        }
        return buildCertStore(result);
    }

    /**
     * Gera o contêiner de contra-assinatura CMS
     * @param in O documento assinado
     * @param pvKey Chave privada
     * @param cert Certificado do assinante
     * @return O contêiner de assinatura CMS
     * @throws CertificateEncodingException Exceção em caso de problema com o certificado
     * @throws CMSException Exceção em caso de erro de processamento da assinatura CMS
     * @throws IOException Exceção em caso de problema com o {@link InputStream}
     */
    @Override
    public CmsSignatureContainer generate(InputStream in, PrivateKey pvKey, X509Certificate cert)
            throws CertificateEncodingException, CMSException, IOException {
        try {
            signedData = new CMSSignedData(in);
            Collection<SignerInformation> signers = signedData.getSignerInfos().getSigners();
            for (SignerInformation signer : signers) {
                boolean hasArchiveTimestamp = signer.getUnsignedAttributes()
                        .get(new ASN1ObjectIdentifier(IdAaEtsArchiveTimeStampV2.IDENTIFIER)) != null;
                if (hasArchiveTimestamp) {
                    throw new CmsSignerException("Carimbo de tempo de arquivamento impede assinar uma contra-assinatura");
                }
                byte[] signatureFromSigner = signer.getSignature();
                CMSSignedData cmsCounterSignatureSignedData =
                        super.generate(new ByteArrayInputStream(signatureFromSigner), pvKey, cert).getCmsSignedData();
                signedData = updateSignedDataWithCounterSignature(cmsCounterSignatureSignedData, signedData, signer.getSID());
            }
            return new CmsSignatureContainer(signedData, null);
        } finally {
            System.out.println(" ");
        }
    }

    /**
     * Modifica o conteúdo da assinatura
     * @param counterSignature O conteúdo da contra-assinatura
     * @param originalSignature O conteúdo da assinatura contra-assinada
     * @param selector Identificador do assinador
     * @return O novo conteúdo contra-assinado atualizado
     */
    public CMSSignedData updateSignedDataWithCounterSignature(final CMSSignedData counterSignature, final CMSSignedData originalSignature,
                                                              SignerId selector) {
        // Retrive the SignerInformation from the countersigned signature
        SignerInformationStore originaSignerInformation = originalSignature.getSignerInfos();
        // Retrive the SignerInformation from the counterSignature
        SignerInformationStore signerInformation = counterSignature.getSignerInfos();

        // Add counterSignature
        SignerInformation si = originaSignerInformation.get(selector);
        SignerInformation updatedSi = SignerInformation.addCounterSigners(si, signerInformation);

        // Create updated SignerInformationStore
        Collection<SignerInformation> informationCollection = new ArrayList<SignerInformation>();
        informationCollection.add(updatedSi);
        SignerInformationStore signerInformationStore = new SignerInformationStore(informationCollection);

        CMSSignedData signedData = CMSSignedData.replaceSigners(originalSignature, signerInformationStore);
        try {
            signedData = CMSSignedData.replaceCertificatesAndCRLs(signedData, counterSignature.getCertificates(), originalSignature.getAttributeCertificates(), originalSignature.getCRLs());
            return signedData;
        } catch (CMSException e) {
            return null;
        }
    }

    /**
     * Cria um objeto {@link CMSSignedData} a partir do conteúdo do stream dado
     * @param generator Gerador de {@link CMSSignedData}
     * @param in Stream com o conteúdo
     * @return O objeto {@link CMSSignedData} gerado
     * @throws CMSException Exceção em caso de erro na geração do conteúdo
     * @throws IOException Exceção em caso de erro no conteúdo do stream
     */
    @Override
    protected CMSSignedData cmsSignedDataFromGenerator(CMSSignedDataGenerator generator, InputStream in) throws CMSException, IOException {
        byte[] bytes = IOUtils.toByteArray(in);
        return generator.generate(new CMSProcessableByteArray(null, bytes));
    }
}
