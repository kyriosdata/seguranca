package br.ufsc.labsec.signature.signer.signatureSwitch;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.SignatureDataWrapper;
import br.ufsc.labsec.signature.Signer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignerException;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CmsSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CmsSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.cms.SignatureContainerGenerator;
import br.ufsc.labsec.signature.conformanceVerifier.cms.CounterSignatureContainerGenerator;
import br.ufsc.labsec.signature.conformanceVerifier.validationService.CertificationPathException;
import br.ufsc.labsec.signature.signer.FileFormat;
import br.ufsc.labsec.signature.signer.SignerType;
import br.ufsc.labsec.signature.signer.exceptions.CmsSignerException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;

import java.io.*;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;

/**
 * Esta classe gera assinaturas no formado CMS.
 */
public class CmsSigner extends SignatureDataWrapperGenerator implements Signer {

    /**
     * Chave privada do assinante
     */
    private PrivateKey pvKey;
    /**
     * Certificado do assinante
     */
    private X509Certificate cert;
    /**
     * O arquivo a ser assinado
     */
    private InputStream target;
    /**
     * Política a ser utilizada na assinatura
     */
    private String policyOid;
    /**
     * Modo da assinatura
     */
    private FileFormat format;
    /**
     * Suite da assinatura
     */
    private String suite;
    /**
     * Componente de assinatura CMS
     */
    private CmsSignatureComponent cmsSignatureComponent;
    /**
     * Gerador de contêineres de assinaturas CMS
     */
    private SignatureContainerGenerator cmsContainerGenerator;
    /**
     * Contêiner de assinatura CMS
     */
    private CmsSignatureContainer container;

    /**
     * Construtor
     * @param cmsSignatureComponent Componente de assinatura CMS
     */
    public CmsSigner(CmsSignatureComponent cmsSignatureComponent) {
        this.cmsSignatureComponent = cmsSignatureComponent;
    }

    /**
     * Atribue os valores de chave privada e certificado do assinante para a realização da assinatura
     * @param keyStore {@link KeyStore} que contém as informações do assinante
     * @param password Senha do {@link KeyStore}
     */
    public void selectInformation(KeyStore keyStore, String password) {
        String alias = SwitchHelper.getAlias(keyStore);
        this.pvKey = SwitchHelper.getPrivateKey(keyStore, alias, password.toCharArray());
        this.cert = SwitchHelper.getCertificate(keyStore, alias);
    }

    /**
     * Realiza a assinatura sobre o arquivo dado
     * @param filename Caminho do arquivo a ser assinado
     * @param target O arquivo a ser assinado
     * @param policyId Política a ser utilizada na assinatura
     * @return O arquivo assinado
     */
    @Override
    public SignatureDataWrapper getSignature(String filename, InputStream target, SignerType policyId) {
        selectTarget(target, policyId.toString());
        if (cmsContainerGenerator != null) {
            cmsContainerGenerator.setMode(format.toString());
            cmsContainerGenerator.setSignatureSuite(suite);
            sign();
            InputStream stream = getSignatureStream();
            SignatureDataWrapper signature;
            if (format.equals(FileFormat.DETACHED)) {
                signature = new SignatureDataWrapper(target, stream, filename);
            } else {
                signature = new SignatureDataWrapper(stream, null, filename);
            }
            return signature;
        }
        return null;
    }

    /**
     * The method SignatureContainerGenerator.generate() was duplicated and changed
     * to attend to our needs. We give it the .p12 input stream, the user's private key,
     * the user's certificate and a flag to check if we do need to save the signature
     * in a different file from the given in the .jsp.
     */
    public void createCmsContainerGenerator() {
        try {
            try {
                CMSSignedData signedData = new CMSSignedData(target);
                SignerInformation signerInfo = signedData.getSignerInfos().iterator().next();
                boolean noPolicy =
                        signerInfo.getUnsignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId) == null &&
                                signerInfo.getSignedAttributes().get(PKCSObjectIdentifiers.id_aa_ets_sigPolicyId) == null;
                if (!noPolicy) {
                    throw new CmsSignerException("arquivo TBS assinado com politica");
                }
                cmsContainerGenerator = new CounterSignatureContainerGenerator(cmsSignatureComponent, target);
            } catch (CMSException e) {
                cmsContainerGenerator = new SignatureContainerGenerator(cmsSignatureComponent, target);
            } finally {
                target.reset();
            }
        } catch (IOException e) {
            Application.logger.log(Level.WARNING, e.getMessage(), e);
        }
    }

    /**
     * Inicializa o gerador de contêiner de assinatura
     * @param target  Endereço do arquivo a ser assinado
     * @param policyOid OID da política de assinatura usada
     */
    @Override
    public void selectTarget(String target, String policyOid) {
        try {
            this.selectTarget(new FileInputStream(target), policyOid);
        } catch (FileNotFoundException e) {
            Application.logger.log(Level.SEVERE, "Arquivo não encontrado.", e);
        }
    }

    /**
     * Inicializa o gerador de contêiner de assinatura
     * @param target O arquivo que será assinado
     * @param policyOid OID da política de assinatura utilizada
     */
    @Override
    public void selectTarget(InputStream target, String policyOid) {
        this.target = target;
        this.policyOid = policyOid;
        createCmsContainerGenerator();
    }

    /**
     * Realiza a assinatura
     * @return Indica se o processo de assinatura foi concluído com sucesso
     */
    @Override
    public boolean sign() {
        if (this.cmsContainerGenerator != null) {
            try {
                this.container = cmsContainerGenerator.generate(target, pvKey, cert);
            } catch (CertificateEncodingException | CMSException | IOException e) {
                Application.logger.log(Level.SEVERE, "Não foi possível gerar a assinatura CMS.", e);
            }
            return this.container != null;
        }
        return false;
    }

    /**
     * Salva a assinatura gerada
     * @return Indica se a assinatura foi salva com sucesso
     */
    @Override
    public boolean save() {
        Application.logger.log(Level.SEVERE, "Não foi possível salvar a assinatura");
        return false;
    }

    /**
     * Atribue o tipo de assinatura, anexada ou destacada
     * @param mode O tipo da assinatura
     */
    @Override
    public void setMode(FileFormat mode, String suite) {
        this.format = mode;
        this.suite = suite;
    }

    /**
     * Retorna o tipo da assinatura
     * @return O tipo da assinatura
     */
    public String getName() {
        return "CMS";
    }

    /**
     * Retorna o arquivo assinado
     * @return O {@link InputStream} do arquivo assinado
     */
    @Override
    public InputStream getSignatureStream() {
        return this.container.getStream();
    }

    /**
     * Adiciona um atributo à assinatura
     * @param attribute O atributo a ser selecionado
     */
    @Override
    public void selectAttribute(String attribute) {
        // TODO Auto-generated method stub
    }

    /**
     * Remove um atributo da assinatura
     * @param attribute O atributo a ser removido
     */
    @Override
    public void unselectAttribute(String attribute) {
        // TODO Auto-generated method stub
    }

    /**
     * Retorna a lista de atributos disponíveis da assinatura
     * @return A lista de atributos disponíveis da assinatura
     */
    @Override
    public List<String> getAttributesAvailable() {
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * Retorna a lista dos tipos de assinatura disponíveis
     * @return Lista dos tipos de assinatura disponíveis
     */
    @Override
    public List<String> getAvailableModes() {
        return this.cmsContainerGenerator.getModes();
    }

    /**
     * Retorna a lista de atributos assinados obrigatórios da assinatura
     * @return A lista de atributos assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedSignedAttributeList() {
        return new ArrayList<String>();
    }

    /**
     * Retorna a lista de atributos assinados disponíveis para a assinatura
     * @return A lista de atributos assinados disponíveis para a assinatura
     */
    @Override
    public List<String> getSignedAttributesAvailable() {
        return new ArrayList<String>();
    }

    /**
     * Retorna a lista de atributos não-assinados disponíveis para a assinatura
     * @return A lista de atributos não-assinados disponíveis para a assinatura
     */
    @Override
    public List<String> getUnsignedAttributesAvailable() {
        return new ArrayList<String>();
    }

    /**
     * Retorna a lista de políticas de assinatura disponiveis
     * @return A lista de políticas de assinatura
     */
    @Override
    public List<String> getPoliciesAvailable() {
        List<String> polices = new ArrayList<String>();
        polices.add("CMS");
        return polices;
    }

    /**
     * Retorna a lista de atributos não assinados obrigatórios da assinatura
     * @return A lista de atributos não assinados obrigatórios da assinatura
     */
    @Override
    public List<String> getMandatedUnsignedAttributeList() {
        return new ArrayList<String>();
    }

    @Override
    public boolean supports(InputStream target, SignerType signerType) throws CertificationPathException, SignerException {
        return true;
    }
}
