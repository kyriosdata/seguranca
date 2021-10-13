/*

Desenvolvido pelo Laboratório de Segurança em Computação (LabSEC) do Departamento de Informática e Estatística (INE),
da Universidade Federal de Santa Catarina (UFSC).

Apoio: Colégio Notarial do Brasil (CNB) e Instituto Nacional de Tecnologia da Informação (ITI).

 */

package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.io.OutputStream;
import java.security.Security;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1TaggedObject;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.CMSProcessableFile;
import org.bouncycastle.cms.CMSSignedData;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.CadesSignatureException;
import br.ufsc.labsec.signature.conformanceVerifier.cades.exceptions.SignatureModeException;
import br.ufsc.labsec.signature.exceptions.EncodingException;
import br.ufsc.labsec.signature.exceptions.PbadException;

/**
 * Esta classe representa o contêiner de assinaturas que estão dentro do {@link CMSSignedData}.
 * Implementa {@link SignatureContainer} e {@link CmsParent}.
 */
public class CadesSignatureContainer implements SignatureContainer, CmsParent {

    /**
     * Bytes da assinatura
     */
    private byte[] signatureBytes;
    /**
     * O arquivo assinado
     */
    protected CMSSignedData cmsSignedData;
    /**
     * O conteúdo assinado
     */
    protected byte[] contentToBeSigned;

    /**
     * Instancia o {@link SignatureContainer} a partir de um
     * {@link CMSSignedData} e do conteúdo assinado.
     * @param signatureBytes Bytes da assinatura
     * @param contentToBeSigned O conteúdo assinado
     * @throws CadesSignatureException Exceção em caso de erro na criação do contêiner
     */
    public CadesSignatureContainer(byte[] signatureBytes, byte[] contentToBeSigned) throws CadesSignatureException {
    	Security.addProvider(new BouncyCastleProvider());
        try {
            this.cmsSignedData = new CMSSignedData(signatureBytes);
        } catch (CMSException cmsException) {
            throw new CadesSignatureException("Erro ao decodificar assinatura", cmsException);
        }
        this.contentToBeSigned = contentToBeSigned;
    }

    /**
     * Instancia o {@link SignatureContainer} a partir de um
     * {@link CMSSignedData}.
     * @param cmsSignedData Representa o contêiner de assinaturas
     */
    public CadesSignatureContainer(CMSSignedData cmsSignedData) {
        this.cmsSignedData = cmsSignedData;
    }

    /**
     * Instancia o {@link SignatureContainer} a partir dos bytes da assinatura
     * com o conteúdo anexado.
     * @param signatureBytes Bytes do arquivo da assinatura
     * @throws CadesSignatureException Exceção em caso de erro na criação do contêiner
     * @throws EncodingException Exceção em caso de erro nos bytes da assinatura
     */
    public CadesSignatureContainer(byte[] signatureBytes) throws CadesSignatureException, EncodingException {
        try {
            this.cmsSignedData = new CMSSignedData(signatureBytes);
        } catch (CMSException cmsException) {
            throw new CadesSignatureException("Erro ao decodificar assinatura", cmsException);
        }
        if (this.hasDetachedContent()) {
            this.signatureBytes = signatureBytes;
        }
    }

    /**
     * Verifica se o arquivo possui assinatura com conteúdo destacado
     * @return Indica se o arquivo possui conteúdo destacado
     */
    @Override
    public boolean hasDetachedContent() throws EncodingException {
        try {
            ASN1Sequence contentInfoSeq = (ASN1Sequence) ASN1Sequence.fromByteArray(this.cmsSignedData.getEncoded());
            ASN1TaggedObject berTaggedObj = (ASN1TaggedObject) contentInfoSeq.getObjectAt(1);
            ASN1Sequence signedDataSeq = (ASN1Sequence) berTaggedObj.getObject();
            ASN1Sequence encapContent = (ASN1Sequence) signedDataSeq.getObjectAt(2);
            return encapContent.size() == 1;
        } catch (IOException ioException) {
            throw new EncodingException("Falha na codificação do CMSSignedData passado por parâmetro", ioException);
        }
    }

    /**
     * Retorna a assinatura no índice dado
     * @param index O índice da assinatura
     * @return A assinatura do índice dado
     */
    public CadesSignature getSignatureAt(int index) throws EncodingException {
        CadesSignature cadesSignature = null;
        if (this.getSignatureCount() > index) {
            SignerInformation signerInformation = null;
            Iterator<SignerInformation> iterator = this.cmsSignedData.getSignerInfos().getSigners().iterator();
            for (int i = 0; i <= index; i++) {
                signerInformation = iterator.next();
            }
            cadesSignature = new CadesSignature(this, signerInformation, this);
        }
        return cadesSignature;
    }

    /**
     * Retorna a quantidade de assinaturas no arquivo, desconsiderando contra-assinaturas
     * @return A quantidade de assinaturas no arquivo
     */
    @Override
    public int getSignatureCount() {
        int size = this.cmsSignedData.getSignerInfos().getSigners().size();
        return size;
    }

    /**
     * Obtém os bytes do conteúdo assinado
     * @return Os bytes do conteúdo assinado.
     */
    public byte[] getSignedContent() {
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        try {
            this.cmsSignedData.getSignedContent().write(output);
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CMSException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return output.toByteArray();
    }

    /**
     * Adiciona um novo assinante ao contêiner.
     * @param signature Assinatura no formato CAdES
     * @throws CadesSignatureException
     */
    public void addSignature(CadesSignature signature) throws CadesSignatureException {
        if (!(signature instanceof CadesSignature))
            throw new CadesSignatureException("Assinatura incompatível com formato CMS");
        CadesSignature cadesSignature = (CadesSignature) signature;
        cadesSignature.setParent(this);
        SignerInformation signerInformation = cadesSignature.getSignerInformation();
        Collection<SignerInformation> signersCollection = this.cmsSignedData.getSignerInfos().getSigners();
        signersCollection.add(signerInformation);
        SignerInformationStore signerInfoStore = new SignerInformationStore(signersCollection);
        this.cmsSignedData = CMSSignedData.replaceSigners(this.cmsSignedData, signerInfoStore);
    }

    /**
     * Escreve a assinatura, já codificada para seu formato, no
     * {@link OutputStream} desejado
     * @param outputStream O stream que conterá a assinatura
     * @throws EncodingException Exceção em caso de erro na transformação
     */
    @Override
    public void encode(OutputStream outputStream) throws EncodingException {
        try {
            byte[] cms = this.cmsSignedData.getEncoded();
            outputStream.write(cms);
            outputStream.close();
        } catch (IOException ioException) {
            throw new EncodingException(ioException);
        }
    }

    /**
     * Retorna o conteúdo do contêiner codificado em bytes
     * @return Os bytes do conteúdo do contêiner
     * @throws EncodingException Exceção em caso de erro na transformação
     */
    @Override
    public byte[] getBytes() throws EncodingException {
        try {
            return this.cmsSignedData.getEncoded();
        } catch (IOException ioException) {
            throw new EncodingException(ioException);
        }
    }

    /**
     * Obtém o valor do campo eContentType.
     * @return O tipo do conteúdo assinado
     */
    public String getEContentType() {
        return this.cmsSignedData.getSignedContentTypeOID();
    }

    /**
     * Define qual foi o conteúdo assinado que será usado na verificação da
     * assinatura.
     * @param signedContent O arquivo que contém o
     *            conteúdo que foi assinado
     * @throws PbadException Exceção em caso de erro ao decodificar a assinatura
     */
    public void setSignedContent(File signedContent) throws PbadException {
        try {
            this.cmsSignedData = new CMSSignedData(new CMSProcessableFile(signedContent), this.signatureBytes);
        } catch (CMSException cmsException) {
            throw new CadesSignatureException("Erro ao decodificar assinatura", cmsException);
        }
    }

    /**
     * Define qual foi o conteúdo assinado que será usado na verificação da
     * assinatura.
     * @param signedContent Bytes do conteúdo que foi assinado
     * @throws PbadException Exceção em caso de erro ao decodificar a assinatura
     */
    public void setSignedContent(byte[] signedContent) throws PbadException {
        try {
            this.cmsSignedData = new CMSSignedData(new CMSProcessableByteArray(signedContent), this.signatureBytes);
        } catch (CMSException cmsException) {
            throw new CadesSignatureException("Erro ao decodificar assinatura", cmsException);
        }
    }

    /**
     * Substitui o primeiro assinante que tiver o mesmo identificador do
     * assinante passado como parâmetro.
     * @param signerToReplace O assinante a ser substituído
     */
    public void replaceChildSignature(SignerInformation signerToReplace) {
        ArrayList<SignerInformation> signers = new ArrayList<SignerInformation>(this.cmsSignedData.getSignerInfos().getSigners());
        int i = 0;
        boolean replaced = false;
        // substitui primeiro SignerInformation que tiver o mesmo id do novo
        // SignerInformation (obs: mantem a ordem dos
        // assinantes)
        while (i < signers.size() && !replaced) {
            if (signers.get(i).getSID().equals(signerToReplace.getSID())) {
                // faz substituicao
                signers.set(i, signerToReplace);
                replaced = true;
            }
            i++;
        }
        this.cmsSignedData = CMSSignedData.replaceSigners(this.cmsSignedData, new SignerInformationStore(signers));
    }

    /**
     * Obtém o modo de assinatura
     * @param index O índice da assinatura dentro do contêiner
     * @return O modo da assinatura no índice dado
     */
    @Override
	public SignatureModeCAdES getMode(Integer index) throws SignatureModeException, EncodingException {
        return this.getSignatureAt(index).getMode();
    }

    @Override
    /**
     * Retorna uma representação do contêiner de assinaturas.
     * @return O objeto {@link CMSSignedData}
     */
    public CMSSignedData getSignedData() {
        return this.cmsSignedData;
    }

    /**
     * Retorna os bytes do conteúdo assinado
     * @return Os bytes do conteúdo assinado
     */
    @Override
    public byte[] getContentToBeSigned() {
        return this.contentToBeSigned;
    }

    /**
     * Retorna o contêiner de assinatura
     * @return O contêiner de assinatura
     */
    @Override
    public SignatureContainer getContainer() {
        return this;
    }

    /**
     * Retorna as assinaturas no arquivo
     * @return As assinaturas no arquivo
     */
    public List<CadesSignature> getSignatures() throws EncodingException {
        ArrayList<CadesSignature> listOfSignatures = new ArrayList<CadesSignature>();
        for (int i = 0; i < getSignatureCount(); i++) {
            listOfSignatures.add(getSignatureAt(i));
        }
        return listOfSignatures;
    }
}
