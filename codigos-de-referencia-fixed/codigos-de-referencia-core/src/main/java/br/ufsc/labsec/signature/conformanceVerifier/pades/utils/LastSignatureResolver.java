package br.ufsc.labsec.signature.conformanceVerifier.pades.utils;

import br.ufsc.labsec.signature.SignaturePolicyInterface;
import br.ufsc.labsec.signature.Verifier;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignature;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesSignatureContainer;
import br.ufsc.labsec.signature.conformanceVerifier.cades.CadesVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureComponent;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesSignatureVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.pades.PadesVerifier;
import br.ufsc.labsec.signature.conformanceVerifier.pades.attributes.DssAttribute;
import br.ufsc.labsec.signature.exceptions.PbadException;
import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.pdmodel.interactive.digitalsignature.PDSignature;

import java.io.IOException;
import java.util.List;

/**
 * Esta classe é responsável por identificar e lidar com a última assinatura
 * em um documento PDF assinado com política PAdES.
 */
public class LastSignatureResolver {

    /**
     * O {@link Verifier} para assinaturas PAdES
     */
    private final PadesVerifier padesVerifier;
    /**
     * A última assinatura do documento assinado
     */
    private PDSignature lastSignature;
    /**
     * O índice da assinatura na lista de assinaturas do documento
     */
    private int lastSignatureIndex;

    /**
     * Construtor
     * @param verifier O {@link Verifier} para assinaturas PAdES
     */
    public LastSignatureResolver(PadesVerifier verifier) {
        this.padesVerifier = verifier;
    }

    /**
     * Prepara o {@link Verifier} para a última assinatura da lista
     * @param signatureList A lista de assinaturas do documento assinado
     * @param pdfFile Os bytes do documento assinado
     */
    public void resolve(List<PDSignature> signatureList, byte[] pdfFile) {
        updateLastSignature(signatureList);
        resolveLastSignature(signatureList, pdfFile);
    }

    /**
     * Retorna a última assinatura
     * @return A última assinatura
     */
    public PDSignature getLastSignature() {
        return lastSignature;
    }

    /**
     * Verifica o tipo da última assinatura e aciona o método apropriado para
     * lidar com ela
     * @param signatureList A lista de assinaturas
     * @param pdfFile Os bytes do documento assinado
     */
    private void resolveLastSignature(List<PDSignature> signatureList, byte[] pdfFile) {
        String typeDic = this.padesVerifier.getTypeOfDictionary(lastSignature);
        if (typeDic.equals("DocTimeStamp")) {
            resolveTSLastSignaturePolicy(signatureList, pdfFile);
        } else {
            resolveLastSignaturePolicy(null, pdfFile);
        }
    }

    /**
     * Utilizado quando a última assinatura é um carimbo de tempo. Atualiza
     * os atributos da classe e configura o {@link Verifier} de acordo
     * @param signatureList A lista de assinaturas
     * @param pdfFile Os bytes do documento assinado
     */
    private void resolveTSLastSignaturePolicy(List<PDSignature> signatureList, byte[] pdfFile) {
        PDSignature lastSignature = signatureList.get(0);

        boolean found = false;
        while (!found) {
            this.updateLastSignature(signatureList);
            String typeDicAux = this.padesVerifier.getTypeOfDictionary(lastSignature);
            if (typeDicAux.equals("Sig")) {
                found = true;
                resolveLastSignaturePolicy(null, pdfFile);
            } else {
                signatureList.remove(this.lastSignatureIndex);
            }
        }
        this.lastSignature = lastSignature;
    }

    /**
     * Atualiza os atributos da classe e configura o {@link Verifier} de acordo
     * com os valores da última assinatura
     * @param pdfFile Os bytes do documento assinado
     */
    public void resolveLastSignaturePolicy(DssAttribute dssAttribute, byte[] pdfFile) {
        byte[] contents = null;
        try {
            contents = lastSignature.getContents(pdfFile);
        } catch (IOException e) {
            e.printStackTrace();
        }
        this.resolveSignaturePolicy(dssAttribute, contents);
    }

    /**
     * Verifica se o conteúdo é uma assinatura CAdES válida e aciona
     * o método de configuração do {@link Verifier}.
     * Re-útiliza a política armazenada no DSS se possível. Parâmetro DSS como nulo sempre vai resultar no download
     * de uma nova política.
     * @param dssAttribute Atribudo DSS
     * @param contents Conteúdo da assinatura
     */
    private void resolveSignaturePolicy(DssAttribute dssAttribute, byte[] contents) {
        try {
            CadesSignatureContainer signatureContainer = new CadesSignatureContainer(contents);
            List<CadesSignature> signatureList = signatureContainer.getSignatures();
            if (signatureList.size() == 1) {
                runCadesVerifierSetActualPolicy(dssAttribute, signatureList);
            }
        } catch (PbadException e) {
            e.printStackTrace();
        }
    }

    /**
     * Configura o {@link Verifier} de acordo com os valores da última assinatura
     * Re-útiliza a política armazenada no DSS se possível. Parâmetro DSS como nulo sempre vai resultar no download
     * de uma nova política.
     * @param signatureList A lista de assinaturas
     */
    private void runCadesVerifierSetActualPolicy(DssAttribute dssAttribute, List<CadesSignature> signatureList) {
        CadesSignature signature = signatureList.get(0);
        PadesSignatureComponent padesComponent = this.padesVerifier.getPadesComponent();
        CadesVerifier cadesVerifier = (CadesVerifier) padesComponent.getCadesVerifier();
        cadesVerifier.setPolicyType(SignaturePolicyInterface.AdESType.PAdES);
        try {
            if (dssAttribute == null || !dssAttribute.resolvePolicy(signature.getSignaturePolicyIdentifier())) {
                padesComponent.getSignaturePolicy().setActualPolicy(
                        signature.getSignaturePolicyIdentifier(),
                        signature.getSignaturePolicyUri(), SignaturePolicyInterface.AdESType.PAdES);
            }
        } catch (Exception e) {
            padesComponent.getSignaturePolicy().setDefaultPolicy();
        }
    }

    /**
     * Atualiza os atributos da classe e remove a última assinatura
     * da lista dada
     * @param signatureList A lista de assinaturas
     * @return A lista de assinaturas com a última assinatura removida
     */
    public List<PDSignature> updateLastSignature(List<PDSignature> signatureList) {
        PDSignature lastSignature = signatureList.get(0);
        int[] lastSignatureByteRange = lastSignature.getByteRange();
        int lastSignatureIndex = 0;

        for (int i = 1; i < signatureList.size(); i++) {
            PDSignature toCompare = signatureList.get(i);
            int[] toCompareByteRange = toCompare.getByteRange();
            if (toCompareByteRange[1] > lastSignatureByteRange[1]) {
                lastSignature = toCompare;
                lastSignatureIndex = i;
                lastSignatureByteRange = toCompareByteRange;
            }
        }

        this.lastSignature = lastSignature;
        this.lastSignatureIndex = lastSignatureIndex;

        signatureList.remove(lastSignatureIndex);
        return signatureList;
    }

}
