package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IUException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.IncrementalUpdateException;
import br.ufsc.labsec.signature.conformanceVerifier.pdf.exceptions.PossibleIncrementalUpdateException;
import org.apache.pdfbox.cos.*;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.IOException;

/**
 * Esta classe é responsável por detectar mudanças nos valores
 * dos campos de formulário de um arquivo PDF.
 */
public abstract class FieldMDPTransformation extends DocMDP {

    /**
     * Construtor
     * @param signatureReference Dicionário da assinatura
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @throws IOException
     */
    public FieldMDPTransformation(COSDictionary signatureReference, PDDocument document, PDDocument previousVersion) throws IOException {
        super(signatureReference, document, previousVersion);
    }

    /**
     * Construtor
     * @param signatureReference Dicionário da assinatura
     * @param document O documento assinado
     * @param previousVersion Versão anterior do documento assinado
     * @param p Índice do parâmetro de transformação
     * @throws IOException
     */
    public FieldMDPTransformation(COSDictionary signatureReference, PDDocument document, PDDocument previousVersion, int p) throws IOException {
        super(signatureReference, document, previousVersion, p);
    }

    /**
     * Verifica a presença dos campos obrigatórios dependendo da ação no campo MDP
     * @param fieldMDPDictionary Dicionário do campo MDP
     * @param base Objeto do campo
     * @return Indica se estão presentes todos os campos necessários
     */
    @Override
    public boolean transformationContainsField(COSDictionary fieldMDPDictionary, COSBase base) {
        if (!(base instanceof COSDictionary) || !PDDocumentUtils.isField((COSDictionary) base)) {
            return false;
        }
        COSDictionary field = (COSDictionary) base;
        String action = fieldMDPDictionary.getNameAsString("Action");
        if (action.equals("All")) {
            return true;
        }
        COSArray fieldNames = (COSArray) fieldMDPDictionary.getDictionaryObject("Fields");
        String name = getFullyQualifiedName(field);
        boolean contains = false;
        for (int i = 0; i < fieldNames.size(); i++) {
            String compare = ((COSString) fieldNames.get(i)).getString();
            if (compare.equals(name)) {
                contains = true;
                break;
            }
        }
        return contains && action.equals("Include") || !contains && action.equals("Exclude");
    }

    /**
     * Realiza a transformação. Verifica se houveram mudanças no arquivo.
     * @throws IncrementalUpdateException Exceção em caso de haver atualizações incrementais na assinatura
     * @throws PossibleIncrementalUpdateException Exceção em caso de não ser possível identificar
     *  quais modificações incrementais foram feitas após uma assinatura
     */
    public abstract void fieldMDPTransform() throws IncrementalUpdateException, PossibleIncrementalUpdateException;

    /**
     * Realiza a transformação. Verifica se houveram mudanças no arquivo.
     * @throws IncrementalUpdateException Exceção em caso de haver atualizações incrementais na assinatura
     * @throws PossibleIncrementalUpdateException Exceção em caso de não ser possível identificar
     *  quais modificações incrementais foram feitas após uma assinatura
     */
    @Override
    public void transform() throws IUException {
        try {
            super.transform();
            fieldMDPTransform();
        } catch (IOException e) {
            PossibleIncrementalUpdateException.throwExceptionFromNoVerification(previousVersion);
        }
    }

    /**
     * Retorna o dicionário 'Data' do dicionário dado
     * @param signatureReference O dicionário a ser buscada a entrada 'Data'
     * @return O dicionário 'Data' do dicionário dado
     */
    @Override
    public COSDictionary getCatalog(COSDictionary signatureReference) {
        return (COSDictionary) signatureReference.getDictionaryObject("Data");
    }
}
