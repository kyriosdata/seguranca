package br.ufsc.labsec.signature.conformanceVerifier.report;

import br.ufsc.labsec.signature.exceptions.SignatureAttributeException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * Esta classe representa o relatório de uma verificação cuja assinatura
 * não foi feita com um certificado ICP-Brasil. Estende {@link SignatureReport}
 */
public class NotICPBrasilSignatureReport extends SignatureReport {

    /**
     * Constrói um nodo XML que possui as informações da assinatura
     * @param document Relatório da verificação em XML
     * @return O nodo com informações da assinatura
     */
    @Override
    public Element generateSignatureElement(Document document) {
        Element signature = document.createElement("notIcpbrSignature");

        Element certification = document.createElement("certification");
        signature.appendChild(certification);

        Element signer = document.createElement("signer");
        Element signerSubjectName = document.createElement("subjectName");
        signerSubjectName.setTextContent(this.signerSubjectName);
        signer.appendChild(signerSubjectName);

        certification.appendChild(signer);

        return signature;
    }


    @Override
    /**
     * Retorna a validade da assinatura
     * @return Indica a validade da assinatura
     */
    public SignatureValidity validityStatus() {
        return SignatureValidity.Indeterminate;
    }

    @Override
    /**
     * Retorna se a assinatura é válida
     * @return Indica se a assinatura é válida
     */
    public boolean isValid() {
        return false;
    }
}
