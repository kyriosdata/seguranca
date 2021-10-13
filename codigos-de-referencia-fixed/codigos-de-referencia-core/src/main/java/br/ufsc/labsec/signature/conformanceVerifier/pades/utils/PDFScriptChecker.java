package br.ufsc.labsec.signature.conformanceVerifier.pades.utils;

import br.ufsc.labsec.signature.conformanceVerifier.report.SignatureReport;
import org.apache.pdfbox.pdmodel.PDDocument;
import org.apache.pdfbox.pdmodel.PDDocumentNameDictionary;
import org.apache.pdfbox.pdmodel.PDJavascriptNameTreeNode;

/**
 * Esta classe realiza a verificação de presença de código
 * JavaScript em um documento PDF.
 */
public class PDFScriptChecker {

    /**
     * O documento PDF
     */
    private PDDocument document;

    /**
     * Construtor
     * @param document O arquivo PDF
     */
    public PDFScriptChecker(PDDocument document) {
        this.document = document;
    }

    /**
     * Verifica se o documento PDF possui código JavaScript no seu conteúdo.
     * Se houver presença de código, uma mensagem de alerta é adicionada
     * ao relatório
     * @param report Relatório de assinatura
     */
    public void treatPresenceOfJavaScript(SignatureReport report) {
        PDDocumentNameDictionary names = new PDDocumentNameDictionary(document.getDocumentCatalog());
        PDJavascriptNameTreeNode jsTreeNode = names.getJavaScript();
        if (jsTreeNode != null) {
            report.setErrorMessage("O documento possui código JavaScript, que pode modificar o seu conteúdo visual.");
        }
    }

}
