package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.pdfparser.COSParser;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.IOException;

/**
 * Esta classe é um Parser de dicionários de documentos PDF
 */
public abstract class DictionaryParser extends COSParser {
    /**
     * Construtor
     * @param source Objeto que permite leitura aleatório em um documento
     * @param document O documento PDF
     */
    public DictionaryParser(RandomAccessRead source, PDDocument document) {
        super(source);
        this.document = document.getDocument();
    }

    /**
     * Realiza a operação de parse no dicionário
     * @return Retorna o dicionário após a operação de parse
     * @throws IOException Exceção em caso de erro durante o parse
     */
    protected COSDictionary parseDictionary() throws IOException {
        this.readObjectNumber();
        this.readGenerationNumber();
        this.readExpectedString(OBJ_MARKER, true);
        return this.parseCOSDictionary();
    }
}
