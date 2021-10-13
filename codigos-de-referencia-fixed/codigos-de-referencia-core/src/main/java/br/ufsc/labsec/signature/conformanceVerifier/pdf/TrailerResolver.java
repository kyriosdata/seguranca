package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import org.apache.pdfbox.cos.COSDictionary;
import org.apache.pdfbox.io.RandomAccessBufferedFileInputStream;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.pdfparser.COSParser;
import org.apache.pdfbox.pdmodel.PDDocument;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.util.Arrays;

/**
 * Esta classe é responsável por lidar com as seções de trailer
 * de um documento PDF
 */
public class TrailerResolver {
    /**
     * Documento assinado
     */
    private PDDocument document;
    /**
     * Seção de trailer
     */
    private COSDictionary trailer;
    /**
     * Conteúdo assinado
     */
    private byte[] content;

    /**
     * Construtor
     * @param document O documento assinado
     * @param content O conteúdo assinado
     */
    public TrailerResolver(PDDocument document, byte[] content) {
        this.trailer = document.getDocument().getTrailer();
        this.document = document;
        this.content = content;
    }

    /**
     * Retorna a seção de trailer
     * @return A seção de trailer
     */
    public COSDictionary getTrailer() {
        return this.trailer;
    }

    /**
     * Caminha pelas seções de trailer do arquivo
     * @throws IOException Exceção em caso de erro na leitura do arquivo
     */
    public void next() throws IOException {
        if (trailer != null && trailer.containsKey("Prev")) {
            long address = trailer.getInt("Prev");
            byte[] newTrailer = Arrays.copyOfRange(content, (int)address, content.length);
            RandomAccessRead rar = new RandomAccessBufferedFileInputStream(new ByteArrayInputStream(newTrailer));
            TrailerParser trailerParser = new TrailerParser(rar, document);
            trailer = trailerParser.getTrailer();
        } else {
            trailer = null;
        }
    }

    /**
     * Esta classe representa um Parser do dicionário de trailer
     */
    private class TrailerParser extends DictionaryParser {

        /**
         * O dicionário
         */
        private COSDictionary dictionary;

        /**
         * Construtor
         * @param trailerSource
         * @param document O documento assinado
         */
        public TrailerParser(RandomAccessRead trailerSource, PDDocument document) {
            super(trailerSource, document);
        }

        /**
         * Realiza o parse do dicionário
         * @return O dicionário após a operação de parse
         * @throws IOException Exceção em caso de erro durante o parse
         */
        public COSDictionary getTrailer() throws IOException {
            /*
            Somente percorre um único dicionário
             */
            if (dictionary == null) {
                dictionary = this.parseDictionary();
            }
            return dictionary;
        }
    }
}
