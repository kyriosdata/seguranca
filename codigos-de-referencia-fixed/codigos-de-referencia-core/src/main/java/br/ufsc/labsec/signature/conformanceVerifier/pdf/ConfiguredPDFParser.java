package br.ufsc.labsec.signature.conformanceVerifier.pdf;

import br.ufsc.labsec.component.Application;
import org.apache.pdfbox.io.RandomAccessRead;
import org.apache.pdfbox.io.ScratchFile;
import org.apache.pdfbox.pdfparser.PDFParser;

import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Level;

public class ConfiguredPDFParser extends PDFParser {

    public ConfiguredPDFParser(RandomAccessRead source) throws IOException {
        super(source);
    }

    public boolean containsEOFInRange(int range) {
        try {
            byte[] buffer = new byte[range];
            source.seek((int) source.length() - buffer.length);
            source.read(buffer);
            return this.lastIndexOf(EOF_MARKER, buffer, buffer.length) != -1;
        } catch (IOException e) {
            return false;
        } finally {
            try {
                if (source.length() != 0)
                    source.seek(0);
            } catch (IOException e) {
                Application.logger.log(Level.SEVERE, "Não foi possível retornar ao estado inicial do leitor do PDF.", e);
            }
        }
    }
}
