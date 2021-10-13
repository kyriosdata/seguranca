package br.ufsc.labsec.signature.conformanceVerifier.cades;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import javax.activation.MimetypesFileTypeMap;

/**
 * Esta classe provê o MIME type através da extensão do arquivo
 */
public class MimeTypesMap {

	/**
	 * Instância da classe
	 */
    private static MimeTypesMap instance;
	/**
	 * Mapa entre os tipos e as extensões de arquivos
	 */
    private MimetypesFileTypeMap mimeTypesFileTypeMap;

	/**
	 * Construtor. Carrega os dados do mapa através de
	 * arquivos de configuração nos recursos do projeto
	 */
    private MimeTypesMap() throws FileNotFoundException {
    	try {
			InputStream stream = this.getClass().getResourceAsStream(
					"/resources/mimeTypes.conf");
			if (stream == null) {
				stream = new FileInputStream("resources/mimeTypes.conf");
			}
			this.mimeTypesFileTypeMap = new MimetypesFileTypeMap(stream);

		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    }

	/**
	 * Retorna a instância da classe
	 * @return A instância da classe
	 */
    public static MimeTypesMap getInstance() throws FileNotFoundException {
        if (instance == null) {
            instance = new MimeTypesMap();
        }
        return instance;
    }

	/**
	 * Retorna o MIME type do arquivo
	 * @param contentFile O arquivo a ser analisado
	 * @return O MIME type do arquivo
	 */
    public String getContentType(File contentFile) {
        return this.mimeTypesFileTypeMap.getContentType(contentFile);
    }
}
