package br.ufsc.labsec.signature;

import java.io.InputStream;
import java.io.OutputStream;

public interface IOService {
	
	void save(InputStream inputStream, String fileType);
	OutputStream save(String fileType);
	String getSavePath(String fileType);
	
}
