package br.ufsc.labsec.signature.signer.ioService;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.logging.Level;

import javax.swing.JFileChooser;
import javax.swing.filechooser.FileNameExtensionFilter;

import br.ufsc.labsec.component.Application;
import br.ufsc.labsec.signature.IOService;

public class IOServiceImp implements IOService {

	@Override
	public void save(InputStream inputStream, String fileType) {
		// TODO Auto-generated method stub

	}

	@Override
	public OutputStream save(String fileType) {

		OutputStream output = null;
		
		JFileChooser fileChooser = new JFileChooser();
		fileChooser.removeChoosableFileFilter(fileChooser.getFileFilter() );
		
		FileNameExtensionFilter filter = new FileNameExtensionFilter("Arquivo " + fileType, ""+fileType);
		fileChooser.setFileFilter(filter);
		
		if (fileChooser.showSaveDialog(null) == JFileChooser.APPROVE_OPTION) {
			String name = fileChooser.getSelectedFile().getAbsolutePath();
			if (!name.endsWith("." + fileType)) {
				name = name + "." + fileType;
			}
			try {
				
				output = new FileOutputStream(name);

			} catch (FileNotFoundException fileNotFoundException) {
				Application.logger.log(Level.SEVERE, fileNotFoundException.getMessage());
				return null;
			}
		}
		
		return output;
	}

	@Override
	public String getSavePath(String fileType) {
		// TODO Auto-generated method stub
		return null;
	}

}
