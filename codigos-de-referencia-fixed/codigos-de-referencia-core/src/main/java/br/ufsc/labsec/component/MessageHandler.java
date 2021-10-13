package br.ufsc.labsec.component;

import java.util.logging.Handler;
import java.util.logging.Level;
import java.util.logging.LogRecord;

import javax.swing.JOptionPane;

/**
 * Esta classe lida com a escrita de mensagens de erro
 */
public class MessageHandler extends Handler {

	@Override
	public void publish(LogRecord record) {
		if (record.getLevel() == Level.SEVERE) {
			JOptionPane.showMessageDialog(null, record.getMessage(), "Problema", JOptionPane.WARNING_MESSAGE);
		}
	}

	@Override
	public void flush() {
		// TODO Auto-generated method stub

	}

	@Override
	public void close() throws SecurityException {
		// TODO Auto-generated method stub

	}

}
