package br.ufsc.labsec.signature.tsa;

import java.util.List;

public interface TimeStampAttributeIncluder {
	
	byte[] addAttributesTimeStamp(byte[] timeStamp,List<String> attributesList);
}
