package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"importDataItem"})
@XmlRootElement(name = "importDataRequest")
public class ImportDataRequest {
	@XmlElement(required = true)
	protected List<KeyedDocumentType> importDataItem;

	public List<KeyedDocumentType> getImportDataItem() {
		if (this.importDataItem == null) {
			this.importDataItem = new ArrayList();
		}
		return this.importDataItem;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\ImportDataRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */