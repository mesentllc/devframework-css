package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"domain", "sequenceName", "blockSize"})
@XmlRootElement(name = "sequenceRequest")
public class SequenceRequest {
	@XmlElement(required = true)
	protected String domain;
	@XmlElement(required = true)
	protected String sequenceName;
	protected int blockSize;

	public String getDomain() {
		return this.domain;
	}

	public void setDomain(String value) {
		this.domain = value;
	}

	public String getSequenceName() {
		return this.sequenceName;
	}

	public void setSequenceName(String value) {
		this.sequenceName = value;
	}

	public int getBlockSize() {
		return this.blockSize;
	}

	public void setBlockSize(int value) {
		this.blockSize = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\SequenceRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */