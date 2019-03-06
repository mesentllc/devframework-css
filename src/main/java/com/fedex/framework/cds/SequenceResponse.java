package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"domain", "sequenceName", "blockSize", "startSequence", "endSequence", "currentSequence", "startRange", "endRange", "wrapped", "incrementBy", "dataCenterId"})
@XmlRootElement(name = "sequenceResponse")
public class SequenceResponse {
	@XmlElement(required = true)
	protected String domain;
	@XmlElement(required = true)
	protected String sequenceName;
	@XmlElement(required = true)
	protected String blockSize;
	protected String startSequence;
	protected String endSequence;
	protected String currentSequence;
	@XmlElement(required = true)
	protected String startRange;
	@XmlElement(required = true)
	protected String endRange;
	protected boolean wrapped;
	@XmlElement(required = true)
	protected String incrementBy;
	@XmlElement(required = true)
	protected String dataCenterId;

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

	public String getBlockSize() {
		return this.blockSize;
	}

	public void setBlockSize(String value) {
		this.blockSize = value;
	}

	public String getStartSequence() {
		return this.startSequence;
	}

	public void setStartSequence(String value) {
		this.startSequence = value;
	}

	public String getEndSequence() {
		return this.endSequence;
	}

	public void setEndSequence(String value) {
		this.endSequence = value;
	}

	public String getCurrentSequence() {
		return this.currentSequence;
	}

	public void setCurrentSequence(String value) {
		this.currentSequence = value;
	}

	public String getStartRange() {
		return this.startRange;
	}

	public void setStartRange(String value) {
		this.startRange = value;
	}

	public String getEndRange() {
		return this.endRange;
	}

	public void setEndRange(String value) {
		this.endRange = value;
	}

	public boolean isWrapped() {
		return this.wrapped;
	}

	public void setWrapped(boolean value) {
		this.wrapped = value;
	}

	public String getIncrementBy() {
		return this.incrementBy;
	}

	public void setIncrementBy(String value) {
		this.incrementBy = value;
	}

	public String getDataCenterId() {
		return this.dataCenterId;
	}

	public void setDataCenterId(String value) {
		this.dataCenterId = value;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\SequenceResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */