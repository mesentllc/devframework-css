package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"queryResponse"})
@XmlRootElement(name = "chainedQueryResponse")
public class ChainedQueryResponse {
	protected List<QueryResponse> queryResponse;

	public List<QueryResponse> getQueryResponse() {
		if (this.queryResponse == null) {
			this.queryResponse = new ArrayList();
		}
		return this.queryResponse;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"queryName", "parameterSetName", "keyedStanzas"})
	public static class QueryResponse {
		@XmlElement(required = true)
		protected String queryName;
		protected String parameterSetName;
		protected List<KeyedStanzasType> keyedStanzas;
		@XmlAttribute
		protected Boolean partialResult;

		public String getQueryName() {
			return this.queryName;
		}

		public void setQueryName(String value) {
			this.queryName = value;
		}

		public String getParameterSetName() {
			return this.parameterSetName;
		}

		public void setParameterSetName(String value) {
			this.parameterSetName = value;
		}

		public List<KeyedStanzasType> getKeyedStanzas() {
			if (this.keyedStanzas == null) {
				this.keyedStanzas = new ArrayList();
			}
			return this.keyedStanzas;
		}

		public Boolean isPartialResult() {
			return this.partialResult;
		}

		public void setPartialResult(Boolean value) {
			this.partialResult = value;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\ChainedQueryResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */