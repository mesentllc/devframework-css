package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlAttribute;
import javax.xml.bind.annotation.XmlElement;
import javax.xml.bind.annotation.XmlElements;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"parameterSet", "keyQueryRequestOrIndexQueryRequest", "responseQueries"})
@XmlRootElement(name = "chainedQueryRequest")
public class ChainedQueryRequest {
	protected List<ParameterSet> parameterSet;
	@XmlElements({@XmlElement(name = "indexQueryRequest", namespace = "http://www.fedex.com/xmlns/cds2", type = IndexQueryRequest.class), @XmlElement(name = "keyQueryRequest", namespace = "http://www.fedex.com/xmlns/cds2", type = KeyQueryRequest.class)})
	protected List<Object> keyQueryRequestOrIndexQueryRequest;
	@XmlElement(required = true)
	protected ResponseQueries responseQueries;

	public List<ParameterSet> getParameterSet() {
		if (this.parameterSet == null) {
			this.parameterSet = new ArrayList();
		}
		return this.parameterSet;
	}

	public List<Object> getKeyQueryRequestOrIndexQueryRequest() {
		if (this.keyQueryRequestOrIndexQueryRequest == null) {
			this.keyQueryRequestOrIndexQueryRequest = new ArrayList();
		}
		return this.keyQueryRequestOrIndexQueryRequest;
	}

	public ResponseQueries getResponseQueries() {
		return this.responseQueries;
	}

	public void setResponseQueries(ResponseQueries value) {
		this.responseQueries = value;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"name", "parameter"})
	public static class ParameterSet {
		@XmlElement(required = true)
		protected String name;
		@XmlElement(required = true)
		protected List<Parameter> parameter;

		public String getName() {
			return this.name;
		}

		public void setName(String value) {
			this.name = value;
		}

		public List<Parameter> getParameter() {
			if (this.parameter == null) {
				this.parameter = new ArrayList();
			}
			return this.parameter;
		}

		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = {"name", "value"})
		public static class Parameter {
			@XmlElement(required = true)
			protected String name;
			@XmlElement(required = true)
			protected String value;

			public String getName() {
				return this.name;
			}

			public void setName(String value) {
				this.name = value;
			}

			public String getValue() {
				return this.value;
			}

			public void setValue(String value) {
				this.value = value;
			}
		}
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"name"})
	public static class ResponseQueries {
		@XmlElement(required = true)
		protected List<String> name;
		@XmlAttribute
		protected Boolean partialResult;

		public List<String> getName() {
			if (this.name == null) {
				this.name = new ArrayList();
			}
			return this.name;
		}

		public Boolean isPartialResult() {
			return this.partialResult;
		}

		public void setPartialResult(Boolean value) {
			this.partialResult = value;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\ChainedQueryRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */