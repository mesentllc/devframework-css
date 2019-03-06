package com.fedex.framework.cds;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlRootElement;
import javax.xml.bind.annotation.XmlType;
import java.util.ArrayList;
import java.util.List;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "", propOrder = {"queryItem"})
@XmlRootElement(name = "indexQueryResponse")
public class IndexQueryResponse {
	protected List<QueryItem> queryItem;

	public List<QueryItem> getQueryItem() {
		if (this.queryItem == null) {
			this.queryItem = new ArrayList();
		}
		return this.queryItem;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"keyedStanzas", "paging"})
	public static class QueryItem {
		protected List<KeyedStanzasType> keyedStanzas;
		protected PagingResponseType paging;

		public List<KeyedStanzasType> getKeyedStanzas() {
			if (this.keyedStanzas == null) {
				this.keyedStanzas = new ArrayList();
			}
			return this.keyedStanzas;
		}

		public PagingResponseType getPaging() {
			return this.paging;
		}

		public void setPaging(PagingResponseType value) {
			this.paging = value;
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\IndexQueryResponse.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */