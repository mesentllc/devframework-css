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
@XmlType(name = "", propOrder = {"name", "queryItem"})
@XmlRootElement(name = "indexQueryRequest")
public class IndexQueryRequest {
	protected String name;
	@XmlElement(required = true)
	protected List<QueryItem> queryItem;

	public String getName() {
		return this.name;
	}

	public void setName(String value) {
		this.name = value;
	}

	public List<QueryItem> getQueryItem() {
		if (this.queryItem == null) {
			this.queryItem = new ArrayList();
		}
		return this.queryItem;
	}

	@XmlAccessorType(XmlAccessType.FIELD)
	@XmlType(name = "", propOrder = {"index", "stanzaId", "paging"})
	public static class QueryItem {
		@XmlElement(required = true)
		protected List<Index> index;
		@XmlElement(required = true)
		protected List<StanzaIdType> stanzaId;
		protected PagingRequestType paging;

		public List<Index> getIndex() {
			if (this.index == null) {
				this.index = new ArrayList();
			}
			return this.index;
		}

		public List<StanzaIdType> getStanzaId() {
			if (this.stanzaId == null) {
				this.stanzaId = new ArrayList();
			}
			return this.stanzaId;
		}

		public PagingRequestType getPaging() {
			return this.paging;
		}

		public void setPaging(PagingRequestType value) {
			this.paging = value;
		}

		@XmlAccessorType(XmlAccessType.FIELD)
		@XmlType(name = "", propOrder = {"stanzaId", "indexElement", "sortElement"})
		public static class Index {
			@XmlElement(required = true)
			protected StanzaIdType stanzaId;
			@XmlElement(required = true)
			protected List<IndexElementType> indexElement;
			protected List<SortElementType> sortElement;
			@XmlAttribute
			protected EffectiveDateFilterType effectiveDateFilter;

			public StanzaIdType getStanzaId() {
				return this.stanzaId;
			}

			public void setStanzaId(StanzaIdType value) {
				this.stanzaId = value;
			}

			public List<IndexElementType> getIndexElement() {
				if (this.indexElement == null) {
					this.indexElement = new ArrayList();
				}
				return this.indexElement;
			}

			public List<SortElementType> getSortElement() {
				if (this.sortElement == null) {
					this.sortElement = new ArrayList();
				}
				return this.sortElement;
			}

			public EffectiveDateFilterType getEffectiveDateFilter() {
				return this.effectiveDateFilter;
			}

			public void setEffectiveDateFilter(EffectiveDateFilterType value) {
				this.effectiveDateFilter = value;
			}
		}
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\framework\cds\IndexQueryRequest.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */