package com.fedex.enterprise.security.role.restriction;

import com.fedex.enterprise.security.utils.SecurityDataBaseClass;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;

public class RestrictionDataItem
		extends SecurityDataBaseClass
		implements Serializable {
	private static final long serialVersionUID = 1L;
	public String restrictionItemIndex;

	public List<Entry> getEntry() {
		return this.entryList;
	}

	protected List<Entry> entryList = new ArrayList();

	public List<Entry> getEntryList() {
		return this.entryList;
	}

	public void setEntryList(List<Entry> itemList) {
		this.entryList = itemList;
	}

	public String getRestrictionItemIndex() {
		return this.restrictionItemIndex;
	}

	public void setRestrictionItemIndex(String restrictionItemIndex) {
		this.restrictionItemIndex = restrictionItemIndex;
	}

	public boolean validate() {
		super.validate();
		if ((this.entryList == null) || (this.entryList.size() == 0)) {
			this.validationError.append("Empty entry list.  ");
		}
		return this.validationError.length() == 0;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\role\restriction\RestrictionDataItem.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */