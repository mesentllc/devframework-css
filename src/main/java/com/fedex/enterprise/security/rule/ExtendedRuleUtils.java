package com.fedex.enterprise.security.rule;

import javax.faces.model.SelectItem;
import java.util.ArrayList;
import java.util.List;

public class ExtendedRuleUtils {
	public static List<SelectItem> createExtRuleOperatorItems() {
		List<SelectItem> extRuleOperatorItems = new ArrayList();
		SelectItem tmpSelectItem = new SelectItem();
		tmpSelectItem.setLabel("equals");
		tmpSelectItem.setValue("equals");
		extRuleOperatorItems.add(tmpSelectItem);
		SelectItem tmpSelectItem2 = new SelectItem();
		tmpSelectItem2.setLabel("is not equal");
		tmpSelectItem2.setValue("is not equal");
		extRuleOperatorItems.add(tmpSelectItem2);
		SelectItem tmpSelectItem3 = new SelectItem();
		tmpSelectItem3.setLabel("is greater than");
		tmpSelectItem3.setValue("is greater than");
		extRuleOperatorItems.add(tmpSelectItem3);
		SelectItem tmpSelectItem4 = new SelectItem();
		tmpSelectItem4.setLabel("is less than");
		tmpSelectItem4.setValue("is less than");
		extRuleOperatorItems.add(tmpSelectItem4);
		SelectItem tmpSelectItem5 = new SelectItem();
		tmpSelectItem5.setLabel("is after");
		tmpSelectItem5.setValue("is after");
		extRuleOperatorItems.add(tmpSelectItem5);
		SelectItem tmpSelectItem6 = new SelectItem();
		tmpSelectItem6.setLabel("is before");
		tmpSelectItem6.setValue("is before");
		extRuleOperatorItems.add(tmpSelectItem6);
		return extRuleOperatorItems;
	}

	public static List<SelectItem> createExtRuleValueTypeItems() {
		List<SelectItem> extRuleValueTypeItems = new ArrayList();
		SelectItem tmpSelectItem = new SelectItem();
		tmpSelectItem.setLabel("String");
		tmpSelectItem.setValue("String");
		extRuleValueTypeItems.add(tmpSelectItem);
		SelectItem tmpSelectItem1 = new SelectItem();
		tmpSelectItem1.setLabel("Number");
		tmpSelectItem1.setValue("Number");
		extRuleValueTypeItems.add(tmpSelectItem1);
		SelectItem tmpSelectItem2 = new SelectItem();
		tmpSelectItem2.setLabel("Decimal");
		tmpSelectItem2.setValue("Decimal");
		extRuleValueTypeItems.add(tmpSelectItem2);
		SelectItem tmpSelectItem3 = new SelectItem();
		tmpSelectItem3.setLabel("Date");
		tmpSelectItem3.setValue("Date");
		extRuleValueTypeItems.add(tmpSelectItem3);
		SelectItem tmpSelectItem4 = new SelectItem();
		tmpSelectItem4.setLabel("Time");
		tmpSelectItem4.setValue("Time");
		extRuleValueTypeItems.add(tmpSelectItem4);
		SelectItem tmpSelectItem5 = new SelectItem();
		tmpSelectItem5.setLabel("Key");
		tmpSelectItem5.setValue("Key");
		extRuleValueTypeItems.add(tmpSelectItem5);
		return extRuleValueTypeItems;
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\rule\ExtendedRuleUtils.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */