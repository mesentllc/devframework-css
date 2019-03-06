package com.fedex.xmlns.cds.authz;

import javax.xml.bind.annotation.XmlRegistry;

@XmlRegistry
public class ObjectFactory {
	public Restriction.RestrictionItem.Entry createRestrictionRestrictionItemEntry() {
		return new Restriction.RestrictionItem.Entry();
	}

	public Restriction.USERID createRestrictionUSERID() {
		return new Restriction.USERID();
	}

	public Restriction.RestrictionItem createRestrictionRestrictionItem() {
		return new Restriction.RestrictionItem();
	}

	public Restriction createRestriction() {
		return new Restriction();
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\xmlns\cds\authz\ObjectFactory.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */