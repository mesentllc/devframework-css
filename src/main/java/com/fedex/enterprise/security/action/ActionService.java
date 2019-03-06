package com.fedex.enterprise.security.action;

import com.fedex.cds.Bookmark;

import java.util.List;

public interface ActionService {
	List<ActionData> getActionsForApplication(String paramString, Bookmark paramBookmark);

	List<ActionData> getActionsForApplicationByPartialActionName(String paramString1, String paramString2, Bookmark paramBookmark);

	ActionData getAction(long paramLong);

	long insertAction(ActionData paramActionData);

	void deleteAction(ActionData paramActionData);

	void deleteAction(ActionData paramActionData, boolean paramBoolean, String paramString1, String paramString2);

	void updateAction(ActionData paramActionData);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\action\ActionService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */