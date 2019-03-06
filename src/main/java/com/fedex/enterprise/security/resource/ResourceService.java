package com.fedex.enterprise.security.resource;

import com.fedex.cds.Bookmark;

import java.util.List;

public interface ResourceService {
	List<ResourceData> getResourcesForApplication(String paramString, Bookmark paramBookmark);

	ResourceData getResourceByName(String paramString1, String paramString2);

	List<ResourceData> getResourcesForApplicationByPartialResource(String paramString1, String paramString2, Bookmark paramBookmark);

	List<ResourceData> getResourceRootsForApplication(String paramString, Bookmark paramBookmark);

	ResourceData getResource(long paramLong);

	long insertResource(ResourceData paramResourceData);

	void updateResource(ResourceData paramResourceData);

	void deleteResource(ResourceData paramResourceData);

	void deleteResource(ResourceData paramResourceData, boolean paramBoolean, String paramString1, String paramString2);

	void deleteResourceByRoot(String paramString1, String paramString2);
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\enterprise\security\resource\ResourceService.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */