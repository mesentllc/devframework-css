package com.fedex.cds.client.security;

import com.fedex.framework.logging.FedExLoggerInterface;

public class ClientInvocationContext {
	private static final FedExLoggerInterface LOGGER = com.fedex.framework.logging.FedExLogger.getLogger(ClientInvocationContext.class);
	private static ThreadLocal<String> userId = new ThreadLocal() {
		protected synchronized String initialValue() {
			return "";
		}
	};
	private static ThreadLocal<String> endpointServiceAppId = new ThreadLocal() {
		protected synchronized String initialValue() {
			return "";
		}
	};

	public static String getUserId() {
		return userId.get();
	}

	public static void setUserId(String uId) {
		userId.set(uId);
	}

	public static String getEndpointServiceAppId() {
		return endpointServiceAppId.get();
	}

	public static void setEndpointServiceAppId(String serviceAppId) {
		endpointServiceAppId.set(serviceAppId);
	}

	public static void clear() {
		userId.set("");
		endpointServiceAppId.set("");
	}

	public static String getDebugInfo() {
		return "UserId=" + userId.get() + "; endpointServiceAppId=" + endpointServiceAppId.get();
	}

	public static void main(String[] args) {
		LOGGER.always("Current User=" + getUserId());
		setUserId("230734");
		LOGGER.always("Current User=" + getUserId());
		clear();
		LOGGER.always("Current User=" + getUserId());
		LOGGER.always("Current App Id=" + getEndpointServiceAppId());
		LOGGER.always(getDebugInfo());
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\client\security\ClientInvocationContext.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */