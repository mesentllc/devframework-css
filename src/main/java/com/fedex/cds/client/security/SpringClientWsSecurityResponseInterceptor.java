package com.fedex.cds.client.security;

import com.fedex.common.icefaces.util.FacesUtils;
import com.fedex.enterprise.security.cds.authZ.Action;
import com.fedex.enterprise.security.cds.authZ.ApplicationRole;
import com.fedex.enterprise.security.cds.authZ.AuditRecord;
import com.fedex.enterprise.security.cds.authZ.CustomAuthZClass;
import com.fedex.enterprise.security.cds.authZ.ExtRuleXRef;
import com.fedex.enterprise.security.cds.authZ.ExtendedRule;
import com.fedex.enterprise.security.cds.authZ.GroupOwner;
import com.fedex.enterprise.security.cds.authZ.GroupRole;
import com.fedex.enterprise.security.cds.authZ.Resource;
import com.fedex.enterprise.security.cds.authZ.Role;
import com.fedex.enterprise.security.cds.authZ.RoleOwner;
import com.fedex.enterprise.security.cds.authZ.Rule;
import com.fedex.enterprise.security.cds.authZ.UserRole;
import com.fedex.enterprise.security.esc.view.model.WssoHandler;
import com.fedex.framework.cds.IndexQueryResponse;
import com.fedex.framework.cds.KeyedStanzasType;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;
import com.fedex.security.server.Authorizor;
import com.fedex.security.server.AuthorizorFactory;
import org.springframework.ws.client.WebServiceClientException;
import org.springframework.ws.client.core.WebServiceTemplate;
import org.springframework.ws.client.support.interceptor.ClientInterceptor;
import org.springframework.ws.context.MessageContext;
import org.springframework.ws.soap.SoapHeader;
import org.springframework.ws.soap.saaj.SaajSoapMessage;
import org.springframework.ws.soap.saaj.SaajSoapMessageFactory;
import org.springframework.xml.transform.StringResult;
import org.w3c.dom.Element;

import javax.xml.bind.JAXBContext;
import javax.xml.soap.SOAPBody;
import javax.xml.soap.SOAPBodyElement;
import javax.xml.transform.dom.DOMResult;
import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class SpringClientWsSecurityResponseInterceptor
		implements ClientInterceptor {
	public static final String WSSE_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
	public static final String WSU_NAMESPACE = "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
	private final FedExLoggerInterface logger = FedExLogger.getLogger(SpringClientWsSecurityResponseInterceptor.class);
	private WebServiceTemplate webServiceTemplate;

	public WebServiceTemplate getWebServiceTemplate() {
		return this.webServiceTemplate;
	}

	public void setWebServiceTemplate(WebServiceTemplate webServiceTemplate) {
		this.webServiceTemplate = webServiceTemplate;
	}

	public boolean handleFault(MessageContext mc)
			throws WebServiceClientException {
		return false;
	}

	public boolean handleRequest(MessageContext mc)
			throws WebServiceClientException {
		return true;
	}

	public boolean handleResponse(MessageContext mc)
			throws WebServiceClientException {
		try {
			SaajSoapMessage saajSoapMessage = (SaajSoapMessage)mc.getResponse();
			SOAPBody soapBody = saajSoapMessage.getSaajMessage().getSOAPBody();
			SoapHeader soapHeader = saajSoapMessage.getSoapHeader();
			Iterator<SOAPBodyElement> iterator = soapBody.getChildElements();
			this.logger.warn(new FedExLogEntry("SOAPBody Name = " + soapBody.getNodeName()));
			WssoHandler roleHandler = (WssoHandler)FacesUtils.getManagedBean("wssoHandler");
			String onBehalfOf = roleHandler.getUserId();
			while (iterator.hasNext()) {
				SOAPBodyElement bodyElement = iterator.next();
				String bodyElementName = bodyElement.getNodeName();
				this.logger.warn(new FedExLogEntry("SOAPBodyElement Name = " + bodyElementName));
				if ("cds:indexQueryResponse".equals(bodyElementName)) {
					IndexQueryResponse indexResponse = (IndexQueryResponse)this.webServiceTemplate.getUnmarshaller().unmarshal(saajSoapMessage.getPayloadSource());
					List<IndexQueryResponse.QueryItem> queryItemList = indexResponse.getQueryItem();
					ArrayList<Long> keysToRemove = new ArrayList();
					KeyedStanzasType.Stanza sOut = null;
					for (IndexQueryResponse.QueryItem item : queryItemList) {
						for (KeyedStanzasType keyedStanzas : item.getKeyedStanzas()) {
							List<KeyedStanzasType.Stanza> stanzaList = keyedStanzas.getStanza();
							for (KeyedStanzasType.Stanza s : stanzaList) {
								Element docElement = s.getAny();
								String stanzaName = s.getName();
								this.logger.warn(new FedExLogEntry("Stanza Name = " + stanzaName));
								if ("action".equalsIgnoreCase(stanzaName)) {
									JAXBContext context = null;
									javax.xml.bind.Unmarshaller unmarshaller = null;
									context = JAXBContext.newInstance(Action.class);
									unmarshaller = context.createUnmarshaller();
									Action action = (Action)unmarshaller.unmarshal(docElement);
									this.logger.warn(new FedExLogEntry("Action = " + action.getActionName()));
									Authorizor authZ = AuthorizorFactory.getAuthorizor();
									String resource = formatAppId(String.valueOf(action.getApplicationId())) + "/ACTION/";
									if ((!authZ.isAllowed(onBehalfOf, resource, "view")) && (!authZ.isAllowed(onBehalfOf, resource, "create")) && (!authZ.isAllowed(onBehalfOf, resource, "modify")) && (!authZ.isAllowed(onBehalfOf, resource, "delete"))) {
										if ("view".equals(action.getActionName())) {
											sOut = s;
											keysToRemove.add(Long.valueOf(keyedStanzas.getKey()));
										}
									}
								}
								else {
									if ("resource".equalsIgnoreCase(stanzaName)) {
										JAXBContext context = null;
										javax.xml.bind.Unmarshaller unmarshaller = null;
										context = JAXBContext.newInstance(Resource.class);
										unmarshaller = context.createUnmarshaller();
										Resource resource = (Resource)unmarshaller.unmarshal(docElement);
										this.logger.warn(new FedExLogEntry("Resource = " + resource.getResourceName()));
									}
									else {
										if ("role".equalsIgnoreCase(stanzaName)) {
											JAXBContext context = null;
											javax.xml.bind.Unmarshaller unmarshaller = null;
											context = JAXBContext.newInstance(Role.class);
											unmarshaller = context.createUnmarshaller();
											Role role = (Role)unmarshaller.unmarshal(docElement);
											this.logger.warn(new FedExLogEntry("Role = " + role.getRoleScopeName()));
										}
										else {
											if ("rule".equalsIgnoreCase(stanzaName)) {
												JAXBContext context = null;
												javax.xml.bind.Unmarshaller unmarshaller = null;
												context = JAXBContext.newInstance(Rule.class);
												unmarshaller = context.createUnmarshaller();
												Rule rule = (Rule)unmarshaller.unmarshal(docElement);
												this.logger.warn(new FedExLogEntry("Rule = " + rule.getActionDocId() + ", " + rule.getResourceDocId() + ", " + rule.getRoleDocId()));
											}
											else {
												if ("auditRecord".equalsIgnoreCase(stanzaName)) {
													JAXBContext context = null;
													javax.xml.bind.Unmarshaller unmarshaller = null;
													context = JAXBContext.newInstance(AuditRecord.class);
													unmarshaller = context.createUnmarshaller();
													AuditRecord auditRecord = (AuditRecord)unmarshaller.unmarshal(docElement);
													this.logger.warn(new FedExLogEntry("AuditRecord = " + auditRecord.getEventDesc()));
												}
												else {
													if ("extendedRule".equalsIgnoreCase(stanzaName)) {
														JAXBContext context = null;
														javax.xml.bind.Unmarshaller unmarshaller = null;
														context = JAXBContext.newInstance(ExtendedRule.class);
														unmarshaller = context.createUnmarshaller();
														ExtendedRule extRule = (ExtendedRule)unmarshaller.unmarshal(docElement);
														this.logger.warn(new FedExLogEntry("ExtendedRule = " + extRule.getExtendedRuleKey() + " " + extRule.getExtendedRuleOperator() + " " + extRule.getExtendedRuleValue()));
													}
													else {
														if ("extRuleXRef".equalsIgnoreCase(stanzaName)) {
															JAXBContext context = null;
															javax.xml.bind.Unmarshaller unmarshaller = null;
															context = JAXBContext.newInstance(ExtRuleXRef.class);
															unmarshaller = context.createUnmarshaller();
															ExtRuleXRef extRuleXRef = (ExtRuleXRef)unmarshaller.unmarshal(docElement);
															this.logger.warn(new FedExLogEntry("ExtRuleXRef = " + extRuleXRef.getRuleDocId() + ":" + extRuleXRef.getExtRuleDocId()));
														}
														else {
															if ("roleOwner".equalsIgnoreCase(stanzaName)) {
																JAXBContext context = null;
																javax.xml.bind.Unmarshaller unmarshaller = null;
																context = JAXBContext.newInstance(RoleOwner.class);
																unmarshaller = context.createUnmarshaller();
																RoleOwner roleOwner = (RoleOwner)unmarshaller.unmarshal(docElement);
																this.logger.warn(new FedExLogEntry("RoleOwner = " + roleOwner.getRoleDocId() + ":" + roleOwner.getRoleOwnerFedExId()));
															}
															else {
																if ("groupOwner".equalsIgnoreCase(stanzaName)) {
																	JAXBContext context = null;
																	javax.xml.bind.Unmarshaller unmarshaller = null;
																	context = JAXBContext.newInstance(GroupOwner.class);
																	unmarshaller = context.createUnmarshaller();
																	GroupOwner groupOwner = (GroupOwner)unmarshaller.unmarshal(docElement);
																	this.logger.warn(new FedExLogEntry("GroupOwner = " + groupOwner.getRoleDocId() + ":" + groupOwner.getGroupName()));
																}
																else {
																	if ("applicationRole".equalsIgnoreCase(stanzaName)) {
																		JAXBContext context = null;
																		javax.xml.bind.Unmarshaller unmarshaller = null;
																		context = JAXBContext.newInstance(ApplicationRole.class);
																		unmarshaller = context.createUnmarshaller();
																		ApplicationRole applicationRole = (ApplicationRole)unmarshaller.unmarshal(docElement);
																		this.logger.warn(new FedExLogEntry("ApplicationRole = " + applicationRole.getRoleDocId() + ":" + applicationRole.getApplicationId()));
																	}
																	else {
																		if ("groupRole".equalsIgnoreCase(stanzaName)) {
																			JAXBContext context = null;
																			javax.xml.bind.Unmarshaller unmarshaller = null;
																			context = JAXBContext.newInstance(GroupRole.class);
																			unmarshaller = context.createUnmarshaller();
																			GroupRole groupRole = (GroupRole)unmarshaller.unmarshal(docElement);
																			this.logger.warn(new FedExLogEntry("GroupRole = " + groupRole.getRoleDocId() + ":" + groupRole.getGroupName()));
																		}
																		else {
																			if ("userRole".equalsIgnoreCase(stanzaName)) {
																				JAXBContext context = null;
																				javax.xml.bind.Unmarshaller unmarshaller = null;
																				context = JAXBContext.newInstance(UserRole.class);
																				unmarshaller = context.createUnmarshaller();
																				UserRole userRole = (UserRole)unmarshaller.unmarshal(docElement);
																				this.logger.warn(new FedExLogEntry("UserRole = " + userRole.getRoleDocId() + ":" + userRole.getUserFedExId()));
																			}
																			else {
																				if ("customAuthZClass".equalsIgnoreCase(stanzaName)) {
																					JAXBContext context = null;
																					javax.xml.bind.Unmarshaller unmarshaller = null;
																					context = JAXBContext.newInstance(CustomAuthZClass.class);
																					unmarshaller = context.createUnmarshaller();
																					CustomAuthZClass customAuthZClass = (CustomAuthZClass)unmarshaller.unmarshal(docElement);
																					this.logger.warn(new FedExLogEntry("CustomAuthZClass = " + customAuthZClass.getCustomAuthZClassName()));
																				}
																			}
																		}
																	}
																}
															}
														}
													}
												}
											}
										}
									}
								}
							}
							if (sOut != null) {
								stanzaList.remove(sOut);
								sOut = null;
							}
						}
					}
					StringResult result = new StringResult();
					this.webServiceTemplate.getMarshaller().marshal(indexResponse, result);
					DOMResult header = (DOMResult)soapHeader.getResult();
					StringBuffer buffer = new StringBuffer();
					buffer.append(header.toString());
					this.logger.warn(new FedExLogEntry("Header = " + buffer.toString()));
					buffer.append(result.toString());
					this.logger.warn(new FedExLogEntry("Message = " + buffer.toString()));
					SaajSoapMessageFactory factory = new SaajSoapMessageFactory();
					SaajSoapMessage newSaajSoapMessage = factory.createWebServiceMessage(new ByteArrayInputStream(buffer.toString().getBytes(StandardCharsets.UTF_8)));
					mc.setResponse(newSaajSoapMessage);
				}
				else {
					if ("cds:keyQueryResponse".equals(bodyElement.getNodeName())) {
						this.webServiceTemplate.getUnmarshaller().unmarshal(saajSoapMessage.getPayloadSource());
					}
				}
			}
		}
		catch (Exception e) {
			this.logger.warn(new FedExLogEntry("Exception in processing response from CDS..."), e);
		}
		return true;
	}

	public String formatAppId(String appId) {
		if ((appId != null) && (!appId.trim().isEmpty())) {
			String formatAppId = appId.trim();
			if (formatAppId.length() >= 4) {
				return appId;
			}
			if (formatAppId.length() == 3) {
				return formatAppId;
			}
			if (formatAppId.length() == 2) {
				return formatAppId;
			}
			return formatAppId;
		}
		return appId;
	}

	public void afterCompletion(MessageContext arg0, Exception arg1)
			throws WebServiceClientException {
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\cds\client\security\SpringClientWsSecurityResponseInterceptor.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */