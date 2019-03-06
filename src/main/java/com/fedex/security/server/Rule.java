package com.fedex.security.server;

import com.fedex.enterprise.security.rule.ExtendedRuleData;
import com.fedex.framework.logging.FedExLogEntry;
import com.fedex.framework.logging.FedExLogger;
import com.fedex.framework.logging.FedExLoggerInterface;

import java.io.Serializable;
import java.math.BigDecimal;
import java.text.SimpleDateFormat;
import java.util.Calendar;
import java.util.List;
import java.util.Map;

public class Rule
		implements Serializable {
	private static final long serialVersionUID = 1L;
	private String roleName = null;
	private String resource = null;
	private String action = null;
	private CustomAuthorizor customAuthorizor = null;
	private char grantFlg;
	private List<ExtendedRuleData> extendedRuleList;
	public static int EXACT_MATCH = 0;
	public static int ENDSWITH_WILDCARD = 1;
	public static int WILDCARD = 2;
	private int resourceType = -1;
	private int actionType = -1;

	public enum valueType {
		LONG,
		STRING,
		DATE,
		TIME,
		FLOAT,
		DOUBLE,
		USD;

		valueType() {
		}
	}

	private static final FedExLoggerInterface logger = FedExLogger.getLogger(Rule.class.getName());

	public Rule(String roleName, String resource, String action, CustomAuthorizor customAuthorizor) {
		this.roleName = roleName;
		configureResource(resource);
		configureAction(action);
		this.grantFlg = 'Y';
		this.extendedRuleList = null;
		this.customAuthorizor = customAuthorizor;
	}

	public Rule(String roleName, String resource, String action, char grantFlg, List<ExtendedRuleData> extRuleList, CustomAuthorizor customAuthorizor) {
		this.roleName = roleName;
		configureResource(resource);
		configureAction(action);
		this.grantFlg = grantFlg;
		this.extendedRuleList = extRuleList;
		this.customAuthorizor = customAuthorizor;
	}

	public String getRoleName() {
		return this.roleName;
	}

	public String getResource() {
		return this.resource;
	}

	public String getAction() {
		return this.action;
	}

	public int getResourceType() {
		return this.resourceType;
	}

	public int getActionType() {
		return this.actionType;
	}

	public char getGrantFlg() {
		return this.grantFlg;
	}

	public List<ExtendedRuleData> getExtendedRuleList() {
		return this.extendedRuleList;
	}

	public CustomAuthorizor getCustomAuthorizor() {
		return this.customAuthorizor;
	}

	public boolean matches(String resource, String action, Map context) {
		boolean resourceMatch = false;
		boolean customAuthzMatch = false;
		if ((getResourceType() == WILDCARD) && (resource != null)) {
			resourceMatch = true;
		}
		else {
			if (!resource.endsWith("/")) {
				resource = resource + "/";
			}
			if ((getResourceType() == EXACT_MATCH) && (getResource().equals(resource))) {
				resourceMatch = true;
			}
			else {
				if ((getResourceType() == ENDSWITH_WILDCARD) && (resource.startsWith(getResource()))) {
					resourceMatch = true;
				}
			}
		}
		boolean actionMatch = false;
		if (resourceMatch) {
			if ((getActionType() == WILDCARD) && (action != null)) {
				actionMatch = true;
			}
			else {
				if ((getActionType() == EXACT_MATCH) && (getAction().equals(action))) {
					actionMatch = true;
				}
			}
		}
		boolean extRuleMatch = false;
		if ((resourceMatch) && (actionMatch)) {
			if (((this.extendedRuleList == null) || (this.extendedRuleList.isEmpty())) && (context == null)) {
				extRuleMatch = true;
			}
			else {
				if (((this.extendedRuleList == null) || (this.extendedRuleList.isEmpty())) && (context != null)) {
					extRuleMatch = false;
				}
				else {
					if (context != null) {
						for (ExtendedRuleData extRule : this.extendedRuleList) {
							if (extendedRuleMatch(extRule, context)) {
								extRuleMatch = true;
							}
							else {
								extRuleMatch = false;
								break;
							}
						}
					}
				}
			}
			if (this.customAuthorizor != null) {
				customAuthzMatch = true;
			}
		}
		return (resourceMatch) && (actionMatch) && ((extRuleMatch) || (customAuthzMatch));
	}

	private void configureResource(String input) {
		if (input != null) {
			if (input.equals("*")) {
				this.resourceType = WILDCARD;
				this.resource = input;
			}
			else {
				if ((input != null) && (input.endsWith("*"))) {
					this.resourceType = ENDSWITH_WILDCARD;
					this.resource = input.substring(0, input.length() - 1);
					if (!this.resource.endsWith("/")) {
						this.resource += "/";
					}
				}
				else {
					this.resourceType = EXACT_MATCH;
					this.resource = input;
					if (!this.resource.endsWith("/")) {
						this.resource += "/";
					}
				}
			}
		}
	}

	private void configureAction(String input) {
		if ((input != null) && (input.equals("*"))) {
			this.actionType = WILDCARD;
			this.action = input;
		}
		else {
			this.actionType = EXACT_MATCH;
			this.action = input;
		}
	}

	private boolean extendedRuleMatch(ExtendedRuleData extRule, Map context) {
		boolean match = false;
		String eKey = extRule.getExtRuleKey();
		String eOper = extRule.getExtRuleOperator();
		String eValue = extRule.getExtRuleValue();
		String eValType = extRule.getExtRuleType();
		try {
			if ("key".equalsIgnoreCase(eValType)) {
				Object m1Object = context.get(eKey);
				Object m2Object = context.get(eValue);
				logger.debug(new FedExLogEntry("[Rule][Ext][Key][Object1 = " + m1Object + "][Oper = " + eOper + "][Object2 = " + m2Object + "]"));
				if ("equals".equalsIgnoreCase(eOper)) {
					match = m1Object.equals(m2Object);
				}
				else {
					if ("is not equal".equalsIgnoreCase(eOper)) {
						match = !m1Object.equals(m2Object);
					}
				}
			}
			else {
				if ("STRING".equalsIgnoreCase(eValType)) {
					String mValue;
					if ((context.get(eKey) instanceof String)) {
						mValue = (String)context.get(eKey);
					}
					else {
						throw new Exception("Value from the context Map is not a String as indicated by the value type in the extended rule!");
					}
					logger.debug(new FedExLogEntry("[Rule][Ext][Number][mValue = " + mValue + "][Oper = " + eOper + "][eValue = " + eValue + "]"));
					if ("equals".equalsIgnoreCase(eOper)) {
						match = mValue.equals(eValue);
					}
					else {
						if ("is not equal".equalsIgnoreCase(eOper)) {
							match = !mValue.equals(eValue);
						}
					}
				}
				else {
					if ("NUMBER".equalsIgnoreCase(eValType)) {
						long eNumber = Long.parseLong(eValue);
						long mNumber;
						if ((context.get(eKey) instanceof Long)) {
							mNumber = ((Long)context.get(eKey)).longValue();
						}
						else {
							throw new Exception("Value from the context Map is not a Long as indicated by the value type in the extended rule!");
						}
						logger.debug(new FedExLogEntry("[Rule][Ext][Number][mNumber = " + mNumber + "][Oper = " + eOper + "][eNumber = " + eNumber + "]"));
						if ("equals".equalsIgnoreCase(eOper)) {
							match = mNumber == eNumber;
						}
						else {
							if ("is not equal".equalsIgnoreCase(eOper)) {
								match = mNumber != eNumber;
							}
							else {
								if ("is less than".equalsIgnoreCase(eOper)) {
									match = mNumber < eNumber;
								}
								else {
									if ("is less than or equals".equalsIgnoreCase(eOper)) {
										match = mNumber <= eNumber;
									}
									else {
										if ("is greater than".equalsIgnoreCase(eOper)) {
											match = mNumber > eNumber;
										}
										else {
											if ("is greater than or equals".equalsIgnoreCase(eOper)) {
												match = mNumber >= eNumber;
											}
										}
									}
								}
							}
						}
					}
					else {
						if ("DATE".equalsIgnoreCase(eValType)) {
							SimpleDateFormat sdf = new SimpleDateFormat("MM/dd/yyyy");
							Calendar eDate = Calendar.getInstance();
							eDate.setTime(sdf.parse(eValue));
							Object oValue = context.get(eKey);
							Calendar mDate;
							if ((oValue instanceof Calendar)) {
								mDate = (Calendar)context.get(eKey);
							}
							else {
								if ((oValue instanceof String)) {
									mDate = Calendar.getInstance();
									mDate.setTime(sdf.parse((String)oValue));
								}
								else {
									throw new Exception("Value from the context Map is not a Calendar or String as indicated by the value type in the extended rule!");
								}
							}
							logger.debug(new FedExLogEntry("[Rule][Ext][Date][mDate = " + mDate + "][Oper = " + eOper + "][eDate = " + eDate + "]"));
							if ("equals".equalsIgnoreCase(eOper)) {
								match = isSameDay(mDate, eDate);
							}
							else {
								if ("is not equal".equalsIgnoreCase(eOper)) {
									match = !isSameDay(mDate, eDate);
								}
								else {
									if (("is less than".equalsIgnoreCase(eOper)) || ("is before".equalsIgnoreCase(eOper))) {
										match = isBeforeDay(mDate, eDate);
									}
									else {
										if ("is less than or equals".equalsIgnoreCase(eOper)) {
											match = (isBeforeDay(mDate, eDate)) || (isSameDay(mDate, eDate));
										}
										else {
											if (("is greater than".equalsIgnoreCase(eOper)) || ("is after".equalsIgnoreCase(eOper))) {
												match = isAfterDay(mDate, eDate);
											}
											else {
												if ("is greater than or equals".equalsIgnoreCase(eOper)) {
													match = (isAfterDay(mDate, eDate)) || (isSameDay(mDate, eDate));
												}
											}
										}
									}
								}
							}
						}
						else {
							if ("TIME".equalsIgnoreCase(eValType)) {
								SimpleDateFormat sdf = new SimpleDateFormat("HH:mm");
								Calendar eTime = Calendar.getInstance();
								eTime.setTime(sdf.parse(eValue));
								Object oValue = context.get(eKey);
								Calendar mTime;
								if ((oValue instanceof Calendar)) {
									mTime = (Calendar)context.get(eKey);
								}
								else {
									if ((oValue instanceof String)) {
										mTime = Calendar.getInstance();
										mTime.setTime(sdf.parse((String)oValue));
									}
									else {
										throw new Exception("Value from the context Map is not a Calendar or a String as indicated by the value type in the extended rule!");
									}
								}
								logger.debug(new FedExLogEntry("[Rule][Ext][Time][mTime = " + mTime + "][Oper = " + eOper + "][eTime = " + eTime + "]"));
								if ("equals".equalsIgnoreCase(eOper)) {
									match = isSameTime(mTime, eTime);
								}
								else {
									if ("is not equal".equalsIgnoreCase(eOper)) {
										match = !isSameTime(mTime, eTime);
									}
									else {
										if (("is less than".equalsIgnoreCase(eOper)) || ("is before".equalsIgnoreCase(eOper))) {
											match = isBeforeTime(mTime, eTime);
										}
										else {
											if ("is less than or equals".equalsIgnoreCase(eOper)) {
												match = (isBeforeTime(mTime, eTime)) || (isSameTime(mTime, eTime));
											}
											else {
												if (("is greater than".equalsIgnoreCase(eOper)) || ("is after".equalsIgnoreCase(eOper))) {
													match = isAfterTime(mTime, eTime);
												}
												else {
													if ("is greater than or equals".equalsIgnoreCase(eOper)) {
														match = (isAfterTime(mTime, eTime)) || (isSameTime(mTime, eTime));
													}
												}
											}
										}
									}
								}
							}
							else {
								if ("Decimal".equalsIgnoreCase(eValType)) {
									BigDecimal eDecimal = new BigDecimal(eValue);
									Object oValue = context.get(eKey);
									BigDecimal mDecimal;
									if ((oValue instanceof BigDecimal)) {
										mDecimal = (BigDecimal)context.get(eKey);
									}
									else {
										if ((oValue instanceof Double)) {
											mDecimal = BigDecimal.valueOf(((Double)oValue).doubleValue());
										}
										else {
											if ((oValue instanceof String)) {
												mDecimal = new BigDecimal((String)oValue);
											}
											else {
												throw new Exception("Value from the context Map is not a BigDecimal, Double, or String as indicated by the value type in the extended rule!");
											}
										}
									}
									logger.debug(new FedExLogEntry("[Rule][Ext][USD][mNumber = " + mDecimal + "][Oper = " + eOper + "][eNumber = " + eDecimal + "]"));
									if ("equals".equalsIgnoreCase(eOper)) {
										match = mDecimal.compareTo(eDecimal) == 0;
									}
									else {
										if ("is not equal".equalsIgnoreCase(eOper)) {
											match = mDecimal.compareTo(eDecimal) != 0;
										}
										else {
											if ("is less than".equalsIgnoreCase(eOper)) {
												match = mDecimal.compareTo(eDecimal) < 0;
											}
											else {
												if ("is less than or equals".equalsIgnoreCase(eOper)) {
													match = mDecimal.compareTo(eDecimal) <= 0;
												}
												else {
													if ("is greater than".equalsIgnoreCase(eOper)) {
														match = mDecimal.compareTo(eDecimal) > 0;
													}
													else {
														if ("is greater than or equals".equalsIgnoreCase(eOper)) {
															match = mDecimal.compareTo(eDecimal) >= 0;
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
		catch (Exception e) {
			logger.warn(new FedExLogEntry("Unable to evaluate this extended rule: " + extRule));
			logger.warn(new FedExLogEntry("With this Map context: " + context));
			logger.warn(new FedExLogEntry("Exception: " + e));
			match = false;
		}
		logger.debug(new FedExLogEntry("Extended Rule Match = " + match));
		return match;
	}

	public static boolean isSameDay(Calendar cal1, Calendar cal2) {
		return (cal1.get(0) == cal2.get(0)) && (cal1.get(1) == cal2.get(1)) && (cal1.get(6) == cal2.get(6));
	}

	public static boolean isBeforeDay(Calendar cal1, Calendar cal2) {
		if (cal1.get(0) < cal2.get(0)) {
			return true;
		}
		if (cal1.get(0) == cal2.get(0)) {
			if (cal1.get(1) < cal2.get(1)) {
				return true;
			}
			return (cal1.get(1) == cal2.get(1)) &&
			       (cal1.get(6) < cal2.get(6));
		}
		return false;
	}

	public static boolean isAfterDay(Calendar cal1, Calendar cal2) {
		if (cal1.get(0) > cal2.get(0)) {
			return true;
		}
		if (cal1.get(0) == cal2.get(0)) {
			if (cal1.get(1) > cal2.get(1)) {
				return true;
			}
			return (cal1.get(1) == cal2.get(1)) &&
			       (cal1.get(6) > cal2.get(6));
		}
		return false;
	}

	public static boolean isSameTime(Calendar cal1, Calendar cal2) {
		return (cal1.get(11) == cal2.get(11)) && (cal1.get(12) == cal2.get(12));
	}

	public static boolean isBeforeTime(Calendar cal1, Calendar cal2) {
		if (cal1.get(11) < cal2.get(11)) {
			return true;
		}
		return (cal1.get(11) == cal2.get(11)) &&
		       (cal1.get(12) < cal2.get(12));
	}

	public static boolean isAfterTime(Calendar cal1, Calendar cal2) {
		if (cal1.get(11) > cal2.get(11)) {
			return true;
		}
		return (cal1.get(11) == cal2.get(11)) &&
		       (cal1.get(12) > cal2.get(12));
	}

	public String toString() {
		return this.roleName + ";" + this.resourceType + "-" + this.resource + ";" + this.actionType + "-" + this.action + ";" + this.grantFlg + ";" + this.extendedRuleList + ";" + (this.customAuthorizor != null ? this.customAuthorizor : "");
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\Rule.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */