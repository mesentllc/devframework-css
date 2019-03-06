package com.fedex.security.server;

import java.util.regex.Pattern;

public class RegexRule
		extends Rule {
	private Pattern resourcePattern = null;
	private Pattern actionPattern = null;

	public RegexRule(String roleName, String resource, String action, CustomAuthorizor customAuthorizor) {
		super(roleName, resource, action, customAuthorizor);
		this.resourcePattern = buildResourceRegex(resource);
		this.actionPattern = buildActionRegex(action);
	}

	public Pattern getResourcePattern() {
		return this.resourcePattern;
	}

	public void setResourcePattern(Pattern resourcePattern) {
		this.resourcePattern = resourcePattern;
	}

	public Pattern getActionPattern() {
		return this.actionPattern;
	}

	public void setActionPattern(Pattern actionPattern) {
		this.actionPattern = actionPattern;
	}

	public boolean matches(String resource, String action) {
		if ((resource != null) && (action != null) && (!"".equals(resource)) && (!"".equals(action))) {
			if (!resource.endsWith("/")) {
				resource = resource + "/";
			}
			return (getResourcePattern().matcher(resource).matches()) && (getActionPattern().matcher(action).matches());
		}
		return false;
	}

	public String toString() {
		return getRoleName() + ";" + this.resourcePattern + ";" + this.actionPattern + ";" + (getCustomAuthorizor() != null ? getCustomAuthorizor() : "");
	}

	private Pattern buildResourceRegex(String input) {
		boolean appendWildcard = false;
		if (input.endsWith("*")) {
			appendWildcard = true;
			input = input.substring(0, input.length() - 1);
		}
		if (input.length() > 0) {
			if (!input.endsWith("/")) {
				input = input + "/";
			}
			input = Pattern.quote(input);
		}
		if (appendWildcard) {
			input = input + ".*";
		}
		return Pattern.compile(input);
	}

	private Pattern buildActionRegex(String input) {
		if ("*".equals(input)) {
			input = ".*";
		}
		else {
			input = Pattern.quote(input);
		}
		return Pattern.compile(input);
	}
}
/* Location:              F:\MES Folders\Downloads\css-7.0.0.jar!\com\fedex\security\server\RegexRule.class
 * Java compiler version: 7 (51.0)
 * JD-Core Version:       0.7.1
 */