package uk.co.jtnet.security;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.servlet.ServletRequest;
import javax.servlet.http.HttpServletRequest;

import org.ietf.jgss.GSSException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import sun.misc.BASE64Decoder;
import sun.security.jgss.spnego.NegTokenInit;

public class AuthHeaderParser {

	private static final Logger LOG = LoggerFactory.getLogger(AuthHeaderParser.class);
	private static final String basicAuthRegex = "Basic (.*)";
	private static final String spnegoAuthRegex = "Negotiate (.*)";
	private String authHeaderEncoded;
	private String base64AuthData;

	public AuthHeaderParser(ServletRequest request) throws Exception {
		this.authHeaderEncoded = ((HttpServletRequest)request).getHeader("Authorization");
		if (authHeaderEncoded == null){
			throw new Exception("No authentication header in request");
		}
	}

	public Boolean basicAuthUsed(){
		Pattern basicAuthPattern = Pattern.compile(basicAuthRegex, Pattern.CASE_INSENSITIVE);
		return authTypeMatcher(basicAuthPattern);
	}

	public Boolean spnegoAuthUsed(){
		Pattern spnegoAuthPattern = Pattern.compile(spnegoAuthRegex, Pattern.CASE_INSENSITIVE);
		return authTypeMatcher(spnegoAuthPattern);
	}

	private Boolean authTypeMatcher(Pattern authPattern){
		Matcher authMatcher = authPattern.matcher(authHeaderEncoded);
		if (authMatcher.find()){
			base64AuthData = authMatcher.group(1);
			return true;
		} else {
			return false;
		}	
	}

	public Map<String,Object> getSpnegoAuthCredentials() throws IOException, GSSException {
		BASE64Decoder decoder = new BASE64Decoder();
		byte[] spnegoTokenBytes = decoder.decodeBuffer(base64AuthData);
		NegTokenInit spnegoTokenInit = new NegTokenInit(spnegoTokenBytes);
		byte[] kerbServiceTicketBytes = spnegoTokenInit.getMechToken();
		Map<String,Object> credMap = new HashMap<String,Object>();
		credMap.put("mechanism", "kerberos");
		credMap.put("serviceTicket", kerbServiceTicketBytes);
		return credMap;
	}

	public Map<String,String> getBasicAuthCredentials() throws IOException {
		BASE64Decoder decoder = new BASE64Decoder();
		String authHeaderDecoded = new String(decoder.decodeBuffer(base64AuthData));
		Map<String,String> credMap = new HashMap<String,String>();
		Pattern usernamePassword = Pattern.compile("(.+?):(.+)");
		Matcher usernamePasswordMatcher = usernamePassword.matcher(authHeaderDecoded);
		if (usernamePasswordMatcher.find()){
			String username = usernamePasswordMatcher.group(1);
			String password = usernamePasswordMatcher.group(2);
			String realm = "blank";
			Pattern usernameRealmPattern = Pattern.compile("(.+)@(.+)");
			Matcher usernameRealmMatcher = usernameRealmPattern.matcher(username);
			if (usernameRealmMatcher.find()){
				LOG.debug("Realm specified using @");
				username = usernameRealmMatcher.group(1);
				realm = usernameRealmMatcher.group(2);
			} else {
				usernameRealmPattern = Pattern.compile("(.+)[/\\\\](.+)");
				usernameRealmMatcher = usernameRealmPattern.matcher(username);
				if (usernameRealmMatcher.find()){
					LOG.debug("Realm specified using slash");
					username = usernameRealmMatcher.group(2);
					realm = usernameRealmMatcher.group(1);
				}	    	
			}
			credMap.put("mechanism", "basic");
			credMap.put("username", username);
			credMap.put("realm", realm);
			credMap.put("clientPrincipal", username + realm.toUpperCase());
			credMap.put("password", password);
			String passwordMask = "<Password could not extracted from header>";
			if (password != null){
				passwordMask = "<masked>";
			}
			LOG.debug("Username: " + username + " ; Realm: " + realm + " ; Password: " + passwordMask);
		}
		return credMap;
	}

}
