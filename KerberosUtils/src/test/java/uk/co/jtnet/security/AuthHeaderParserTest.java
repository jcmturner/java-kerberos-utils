package uk.co.jtnet.security;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.assertEquals;

import java.io.IOException;
import java.util.Map;

import org.ietf.jgss.GSSException;
import org.junit.Test;

public class AuthHeaderParserTest {

	/*
	username@DOMAIN.COM:password
	dXNlcm5hbWVARE9NQUlOLkNPTTpwYXNzd29yZA==

	DOMAIN<backslash>username:password
    RE9NQUlOXHVzZXJuYW1lOnBhc3N3b3Jk

    DOMAIN/username:password
    RE9NQUlOL3VzZXJuYW1lOnBhc3N3b3Jk
	 */
	private String testUsername = "username";
	private String testRealm = "DOMAIN";
	private String testAtRealm = "DOMAIN.COM";
	private String testPassword = "password";
	private String AtSymbolRealmEncodedCredentials = "dXNlcm5hbWVARE9NQUlOLkNPTTpwYXNzd29yZA==";
	private String BackSlashRealmEncodedCredentials = "RE9NQUlOXHVzZXJuYW1lOnBhc3N3b3Jk";
	private String ForwardSlashRealmEncodedCredentials = "RE9NQUlOL3VzZXJuYW1lOnBhc3N3b3Jk";

	@Test
	public void AtSymbolRealmSeparator() throws Exception {
		TestHttpServletRequestAuthHeader testRequest = new 	TestHttpServletRequestAuthHeader();
		testRequest.setAuthorizationHeader(AtSymbolRealmEncodedCredentials);
		AuthHeaderParser authHeaderParser = new AuthHeaderParser(testRequest);
		assertTrue("Basic authentication detection when AT symbol separator used.", authHeaderParser.basicAuthUsed());
		Map<String, String> decodedCredentials  = authHeaderParser.getBasicAuthCredentials();
		assertEquals("Decoded realm when using AT symbol separator", testAtRealm, decodedCredentials.get("realm"));
		assertEquals("Decoded username when using AT symbol separator", testUsername, decodedCredentials.get("username"));
		assertEquals("Decoded password when using AT symbol separator", testPassword, decodedCredentials.get("password"));
	}

	@Test
	public void BackSlashRealmSeparator() throws Exception {
		TestHttpServletRequestAuthHeader testRequest = new 	TestHttpServletRequestAuthHeader();
		testRequest.setAuthorizationHeader(BackSlashRealmEncodedCredentials);
		AuthHeaderParser authHeaderParser = new AuthHeaderParser(testRequest);
		assertTrue("Basic authentication detection when AT symbol separator used.", authHeaderParser.basicAuthUsed());
		Map<String, String> decodedCredentials  = authHeaderParser.getBasicAuthCredentials();
		assertEquals("Decoded realm when using back slash separator", testRealm, decodedCredentials.get("realm"));
		assertEquals("Decoded username when using back slash separator", testUsername, decodedCredentials.get("username"));
		assertEquals("Decoded password when using back slash separator", testPassword, decodedCredentials.get("password"));
	}

	@Test
	public void ForwardSlashRealmSeparator() throws Exception {
		TestHttpServletRequestAuthHeader testRequest = new 	TestHttpServletRequestAuthHeader();
		testRequest.setAuthorizationHeader(ForwardSlashRealmEncodedCredentials);
		AuthHeaderParser authHeaderParser = new AuthHeaderParser(testRequest);
		assertTrue("Basic authentication detection when AT symbol separator used.", authHeaderParser.basicAuthUsed());
		Map<String, String> decodedCredentials  = authHeaderParser.getBasicAuthCredentials();
		assertEquals("Decoded realm when using forward slash separator", testRealm, decodedCredentials.get("realm"));
		assertEquals("Decoded username when using forward slash separator", testUsername, decodedCredentials.get("username"));
		assertEquals("Decoded password when using forward slash separator", testPassword, decodedCredentials.get("password"));
	}
	
	@Test
	public void SpnegoToken(){
		
	}

}
