package uk.co.jtnet.security.kerberos;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

import java.net.URISyntaxException;
import java.util.Set;

import javax.security.auth.Subject;
import javax.security.auth.kerberos.KerberosPrincipal;

import org.junit.Before;
import org.junit.Test;

public class Krb5ClientHelperTest {


	private String testDomain="JTTEST1.CO.UK";
	private String testUsername="servicetestone";
	private String testPassword="Pa55word";
	private String testBadUsername="BADsystestclient";
	private String testBadPassword="BADPassword";
	private String clientPrincipal = testUsername + "@" + testDomain;
	private String serviceAccount = testUsername + "@" + testDomain;
	private String servicePrincipalNameAtFormat = "HTTP@testspn.jttest1.co.uk";
	private String servicePrincipalNameSlashFormat = "HTTP/testspn.jttest1.co.uk";
	private String krb5Conf = "classpathfile:krb5.conf";
	private String keytab = "classpathfile:serviceTestOne-jttest1.keytab";
	private String keytabPath;
	

	private Krb5ClientHelper krb5ClientHelper;

	@Before
	public void setup(){
		System.setProperty("log4j.configuration", "file:src/main/resources/log4j.xml");
		//System.setProperty("sun.security.krb5.debug", "true");  <-- does not work. needs to be set in the run config.
		try {
			Krb5Configure.init(krb5Conf);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		keytabPath = "file:" + KeytabConfigure.init(clientPrincipal, keytab);
		this.krb5ClientHelper = new Krb5ClientHelper(clientPrincipal);
	}

	@Test
	public void clientPasswordloginSuccess() {
		Subject clientSubject = krb5ClientHelper.krb5PasswordLogin(testPassword);
		KerberosPrincipal testingPrincipal = new KerberosPrincipal(clientPrincipal, KerberosPrincipal.KRB_NT_PRINCIPAL);
		Set<KerberosPrincipal> principals  = clientSubject.getPrincipals(KerberosPrincipal.class);
		assertTrue(principals.contains(testingPrincipal));
		assertEquals(krb5ClientHelper.principalNameFromSubject(clientSubject), clientPrincipal);
	}

	@Test
	public void clientPasswordloginBadPasssword() {
		Subject clientSubject = krb5ClientHelper.krb5PasswordLogin(testBadPassword);
		assertNull(clientSubject);
	}

	/*@Test
	public void clientUsernamePasswordloginBadUsername() {
		Subject clientSubject = krb5ClientHelper.krb5PasswordLogin(testPassword);
		assertNull(clientSubject);
	}*/

	@Test
	public void keytabClientLogin() {
		Subject clientSubject = krb5ClientHelper.krb5KeytabLogin(keytabPath);
		assertEquals(krb5ClientHelper.principalNameFromSubject(clientSubject), clientPrincipal);
	}

	@Test
	public void requestServiceTicketAtFormatSPN() {
		Subject clientSubject = krb5ClientHelper.krb5KeytabLogin(keytabPath);
		byte[] serviceTicket = krb5ClientHelper.requestServiceTicket(clientSubject, servicePrincipalNameAtFormat);
		assertNotNull(serviceTicket);
	}

	@Test
	public void requestServiceTicketSlashFormatSPN() {
		Subject clientSubject = krb5ClientHelper.krb5KeytabLogin(keytabPath);
		byte[] serviceTicket = krb5ClientHelper.requestServiceTicket(clientSubject, servicePrincipalNameSlashFormat);
		assertNotNull(serviceTicket);
	}

}
