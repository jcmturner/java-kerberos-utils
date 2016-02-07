package uk.co.jtnet.security.kerberos;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.net.URISyntaxException;
import java.util.Date;

import javax.security.auth.Subject;

import org.junit.Before;
import org.junit.Test;

import uk.co.jtnet.security.Identity;

public class Krb5ServerHelperTest {
	
	//Client Side details
	private String clientDomain="JTTEST1.CO.UK";
	private String clientUsername="testuserone";
	private String clientPrincipal = clientUsername + "@" + clientDomain;
	private String clientKeytab = "file:" + KeytabConfigure.init(clientPrincipal, "classpathfile:testUserOne-jttest1.keytab");
	
	//Server side details
	private String serviceUsername = "servicetestone";
	private String serviceDomain = "JTTEST1.CO.UK";
	private String serviceAccount = serviceUsername + "@" + serviceDomain;
	private String serviceKeytab = "file:" + KeytabConfigure.init(serviceAccount, "classpathfile:serviceTestOne-jttest1.keytab");
	private String servicePrincipalNameAtFormat = "HTTP@testspn.jttest1.co.uk";
	private String servicePrincipalNameSlashFormat = "HTTP/testspn.jttest1.co.uk";
	
	private String krb5Conf = "classpathfile:krb5.conf";
	
	private Krb5ClientHelper krb5ClientHelper;
	private Krb5ServerHelper krb5ServerHelper;
	private Subject clientSubject;
	private byte[] serviceTicket;

	@Before
	public void setup(){
		System.setProperty("log4j.configuration", "file:src/main/resources/log4j.xml");
		//System.setProperty("sun.security.krb5.debug", "true");  <-- does not work. needs to be set in the run config.
		//Krb5Configure.init(krb5Conf);
		try {
			Krb5Configure.init(krb5Conf);
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		this.krb5ServerHelper = new Krb5ServerHelper(servicePrincipalNameAtFormat, serviceAccount, serviceKeytab);
		//Do the client bit
		krb5ClientHelper = new Krb5ClientHelper(clientPrincipal);
		clientSubject = krb5ClientHelper.krb5KeytabLogin(clientKeytab);
		serviceTicket = krb5ClientHelper.requestServiceTicket(clientSubject, servicePrincipalNameAtFormat);
	}

	@Test
	public void getClientDetails() throws Exception{
		Identity clientIdentity = krb5ServerHelper.getClientIdentity(serviceTicket);
		System.out.println(clientIdentity.toString());
		assertEquals("Username - Expected: " + clientUsername + " Actual: " +  clientIdentity.getUsername(), clientUsername, clientIdentity.getUsername());
		assertEquals("Realm - Expected: " + clientDomain + " Actual: " +  clientIdentity.getRealm(), clientDomain, clientIdentity.getRealm());
		assertNotNull("Full name: " + clientIdentity.getAttribute("fullName"), clientIdentity.getAttribute("fullName"));
		assertNotNull("Authentication time: " + clientIdentity.getAuthenticationDateTime().toString(), clientIdentity.getAuthenticationDateTime());
		assertTrue("End time: " + ((Date)clientIdentity.getAttribute("endTime")).toString(), ((Date)clientIdentity.getAttribute("endTime")).after(new Date()));
		assertNotNull(clientIdentity.getAttribute("clientAddress"));
		assertNotNull(clientIdentity.getAttribute("pac"));
		
	}

}
