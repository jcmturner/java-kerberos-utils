package uk.co.jtnet.security.kerberos;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.File;
import java.net.URISyntaxException;

import org.junit.Test;

public class Krb5ConfigureTest {

	@Test
	public void classPathURL() {
		try {
			Krb5Configure.init("classpath:krb5.conf");
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		String krb5ConfTmpOutput = System.getProperty("kerb.krb5Conf.tmp.path", 
				System.getProperty("java.io.tmpdir") + File.separator + "krb5.conf");
		assertEquals(krb5ConfTmpOutput, System.getProperty("java.security.krb5.conf"));
		File f = new File(System.getProperty("java.security.krb5.conf"));
		assertTrue(f.exists() && !f.isDirectory());
	}

}
