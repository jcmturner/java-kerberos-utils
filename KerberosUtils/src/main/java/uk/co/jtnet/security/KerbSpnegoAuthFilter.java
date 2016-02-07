package uk.co.jtnet.security;

import java.io.IOException;
import java.util.Map;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.annotation.WebInitParam;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import uk.co.jtnet.security.kerberos.Krb5ServerHelper;

@WebFilter(
		urlPatterns = { "/*" }, 
		initParams = { 
				@WebInitParam(name = "defaultRealm", value = "JTLAN.CO.UK", description = "realm assumed if not passed when using basic authentication"),
				@WebInitParam(name = "keytab", value = "server.keytab", description = "location of keytab file"),
				@WebInitParam(name = "SPN", value = "HTTP/my.spn.test", description = "SPN for the server"),
				@WebInitParam(name = "serviceAccount", value = "systestaccount1@JTTEST1.CO.UK", description = "SPN for the server"),
				@WebInitParam(name = "java.security.krb5.conf", value = "/home/turnerj/git/servlet-security-filter/KerberosSecurityFilter/src/main/resources/krb5.conf", description = "krb5.conf file"),
				@WebInitParam(name = "fallback", value = "true")
		})
public class KerbSpnegoAuthFilter implements Filter {

	private static final Logger LOG = LoggerFactory.getLogger(KerbSpnegoAuthFilter.class);
	
	private String defaultRealm = "";
	private String keytab = "";
	private String SPN = "";
	private String krb5Conf;
	private String serviceAccount;
	private Boolean fallback = false;
	private Krb5ServerHelper krb5ServerHelper;

	/**
	 * Default constructor. 
	 */
	public KerbSpnegoAuthFilter() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
		// TODO Auto-generated method stub
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		Map<String, Object> decodedCredentials = null;
		try {
			AuthHeaderParser authHeaderParser = new AuthHeaderParser(request);
			if (authHeaderParser.spnegoAuthUsed()){
				LOG.debug("Spnego authentication used.");
				decodedCredentials = authHeaderParser.getSpnegoAuthCredentials();
				if (decodedCredentials != null){
					LOG.info("Authentication attempt via spnego authentication");
					byte[] serviceTicket = (byte[]) decodedCredentials.get("serviceTicket");
					Identity clientIdentity = krb5ServerHelper.getClientIdentity(serviceTicket);
					if (clientIdentity != null){
						//Authentication has succeeded, move on to next filter
						String username = clientIdentity.getUsername();
						LOG.info("Authentication successfull for User: " + clientIdentity.getUsername());
						HttpSession session = ((HttpServletRequest) request).getSession();
						session.setAttribute("username", username);
						session.setAttribute("identity", clientIdentity);
						chain.doFilter(request, response);
					} else {
						//Authentication has been attempted and failed.
						LOG.debug("Authentication failure, invalid kerberos credentials.");
						unauthorizedResponse(response);
					}
				} else {
					//Not sure we will ever end up here but authorization details have not been provided correctly.
					LOG.debug("Authentication failure, invalid details provided");
					unauthorizedResponse(response);
				}
			} else {
				//Basic authentication has not been used. 
				if (fallback){
					LOG.debug("Fallback configured. Proceeding to next filter. Spnego filter has NOT performed authentication as Spnego details were not provided");
					chain.doFilter(request, response);
				} else {
					LOG.debug("Spnego details not provided and fallback not set to true. Insisting on credential information. Sending HTTP/401");
					unauthorizedResponse(response);
				}
				
			}
		} catch (Exception e) {
			//Send 401 as authorization header could not be parsed.
			LOG.debug("Exception occurred in checking credntials. Failing secure. Sending HTTP/401");
			unauthorizedResponse(response);
		}
	}



	public void init(FilterConfig fConfig) throws ServletException {
		LOG.info("Kerberos filter initiated");
		if (fConfig.getInitParameter("defaultRealm") != null){
			defaultRealm = fConfig.getInitParameter("defaultRealm");
			LOG.info("Default realm: " + defaultRealm);
		} else {
			LOG.warn("No default realm configured");
		}
		
		if (fConfig.getInitParameter("keytab") != null){
			keytab = fConfig.getInitParameter("keytab");
			LOG.info("Keytab File: " + keytab);
		} else {
			LOG.error("No keytab file configured");
			throw new ServletException("No keytab configured");
		}
		
		if (fConfig.getInitParameter("SPN") != null){
			SPN = fConfig.getInitParameter("SPN");
			LOG.info("SPN: " + SPN);
		} else {
			LOG.error("SPN not configured");
			throw new ServletException("SPN not configured");
		}
		
		if (fConfig.getInitParameter("serviceAccount") != null){
			serviceAccount = fConfig.getInitParameter("serviceAccount");
			LOG.info("serviceAccount: " + serviceAccount);
		} else {
			LOG.error("serviceAccount not configured");
			throw new ServletException("serviceAccount not configured");
		}
		
		if (fConfig.getInitParameter("java.security.krb5.conf") != null){
			krb5Conf = fConfig.getInitParameter("java.security.krb5.conf");
			System.setProperty("java.security.krb5.conf", krb5Conf);
			LOG.info("krb5.conf: " + System.getProperty("java.security.krb5.conf"));
		} else {
			LOG.warn("krb5.conf not explicitly defined. Host's configuration file will be used");
		}
		if (fConfig.getInitParameter("fallback") != null){
			String fallbackInit = fConfig.getInitParameter("fallback");
			if (fallbackInit.equalsIgnoreCase("yes")) {
			    fallback = true;
			} else {
				fallback = Boolean.valueOf(fallbackInit);
			}
		}
		this.krb5ServerHelper = new Krb5ServerHelper(SPN, serviceAccount, keytab);
	}

	private void unauthorizedResponse(ServletResponse response) throws IOException {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		httpResponse.setHeader("WWW-Authenticate", "Negotiate");
		httpResponse.sendError(401, "Unauthorized");
		//TODO need to do more on the negotiation headers. See: https://msdn.microsoft.com/en-us/library/ms995330.aspx
		//ftp://ftp.software.ibm.com/software/integration/datapower/library/prod_docs/Misc/UnderstandingSPNEGO-v1.pdf
	}

}
