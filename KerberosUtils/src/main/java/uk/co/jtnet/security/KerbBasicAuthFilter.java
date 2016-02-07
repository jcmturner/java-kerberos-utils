package uk.co.jtnet.security;

import java.io.IOException;
import java.util.Map;

import javax.security.auth.Subject;
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

import uk.co.jtnet.security.kerberos.Krb5ClientHelper;
import uk.co.jtnet.security.kerberos.Krb5ServerHelper;

/**
 * Servlet Filter implementation class KerbBasicAuthFilter
 */
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
public class KerbBasicAuthFilter implements Filter {

	private static final Logger LOG = LoggerFactory.getLogger(KerbBasicAuthFilter.class);

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
	public KerbBasicAuthFilter() {
		// TODO Auto-generated constructor stub
	}

	/**
	 * @see Filter#destroy()
	 */
	public void destroy() {
		// TODO Auto-generated method stub
	}

	/**
	 * @see Filter#doFilter(ServletRequest, ServletResponse, FilterChain)
	 */
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		Map<String, String> decodedCredentials = null;
		try {
			AuthHeaderParser authHeaderParser = new AuthHeaderParser(request);
			if (authHeaderParser.basicAuthUsed()){
				LOG.debug("Basic authentication used.");
				decodedCredentials = authHeaderParser.getBasicAuthCredentials();
				if (decodedCredentials != null){
					LOG.info("Authentication attempt via basic authentication: Realm: " + decodedCredentials.get("realm") + " Username: " + decodedCredentials.get("username"));
					String username = decodedCredentials.get("clientPrincipal");
					Krb5ClientHelper krb5ClientHelper = new Krb5ClientHelper((String) username);
					Subject clientSubject = krb5ClientHelper.krb5PasswordLogin((String) decodedCredentials.get("password"));
					byte[] serviceTicket = krb5ClientHelper.requestServiceTicket(clientSubject, SPN);
					if (clientSubject != null){
						//Authentication has succeeded.
						HttpSession session = ((HttpServletRequest) request).getSession();
						session.setAttribute("username", username);
						Identity clientIdentity = krb5ServerHelper.getClientIdentity(serviceTicket);
						if (clientIdentity != null){
							//Authentication has succeeded, move on to next filter
							LOG.info("Authentication successfull for User: " + clientIdentity.getUsername());
							session.setAttribute("identity", clientIdentity);
						} else {
							//In theory we should never end up here.
							LOG.warn("Unable to get further client identity information following basic authentication.");
							Identity basicIdentity = new Identity(username, decodedCredentials.get("realm"));
							session.setAttribute("identity", basicIdentity);
						}
						chain.doFilter(request, response);
					} else {
						//Authentication has been attempted and failed.
						unauthorizedResponse(response);
					}
				} else {
					//Not sure we will ever end up here but authorization details have not been provided correctly.
					unauthorizedResponse(response);
				}
			} else {
				//Basic authentication has not been used. 
				if (fallback){
					chain.doFilter(request, response);
				} else {
					unauthorizedResponse(response);
				}

			}
		} catch (Exception e) {
			//Send 401 as authorization header could not be parsed.
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
		httpResponse.setHeader("WWW-Authenticate", "Basic realm=\"" + SPN + "\"");
		httpResponse.sendError(401, "Unauthorized");
	}


}
