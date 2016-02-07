package uk.co.jtnet.security;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.annotation.WebFilter;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@WebFilter("/DenyFilter")
public class DenyFilter implements Filter {
	
	private static final Logger LOG = LoggerFactory.getLogger(DenyFilter.class);

    public DenyFilter() {
        
    }

	public void destroy() {
	
	}

	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
		HttpServletRequest httpRequest = (HttpServletRequest) request;
		HttpSession session = httpRequest.getSession(false);
		if (session != null){
			chain.doFilter(request, response);
		} else {
			LOG.info("User has no session. Sending HTTP/401");
			unauthorizedResponse(response);
		}		
	}

	public void init(FilterConfig fConfig) throws ServletException {
		
	}
	
	private void unauthorizedResponse(ServletResponse response) throws IOException {
		HttpServletResponse httpResponse = (HttpServletResponse) response;
		httpResponse.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
	}

}
