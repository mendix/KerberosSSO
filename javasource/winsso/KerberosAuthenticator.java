package winsso;

import java.io.File;
import java.io.IOException;
import java.security.PrivilegedAction;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;

import javax.security.auth.Subject;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.auth.login.LoginContext;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.io.FileUtils;
import org.apache.commons.lang3.StringEscapeUtils;
import org.ietf.jgss.GSSContext;
import org.ietf.jgss.GSSCredential;
import org.ietf.jgss.GSSException;
import org.ietf.jgss.GSSManager;
import org.ietf.jgss.Oid;

import com.mendix.core.Core;
import com.mendix.externalinterface.connector.RequestHandler;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.ISession;

/**
 * This authenticator tries to determine the current user based on a kerberos token send by the browsers
 * @author Michel Weststrate
 * @copyright Mendix
 *
 */
public class KerberosAuthenticator extends RequestHandler  
{
	private static final String HTML_CONTENT = "text/html";
	private static final String ENCODING = "UTF-8";
	private static final String XAS_ID = "XASID";
	private String fallbackloginLocation = emptyStringToNull((String) Core.getConfiguration().getConstantValue("WinSSO.FallbackPage"));
	private static final String ARGUSER = "username";
	private static final String ARGPASS = "password";
	
	private Subject loginsubject = null; 
	Oid spnegoOid = null;
	GSSManager manager = null;


	@Override
	public void processRequest(IMxRuntimeRequest arg0, IMxRuntimeResponse arg1,
			String arg2) throws Exception {
		this.doGet(arg0, arg1, false);		
	}
	
	protected void doGet(IMxRuntimeRequest request, IMxRuntimeResponse response, boolean retry) throws Exception
	{
		String auth = request.getHeader("Authorization");
		String clientName = "";
		
		if (auth == null) {
			response.addHeader("WWW-Authenticate", "NEGOTIATE");
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		try
		{
			SSOConfiguration.log.info("Kerberos: trying to authenticate session");
			clientName = authenticate(auth);
			SSOConfiguration.log.info("Kerberos: restoring session for user: "+clientName);
			String username = clientName.substring(0, clientName.indexOf('@'));
			try {
				LoginHelper.createSession(request, response, username);
			}
			catch(Exception e) {
				SSOConfiguration.log.error("Unable to create session: " + e.getMessage());
				return;
			}
		}
		catch (Exception e)
		{
			//Invalid token, probably an NTLM token, fallback
			if (e.getCause() instanceof GSSException) 
			{
				GSSException e2 = (GSSException) e.getCause();
				if (e2.getMajor() == GSSException.DEFECTIVE_TOKEN) 
				{
					SSOConfiguration.log.warn("Kerberos error: invalid token " + auth + " ("+e2.getMinorString()+"), falling back to alternative authentication mechanism");
					serveLogin(request,response, "Sign in with a local account");
					return;
				}
			}

			if (!retry) { //maybe the ticket has expired?
				SSOConfiguration.log.info("Unable to authenticate, recreating login subject.");
				try {
					createServiceSubject();
					SSOConfiguration.log.info("Finished recreating login subject");
				} catch (Exception e1) {
					SSOConfiguration.log.error("Unable to recreate login subject");
				}				
				this.doGet(request, response,true);//true avoids recursion
				return;
			}
			
			if (SSOConfiguration.isDebug())
				SSOConfiguration.log.error("Error while trying to authenticate using kerberos, token: " + auth, e);
			else
				SSOConfiguration.log.error("Error while trying to authenticate using kerberos, token: " + auth + "\n message: "+e.getMessage());
			
			ISession session = this.getSessionFromRequest(request);
			
			if (request.getParameter(ARGUSER)!= null && request.getParameter(ARGPASS) != null) {

            	if ( session == null ) 
            		Core.getLogger("Kerberos").debug("No session found for deeplink: " + request.getResourcePath() + ", attempting login.");
            	else	
            		Core.getLogger("Kerberos").debug("Using session from request: '" + session.getId().toString() + "' for deeplink: " + request.getResourcePath());
        			
            	session = performLogin(request, response);
            	
            	if(session != null)
            		LoginHelper.createSession(request, response, request.getParameter(ARGUSER));
            	else
            		serveLogin(request,response, "The username or password you entered is incorrect");
            }
			else
			{
				serveLogin(request,response, "Sign in with a local account");
			}
		}
	}

	/**
	 * Authenticates the given kerberos token and returns the client principal
	 */
	public String authenticate(String argKerberosTokenAsBase64) throws Exception 
	{
		String token = argKerberosTokenAsBase64.substring("Negotiate ".length());
		byte[] kerberosToken = Base64.decodeBase64(token.getBytes());
		
		// Login to the KDC and obtain subject for the service principal
		return acceptSecurityContext(loginsubject, kerberosToken);
	}
	
	
	/**
	 * Completes the security context initialization and returns the client
	 * name.
	 */
	private String acceptSecurityContext(final Subject argSubject,
			final byte[] serviceTicket) 
	{
		// Accept the context and return the client principal name.
		return (String) Subject.doAs(argSubject, new PrivilegedAction<String>() 
		{
			public String run() 
			{
				try 
				{
					GSSCredential serverGSSCreds = manager.createCredential(null, 
					        GSSCredential.INDEFINITE_LIFETIME, spnegoOid, GSSCredential.INITIATE_AND_ACCEPT);

					GSSContext context = manager.createContext(serverGSSCreds);
					while (!context.isEstablished())
					{
						context.acceptSecContext(serviceTicket, 0, serviceTicket.length);
					} 
					return context.getSrcName().toString();
				} 
				catch (GSSException exp) {
					throw new RuntimeException(exp);
				}
			}
		});
	}	

	//start, create necessary GSS objects
	public KerberosAuthenticator() 
	{
		SSOConfiguration.log.info("Starting Kerberos, creating login subject");
		try
		{
			createServiceSubject();
			
			manager = GSSManager.getInstance();
			spnegoOid = new Oid("1.3.6.1.5.5.2");
		}
		catch (Exception e)
		{
			SSOConfiguration.log.error("Unable to start Kerberos authenticator: ", e);
		}
	}
	
	/**
	 * Creates service subject based on the service principal and service
	 * password
	 */
	private void createServiceSubject() throws Exception 
	{
		LoginContext loginCtx = new LoginContext(SSOConfiguration.LOGIN_MODULE_NAME, null, new CallbackHandler()
		{
			@Override
			public void handle(Callback[] arg0) throws IOException,
					UnsupportedCallbackException
			{
				String s = "";
				for(Callback c : arg0)
					s+= "'"+c.getClass().getSimpleName()+"' ";
				throw new RuntimeException("Kerberos login: Received callback(s) for " + s + " please fix the configuration ");
			}
		}, SSOConfiguration.getJaasConfig());
		
		loginCtx.login();
		loginsubject = loginCtx.getSubject();
		
		if (loginsubject == null)
			throw new Exception("Unable to obtain kerberos service context");
	}
	
	/**
	 * Serves fallback login page when kerberos authentication fails 
	 */

	private void serveLogin(IMxRuntimeRequest request,
			IMxRuntimeResponse response, String result) throws IOException {
		String url = request.getResourcePath();
		String qs = request.getHttpServletRequest().getQueryString();
		if (url.startsWith("/")) {
			url = url.substring(1);
		}
		if (qs != null && !qs.equals("")) {
		    url = url + "?" + qs;
		}
			
		
		Map<String, String> args = new HashMap<String, String>();
		args.put("url", url);
		args.put("result", result);
		args.put("relpath", getRelPath(request));
		
		renderTemplate("login", args, response);
		response.setStatus(IMxRuntimeResponse.OK);
	}

	private ISession performLogin(IMxRuntimeRequest request,
			IMxRuntimeResponse response) throws Exception {
		String username = request.getParameter(ARGUSER);
		String password = request.getParameter(ARGPASS);
					
		try {
			ISession session =  Core.login(username, password);
			Core.getLogger("Kerberos").info("Login OK: user '" + username + "'");
			setCookies(response, session);
			return session;				
		}
		catch (Exception e) {
			Core.getLogger("Kerberos").warn("Login failed for '"  + username + "' : " + e.getMessage());
			return null;
		}
	}
	
	private void setCookies(IMxRuntimeResponse response, ISession session) {
		response.addCookie(getSessionCookieName(), session.getId().toString(),  "/", "", -1, true);
		response.addCookie(XAS_ID, "0."+Core.getXASId(),"/", "", -1, true);			 
	}
	
	private String getRelPath(IMxRuntimeRequest request) {
		String res = "";
		int length = request.getResourcePath().split("/").length +
			(request.getResourcePath().endsWith("/") ? 0 : -1);
		for(int i1 = 0; i1 < length; i1++)
			res+= "../";
		return res;
	}
	
	public void renderTemplate(String template, Map<String, String> params, IMxRuntimeResponse response) throws IOException
	{
		response.setContentType(HTML_CONTENT);
		response.setCharacterEncoding(ENCODING);
		response.getWriter().append(renderTemplate(template, params));
	}

	public String renderTemplate(String template, Map<String, String> params) throws IOException
	{
		String line = FileUtils.readFileToString(new File(Core.getConfiguration().getResourcesPath() + File.separator + this.fallbackloginLocation));
		if (params != null)
			for(String key : params.keySet())
				if (params.get(key) != null)
					line = line.replaceAll("\\{"+key.toUpperCase()+"\\}", Matcher.quoteReplacement(StringEscapeUtils.escapeHtml4(params.get(key))));
		return line;
	}
	
	static String emptyStringToNull(String value) {
		if (value == null)
			return null;
		
		if (value.trim().isEmpty())
			return null;
		if ("\"\"".equals(value) || "''".equals(value))
			return null;
		return value;
	}
	
}
