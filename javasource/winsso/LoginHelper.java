package winsso;

import javax.servlet.http.HttpServletResponse;

import com.mendix.core.Core;
import com.mendix.m2ee.api.IMxRuntimeRequest;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.systemwideinterfaces.core.IContext;
import com.mendix.systemwideinterfaces.core.ISession;
import com.mendix.systemwideinterfaces.core.IUser;

/**
 * Helper class, which is used to create a Mendix Session, which avoids an additional round trip to the client
 * Based on XAS 2.4 com.mendix.core.action.{client/user}.LoginAction
 * 
 * @author Michel Weststrate
 *
 */
class LoginHelper
{

	/** based on xas2.5 */
	private static final String XAS_SESSION_ID = "XASSESSIONID";
	private static final String CONTINUATION_PARAMETER = "cont";
	private static final String XAS_ID = "XASID";
	private static final String OriginURI = "originURI";
	private static final String OriginURIValue = "index.html";
	private static final String INDEX_PAGE_CONSTANT = "WinSSO.IndexPage";
	private static final String UNKNOWN_USER_URL = "WinSSO.UnknownUserPage";	
	 public static final int SECONDS_PER_YEAR = 60*60*24*365;

	
	/** 
	 * this method can be used to initialize an XAS session when the username is known and verified. 
	 * @param request
	 * @param response
	 * @param username
	 * @throws Exception 
	 */
	protected static void createSession(IMxRuntimeRequest request, IMxRuntimeResponse response, String username) throws Exception {
		try {
			IContext context = Core.createSystemContext();
	
			String cookie = request.getParameter(XAS_SESSION_ID);
			if (cookie == null ||  cookie.isEmpty())
				cookie = null;
			
			IUser user = Core.getUser(context, username);
			
			//unknown user?
			if (user == null) {
				String unknownURL = String.valueOf(Core.getConfiguration().getConstantValue(UNKNOWN_USER_URL)) + username;
				if (!unknownURL.startsWith("http"))
					unknownURL = "../" + unknownURL;
				SSOConfiguration.log.info("Kerberos: unknown user: '" + username + "' redirecting to: '" + unknownURL + "'");
				SSOConfiguration.redirect(response, unknownURL);
				return;
			}

			//known user
			ISession session = Core.initializeSession(user , cookie);
		
			//no existing session found, perform login using the provided username
			if (session != null) 
			{
				/** create cookies and redirect: String key, String value, String path, String domain, int expiry */
				response.addCookie(XAS_SESSION_ID, session.getId().toString(), "/", "", -1);
				response.addCookie(XAS_ID, "0."+String.valueOf(Core.getXASId()),"/", "", -1);
				response.addCookie(OriginURI, OriginURIValue, "/","",SECONDS_PER_YEAR);
				SSOConfiguration.log.info("User '" +username + "' has been authenticated using Single Sign On");
				
				Object indexconfig = Core.getConfiguration().getConstantValue(INDEX_PAGE_CONSTANT);
				String indexpage = "../index.html";
				if (indexconfig != null && !indexconfig.toString().trim().isEmpty())
					indexpage = "../" + indexconfig.toString().trim();
				
				String continuation = request.getParameter(CONTINUATION_PARAMETER);
				if (continuation != null && !continuation.trim().isEmpty())
					indexpage = "../" + continuation.trim();
				
				SSOConfiguration.redirect(response, indexpage);
			}
			else
				throw new Exception("No session received from Core");
		}
		catch (Exception e) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			throw new Exception("Single Sign On unable to create new session: " + e.getMessage());
		}
	}
}
