package winsso;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import javax.security.auth.login.AppConfigurationEntry;
import javax.security.auth.login.Configuration;
import javax.servlet.http.HttpServletResponse;

import com.mendix.core.Core;
import com.mendix.m2ee.api.IMxRuntimeResponse;
import com.mendix.logging.ILogNode;

public class SSOConfiguration
{
	/** applications specific constants */
	private static String DOMAIN;
	private static String ACTIVE_DIRECTORY_SERVER;

	private static String KERBEROS_SERVERNAME;
	private static String KERBEROS_KEYTAB_FILE;
	
	private static String DEBUG;
	private static String KERBEROS_PROTOCOL = "http";
	
	/** SSO constants */
    private static final String KERBEROS_PATH = "sso/";
    private static final String FALLBACK_PATH = "../login-default.html";
    protected static final String LOGIN_MODULE_NAME = "MXWINLOGIN";

    private static Properties props = new Properties();
    protected static ILogNode log = null;
    private static Configuration jaasConfig = null;
    private static final String LOGNODE = "WinSSO";
    private static final String CONFIG_DIR = Core.getConfiguration().getResourcesPath().getAbsolutePath() + File.separator + "winsso" + File.separator;

	/** starts the Single Sign On servlet */
	public static void start()
	{
		if (log == null) {
			log = Core.getLogger(LOGNODE);
		}

		log.info("Initializing Single Sign On servlet");
		
		//read the configuration
		try {
			props.load(new FileInputStream(CONFIG_DIR + "sso.properties"));
			loadProperties();
		} catch(IOException e) {
			log.critical("Error reading 'sso.properties'", e);
		}
		initSystemProperties();
		
		try {
			Core.addRequestHandler(KERBEROS_PATH, new KerberosAuthenticator());
			log.info("Kerberos enabled");			
		} catch(Exception e) {
			log.error("Kerberos Authentication support unable to initialize: ", e);
		}
	}

	/** if true, debug output will be printed by several of the used protocols */ 
	public static boolean isDebug()
	{
		return "true".equals(DEBUG);
	}
	
	/**
	 * Kerberos authentication did not work, try NTLM or classic login 
	 * @param response
	 * @throws IOException
	 */
	protected static void fallbackFromKerberos(IMxRuntimeResponse response) throws IOException
	{
		redirect(response, SSOConfiguration.FALLBACK_PATH);
	}
	
	/** Sends a redirect (the redirect method provided by the class is less reliable */
	public static void redirect(IMxRuntimeResponse response, String path)
	{
		response.setStatus(HttpServletResponse.SC_SEE_OTHER);
		response.addHeader("location", path);	
	}
	
	/** Initialize some of the System kerberos related properties */
	static void initSystemProperties() 
	{
		System.setProperty("java.security.krb5.realm", DOMAIN.toUpperCase());
		System.setProperty("java.security.krb5.kdc", ACTIVE_DIRECTORY_SERVER);
		
		if (isDebug()) {
			System.setProperty("sun.security.krb5.debug", "true");
		}
	}

    /** Returns the login configuration used by Kerberos/ JAAS */
	protected static Configuration getJaasConfig()
	{
		if (jaasConfig == null)
		{
			final Map<String, Object> settings = new HashMap<String, Object>();
			settings.put("principal", String.format("%s/%s.%s", KERBEROS_PROTOCOL.toUpperCase(), KERBEROS_SERVERNAME, DOMAIN));
			settings.put("realm", DOMAIN.toUpperCase());
			settings.put("storeKey", "true");
			settings.put("useTicketCache", "false");
			settings.put("useSubjectCredsOnly", "false");
            settings.put("useKeyTab", "true");
			settings.put("keyTab", CONFIG_DIR + KERBEROS_KEYTAB_FILE);
			
			if (isDebug()) {
				settings.put("debug", "true");
			}

			jaasConfig = new Configuration() 
			{
				@Override
				public AppConfigurationEntry[] getAppConfigurationEntry(String name)
				{
					if (!LOGIN_MODULE_NAME.equals(name))
						log.error("Login module '" + name + "' not found!");
					return new AppConfigurationEntry[] { 
							new AppConfigurationEntry(
									com.sun.security.auth.module.Krb5LoginModule.class.getName(),
									AppConfigurationEntry.LoginModuleControlFlag.REQUIRED, settings) 
					};
				}
			};
		}
		return jaasConfig;
	}

	private static void loadProperties() 
	{
		DOMAIN 							= props.getProperty("domain");
		ACTIVE_DIRECTORY_SERVER 		= props.getProperty("active_directory_server");
		KERBEROS_SERVERNAME   		    = props.getProperty("kerberos_servername");
		KERBEROS_KEYTAB_FILE          	= props.getProperty("kerberos_keytab_file");
		KERBEROS_PROTOCOL 				= props.getProperty("kerberos_protocol","http");
		DEBUG 							= props.getProperty("debug","false");
	}
}
