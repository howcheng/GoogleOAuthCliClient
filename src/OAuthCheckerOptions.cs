using System;
using System.Collections.Generic;

namespace GoogleOAuthCliClient
{
	public class OAuthCheckerOptions
	{
		/// <summary>
		/// Name of the file that contains the client secrets (default: "client_secret.json")
		/// </summary>
		public string ClientSecretJsonFilename { get; set; } = "client_secret.json";
		/// <summary>
		/// Name of the file that contains the OAuth token (default: "oauth_token.json")
		/// </summary>
		public string OAuthTokenFilename { get; set; } = "oauth_token.json";
		/// <summary>
		/// Path (relative or absolute) to the location of the <see cref="ClientSecretJsonFilename"/> and <see cref="OAuthTokenFilename"/> files
		/// (default: %APPDATA%\OAuthChecker)
		/// </summary>
		public string SecretsPath
		{
			get => _secretsPath;
			set => _secretsPath = value;
		}
		private string _secretsPath = $"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\\{nameof(OAuthChecker)}";

		/// <summary>
		/// Path (relative or absolute) to the browser application to open to begin the OAuth transaction. Defaults to Google Chrome (64-bit).
		/// </summary>
		public string BrowserPath 
		{
			get => _browserPath;
			set => _browserPath = value;
		}
		private string _browserPath = $"{Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles)}\\Google\\Chrome\\Application\\chrome.exe";

		/// <summary>
		/// Any command-line arguments to pass to the browser
		/// </summary>
		public string BrowserArguments { get; set; }

		public IList<string> Scopes { get; } = new List<string>();
	}
}
