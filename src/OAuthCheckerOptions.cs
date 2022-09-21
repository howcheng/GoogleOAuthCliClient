using System;

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
		public string Path
		{
			get => _path;
			set => _path = value;
		}
		private string _path = $"{Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)}\\{nameof(OAuthChecker)}";
	}
}
