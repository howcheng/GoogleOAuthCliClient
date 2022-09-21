using System;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using Google.Apis.Auth.OAuth2;
using Google.Apis.Util.Store;
using Microsoft.Extensions.Options;

namespace GoogleOAuthCliClient
{
	/// <summary>
	/// Class that does an OAuth 2.0 authorization against Google for console applications. This was adapted from https://github.com/googlesamples/oauth-apps-for-windows/tree/master/OAuthConsoleApp.
	/// </summary>
	public class OAuthChecker : IOAuthChecker
	{
		private static Lazy<ClientSecret> s_ClientSecret;
		private ClientSecret Secret { get => s_ClientSecret.Value; }
		private readonly OAuthCheckerOptions _options;

		public string AccessToken { get; set; }
		private string OAuthTokenPath => $"{AppDataFolder}\\{_options.OAuthTokenFilename}";
		private string ClientSecretPath => $"{AppDataFolder}\\{_options.ClientSecretJsonFilename}";
		private string AppDataFolder => _options.Path;

		public OAuthChecker(IOptions<OAuthCheckerOptions> options)
		{
			_options = options.Value;
			s_ClientSecret = new Lazy<ClientSecret>(() =>
			{
				if (!File.Exists(ClientSecretPath))
					throw new InvalidOperationException("No client secrets file found!");

				using (FileStream stream = new FileStream($"{ClientSecretPath}", FileMode.Open, FileAccess.Read))
				using (StreamReader reader = new StreamReader(stream))
				{
					string json = reader.ReadToEnd();
					return JsonConvert.DeserializeObject<ClientSecret>(json);
				}
			});
		}

		/// <summary>
		/// Determines if OAuth authentication is required for the current session.
		/// </summary>
		/// <returns><c>true</c> if the </returns>
		public async Task<bool> IsOAuthRequired()
		{
			if (!File.Exists(OAuthTokenPath))
				return true;

			try
			{
				using (FileStream stream = new FileStream(OAuthTokenPath, FileMode.Open, FileAccess.Read))
				{
					OAuthResponse oauth = null;
					using (StreamReader reader = new StreamReader(stream))
					{
						string json = await reader.ReadToEndAsync();
						oauth = JsonConvert.DeserializeObject<OAuthResponse>(json);

						if (oauth.expiration >= DateTime.Now)
						{
							AccessToken = oauth.access_token;
							return false;
						}

						// try to refresh the access token
						string requestBody = $"client_id={Secret.installed.client_id}&client_secret={Secret.installed.client_secret}&refresh_token={oauth.refresh_token}&grant_type=refresh_token";
						OAuthResponse response = await DoTokenRequest(Secret.installed.token_uri, requestBody);

						oauth.access_token = response.access_token;
						oauth.expiration = response.expiration;
					}

					string tempPath = $"{OAuthTokenPath}.tmp";
					using (FileStream writeStream = new FileStream(tempPath, FileMode.Create, FileAccess.Write))
					using (StreamWriter writer = new StreamWriter(writeStream))
					{
						string json = JsonConvert.SerializeObject(oauth);
						await writer.WriteLineAsync(json);
					}

					File.Delete(OAuthTokenPath);
					File.Move(tempPath, OAuthTokenPath);
					return false;
				}
			}
			catch
			{
				return true;
			}
		}

		// ref http://stackoverflow.com/a/3978040
		public static int GetRandomUnusedPort()
		{
			var listener = new TcpListener(IPAddress.Loopback, 0);
			listener.Start();
			var port = ((IPEndPoint)listener.LocalEndpoint).Port;
			listener.Stop();
			return port;
		}

		public async void DoOAuth()
		{
			Console.WriteLine("+-----------------------+");
			Console.WriteLine("|  Sign in with Google  |");
			Console.WriteLine("+-----------------------+");
			Console.WriteLine("");
			Console.WriteLine("Press any key to sign in...");
			Console.ReadKey();

			// Generates state and PKCE values.
			string state = randomDataBase64url(32);
			string code_verifier = randomDataBase64url(32);
			string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
			const string code_challenge_method = "S256";

			// Creates a redirect URI using an available port on the loopback address.
			string redirectURI = string.Format("http://{0}:{1}/", IPAddress.Loopback, GetRandomUnusedPort());
			output("redirect URI: " + redirectURI);

			// Creates an HttpListener to listen for requests on that redirect URI.
			var http = new HttpListener();
			http.Prefixes.Add(redirectURI);
			output("Listening..");
			http.Start();

			// Creates the OAuth 2.0 authorization request.
			string authorizationRequest = string.Format("{0}?response_type=code&scope=openid%20profile&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
				Secret.installed.auth_uri,
				Uri.EscapeDataString(redirectURI),
				Secret.installed.client_id,
				state,
				code_challenge,
				code_challenge_method);

			// Opens request in the browser.
			System.Diagnostics.Process.Start(authorizationRequest);

			// Waits for the OAuth authorization response.
			var context = await http.GetContextAsync();

			// Brings the Console to Focus.
			BringConsoleToFront();

			// Sends an HTTP response to the browser.
			var response = context.Response;
			string responseString = string.Format("<html><head><meta http-equiv='refresh' content='10;url=https://google.com'></head><body>Please return to the app.</body></html>");
			var buffer = System.Text.Encoding.UTF8.GetBytes(responseString);
			response.ContentLength64 = buffer.Length;
			var responseOutput = response.OutputStream;
			Task responseTask = responseOutput.WriteAsync(buffer, 0, buffer.Length).ContinueWith((task) =>
			{
				responseOutput.Close();
				http.Stop();
				Console.WriteLine("HTTP server stopped.");
			});

			// Checks for errors.
			if (context.Request.QueryString.Get("error") != null)
			{
				output(String.Format("OAuth authorization error: {0}.", context.Request.QueryString.Get("error")));
				return;
			}
			if (context.Request.QueryString.Get("code") == null
				|| context.Request.QueryString.Get("state") == null)
			{
				output("Malformed authorization response. " + context.Request.QueryString);
				return;
			}

			// extracts the code
			var code = context.Request.QueryString.Get("code");
			var incoming_state = context.Request.QueryString.Get("state");

			// Compares the receieved state to the expected value, to ensure that
			// this app made the request which resulted in authorization.
			if (incoming_state != state)
			{
				output(String.Format("Received request with invalid state ({0})", incoming_state));
				return;
			}
			output("Authorization code: " + code);

			// Starts the code exchange at the Token Endpoint.
			performCodeExchange(code, code_verifier, redirectURI);

			Console.ReadKey();
		}

		async void performCodeExchange(string code, string code_verifier, string redirectURI)
		{
			output("Exchanging code for tokens...");

			// builds the  request
			string tokenRequestURI = Secret.installed.token_uri;
			string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&client_secret={4}&scope=&grant_type=authorization_code",
				code,
				System.Uri.EscapeDataString(redirectURI),
				Secret.installed.client_id,
				code_verifier,
				Secret.installed.client_secret
				);

			// sends the request
			OAuthResponse response = await DoTokenRequest(tokenRequestURI, tokenRequestBody);
			string responseJson = JsonConvert.SerializeObject(response);
			using (FileStream writeStream = new FileStream(OAuthTokenPath, FileMode.OpenOrCreate, FileAccess.Write))
			using (StreamWriter writer = new StreamWriter(writeStream))
			{
				writer.WriteLine(responseJson);
			}
		}

		private async Task<OAuthResponse> DoTokenRequest(string tokenRequestURI, string tokenRequestBody)
		{
			HttpWebRequest tokenRequest = (HttpWebRequest)WebRequest.Create(tokenRequestURI);
			tokenRequest.Method = "POST";
			tokenRequest.ContentType = "application/x-www-form-urlencoded";
			tokenRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
			byte[] _byteVersion = Encoding.ASCII.GetBytes(tokenRequestBody);
			tokenRequest.ContentLength = _byteVersion.Length;
			Stream stream = tokenRequest.GetRequestStream();
			await stream.WriteAsync(_byteVersion, 0, _byteVersion.Length);
			stream.Close();

			try
			{
				// gets the response
				WebResponse tokenResponse = await tokenRequest.GetResponseAsync();
				using (StreamReader reader = new StreamReader(tokenResponse.GetResponseStream()))
				{
					// reads response body
					string responseText = await reader.ReadToEndAsync();
					Console.WriteLine(responseText);

					// converts to dictionary
					Dictionary<string, string> tokenEndpointDecoded = JsonConvert.DeserializeObject<Dictionary<string, string>>(responseText);

					string access_token = tokenEndpointDecoded["access_token"];
					//userinfoCall(access_token);
					AccessToken = access_token;

					OAuthResponse response = new OAuthResponse
					{
						access_token = access_token,
						id_token = tokenEndpointDecoded.ContainsKey("id_token") ? tokenEndpointDecoded["id_token"] : null,
						refresh_token = tokenEndpointDecoded.ContainsKey("refresh_token") ? tokenEndpointDecoded["refresh_token"] : null,
						token_type = tokenEndpointDecoded.ContainsKey("token_type") ? tokenEndpointDecoded["token_type"] : null,
						expiration = DateTime.Now.AddSeconds(int.Parse(tokenEndpointDecoded["expires_in"]))
					};

					return response;
				}
			}
			catch (WebException ex)
			{
				if (ex.Status == WebExceptionStatus.ProtocolError)
				{
					var response = ex.Response as HttpWebResponse;
					if (response != null)
					{
						output("HTTP: " + response.StatusCode);
						using (StreamReader reader = new StreamReader(response.GetResponseStream()))
						{
							// reads response body
							string responseText = await reader.ReadToEndAsync();
							output(responseText);
						}
					}

				}
				throw;
			}
		}

		async void userinfoCall(string access_token)
		{
			output("Making API Call to Userinfo...");

			// builds the  request
			string userinfoRequestURI = "https://www.googleapis.com/oauth2/v3/userinfo";

			// sends the request
			HttpWebRequest userinfoRequest = (HttpWebRequest)WebRequest.Create(userinfoRequestURI);
			userinfoRequest.Method = "GET";
			userinfoRequest.Headers.Add(string.Format("Authorization: Bearer {0}", access_token));
			userinfoRequest.ContentType = "application/x-www-form-urlencoded";
			userinfoRequest.Accept = "Accept=text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";

			// gets the response
			WebResponse userinfoResponse = await userinfoRequest.GetResponseAsync();
			using (StreamReader userinfoResponseReader = new StreamReader(userinfoResponse.GetResponseStream()))
			{
				// reads response body
				string userinfoResponseText = await userinfoResponseReader.ReadToEndAsync();
				output(userinfoResponseText);
			}
		}

		/// <summary>
		/// Appends the given string to the on-screen log, and the debug console.
		/// </summary>
		/// <param name="output">string to be appended</param>
		public void output(string output)
		{
			Console.WriteLine(output);
		}

		/// <summary>
		/// Returns URI-safe data with a given input length.
		/// </summary>
		/// <param name="length">Input length (nb. output will be longer)</param>
		/// <returns></returns>
		public static string randomDataBase64url(uint length)
		{
			RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider();
			byte[] bytes = new byte[length];
			rng.GetBytes(bytes);
			return base64urlencodeNoPadding(bytes);
		}

		/// <summary>
		/// Returns the SHA256 hash of the input string.
		/// </summary>
		/// <param name="inputStirng"></param>
		/// <returns></returns>
		public static byte[] sha256(string inputStirng)
		{
			byte[] bytes = Encoding.ASCII.GetBytes(inputStirng);
			SHA256Managed sha256 = new SHA256Managed();
			return sha256.ComputeHash(bytes);
		}

		/// <summary>
		/// Base64url no-padding encodes the given input buffer.
		/// </summary>
		/// <param name="buffer"></param>
		/// <returns></returns>
		public static string base64urlencodeNoPadding(byte[] buffer)
		{
			string base64 = Convert.ToBase64String(buffer);

			// Converts base64 to base64url.
			base64 = base64.Replace("+", "-");
			base64 = base64.Replace("/", "_");
			// Strips padding.
			base64 = base64.Replace("=", "");

			return base64;
		}

		// Hack to bring the Console window to front.
		// ref: http://stackoverflow.com/a/12066376

		[DllImport("kernel32.dll", ExactSpelling = true)]
		public static extern IntPtr GetConsoleWindow();

		[DllImport("user32.dll")]
		[return: MarshalAs(UnmanagedType.Bool)]
		public static extern bool SetForegroundWindow(IntPtr hWnd);

		public void BringConsoleToFront()
		{
			SetForegroundWindow(GetConsoleWindow());
		}

		public UserCredential GetUserCredential(string scope)
		{
			using (FileStream stream = new FileStream(ClientSecretPath, FileMode.Open, FileAccess.Read))
			{
				UserCredential credential = GoogleWebAuthorizationBroker.AuthorizeAsync(
					GoogleClientSecrets.FromStream(stream).Secrets,
					new[] { scope },
					"user", System.Threading.CancellationToken.None, new FileDataStore($"{AppDataFolder}\\filedatastore", true)).Result;
				return credential;
			}
		}

		private class ClientSecret
		{
			public OAuthParameters installed { get; set; }
		}
		private class OAuthParameters
		{
			/// <summary>
			/// The client ID obtained from the API Console.
			/// </summary>
			public string client_id { get; set; }
			public string client_secret { get; set; }
			public string[] redirect_uris { get; set; }
			public string auth_uri { get; set; }
			public string token_uri { get; set; }
		}

		private class OAuthResponse
		{
			/// <summary>
			/// The token that your application sends to authorize a Google API request.
			/// </summary>
			public string access_token { get; set; }
			/// <summary>
			/// This property is only returned if your request included an identity scope, such as openid, profile, or email. The value is a JSON Web Token (JWT) that contains digitally signed identity information about the user.
			/// </summary>
			public string id_token { get; set; }
			/// <summary>
			/// A token that you can use to obtain a new access token. Refresh tokens are valid until the user revokes access. Note that refresh tokens are always returned for installed applications.
			/// </summary>
			public string refresh_token { get; set; }
			/// <summary>
			/// The remaining lifetime of the access token.
			/// </summary>
			public DateTime expiration { get; set; }
			/// <summary>
			/// The type of token returned. At this time, this field's value is always set to Bearer.
			/// </summary>
			public string token_type { get; set; }
		}
	}
}
