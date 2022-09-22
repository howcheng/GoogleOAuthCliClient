using System.Threading.Tasks;

namespace GoogleOAuthCliClient
{
	public interface IOAuthChecker
	{
		string AccessToken { get; set; }

		Task DoOAuth();
		Task<bool> IsOAuthRequired();
	}
}