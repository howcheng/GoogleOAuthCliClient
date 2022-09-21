using System.Threading.Tasks;

namespace GoogleOAuthCliClient
{
	public interface IOAuthChecker
	{
		string AccessToken { get; set; }

		void DoOAuth();
		Task<bool> IsOAuthRequired();
	}
}