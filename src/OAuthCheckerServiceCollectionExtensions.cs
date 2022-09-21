using System;
using GoogleOAuthCliClient;

namespace Microsoft.Extensions.DependencyInjection
{
	public static class OAuthCheckerServiceCollectionExtensions
	{
		public static IServiceCollection AddOAuthChecker(this IServiceCollection services) => AddOAuthChecker(services, null);

		public static IServiceCollection AddOAuthChecker(this IServiceCollection services, Action<OAuthCheckerOptions> configureAction)
		{
			OAuthCheckerOptions options = new OAuthCheckerOptions();
			if (configureAction != null)
				configureAction(options);

			return services.AddSingleton(Options.Options.Create(options));
		}
	}
}
