using System;
using System.IO;
using Microsoft.Extensions.Logging;
using XboxWebApi.Authentication;
using XboxWebApi.Authentication.Model;

namespace XboxWebApi.Cli
{
    class Program
    {
        static ILogger logger = XboxWebApi.Common.Logging.Factory.CreateLogger<Program>();
        static void Main(string[] args)
        {
            string tokenOutputFilePath = null;
            string responseUrl = null;
            string requestUrl = AuthenticationService.GetWindowsLiveAuthenticationUrl();

            if (args.Length < 1)
            {
                Console.WriteLine("1) Open following URL in your WebBrowser:\n\n{0}\n\n" +
                                    "2) Authenticate with your Microsoft Account\n" +
                                    "3) Execute application again with returned URL from addressbar as the argument\n", requestUrl);
                return;
            }

            if (args.Length == 2)
            {
                tokenOutputFilePath = args[1];
            }

            responseUrl = args[0];

            WindowsLiveResponse response = AuthenticationService.ParseWindowsLiveResponse(responseUrl);
            AuthenticationService authenticator = new AuthenticationService(response);

            bool success = authenticator.AuthenticateAsync().GetAwaiter().GetResult();
            if (!success)
            {
                Console.WriteLine("Authentication failed!");
                return;
            }

            if (tokenOutputFilePath != null)
            {
                success = authenticator.DumpToJsonFileAsync(tokenOutputFilePath).GetAwaiter().GetResult();
                if (!success)
                {
                    Console.WriteLine("Failed to dump tokens to {}", tokenOutputFilePath);
                }
            }

            Console.WriteLine(authenticator.XToken);
            Console.WriteLine(authenticator.UserInformation);
        }
    }
}
