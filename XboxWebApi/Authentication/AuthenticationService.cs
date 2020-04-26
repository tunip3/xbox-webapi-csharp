using System;
using System.IO;
using System.Collections.Specialized;
using Newtonsoft.Json;
using XboxWebApi.Common;
using XboxWebApi.Authentication.Model;
using System.Text;
using System.Threading.Tasks;
using System.Net.Http;
using System.Text.Encodings.Web;
using Microsoft.Extensions.Logging;

namespace XboxWebApi.Authentication
{
    public class AuthenticationService
    {
        static ILogger logger = Logging.Factory.CreateLogger<AuthenticationService>();
        public AccessToken AccessToken { get; set; }
        public RefreshToken RefreshToken { get; set; }
        public UserToken UserToken { get; set; }
        public DeviceToken DeviceToken { get; set; }
        public TitleToken TitleToken { get; set; }
        public XToken XToken { get; set; }
        public XboxUserInformation UserInformation { get; set; }

        public AuthenticationService()
        {
        }

        public AuthenticationService(WindowsLiveResponse wlResponse)
        {
            AccessToken = new AccessToken(wlResponse);
            RefreshToken = new RefreshToken(wlResponse);
        }

        public AuthenticationService(AccessToken accessToken, RefreshToken refreshToken)
        {
            AccessToken = accessToken;
            RefreshToken = refreshToken;
        }

        public static HttpClient ClientFactory(string baseUrl)
        {
            HttpClient client = new HttpClient();
            client.BaseAddress = new Uri(baseUrl.EndsWith("/") ? baseUrl : baseUrl + "/");
            return client;
        }

        public async Task<bool> AuthenticateAsync()
        {
            WindowsLiveResponse windowsLiveTokens = await RefreshLiveTokenAsync(RefreshToken);
            AccessToken = new AccessToken(windowsLiveTokens);
            RefreshToken = new RefreshToken(windowsLiveTokens);
            UserToken = await AuthenticateXASUAsync(AccessToken);
            XToken = await AuthenticateXSTSAsync(UserToken, DeviceToken, TitleToken);
            UserInformation = XToken.UserInformation;
            return true;
        }

        public static async Task<WindowsLiveResponse> RefreshLiveTokenAsync(
            RefreshToken refreshToken)
        {
            HttpClient client = ClientFactory("https://login.live.com/");

            var request = new HttpRequestMessage(HttpMethod.Get, "oauth20_token.srf");
            var parameters = new Model.WindowsLiveRefreshQuery(refreshToken);
            request.AddQueryParameter(parameters.GetQuery());
            
            var response = (await client.SendAsync(request)).EnsureSuccessStatusCode();
            return await response.Content.ReadAsJsonAsync<WindowsLiveResponse>(JsonNamingStrategy.SnakeCase);
        }

        public static async Task<UserToken> AuthenticateXASUAsync(AccessToken accessToken)
        {
            HttpClient client = ClientFactory("https://user.auth.xboxlive.com/");
            var request = new HttpRequestMessage(HttpMethod.Post, "user/authenticate");
            var requestBody = new XASURequest(accessToken);
            request.Content = new JsonContent(requestBody);
            request.Headers.Add("x-xbl-contract-version", "1");

            var response = (await client.SendAsync(request)).EnsureSuccessStatusCode();
            Console.WriteLine(await response.Content.ReadAsStringAsync());
            var data = await response.Content.ReadAsJsonAsync<XASResponse>();
            return new UserToken(data);
        }

        public static async Task<DeviceToken> AuthenticateXASDAsync(AccessToken accessToken)
        {
            HttpClient client = ClientFactory("https://device.auth.xboxlive.com/");
            var request = new HttpRequestMessage(HttpMethod.Post, "device/authenticate");
            var requestBody = new XASDRequest(accessToken);
            request.Headers.Add("x-xbl-contract-version", "1");
            request.Content = new JsonContent(requestBody);

            var response = (await client.SendAsync(request)).EnsureSuccessStatusCode();
            var data = await response.Content.ReadAsJsonAsync<XASResponse>();
            return new DeviceToken(data);
        }

        public static async Task<TitleToken> AuthenticateXASTAsync(AccessToken accessToken,
                                                  DeviceToken deviceToken)
        {
            HttpClient client = ClientFactory("https://title.auth.xboxlive.com/");
            var request = new HttpRequestMessage(HttpMethod.Post, "title/authenticate");
            var requestBody = new XASTRequest(accessToken, deviceToken);
            request.Headers.Add("x-xbl-contract-version", "1");
            request.Content = new JsonContent(requestBody);

            var response = (await client.SendAsync(request)).EnsureSuccessStatusCode();
            var data = await response.Content.ReadAsJsonAsync<XASResponse>();
            return new TitleToken(data);
        }

        public static async Task<XToken> AuthenticateXSTSAsync(UserToken userToken,
                                              DeviceToken deviceToken = null,
                                              TitleToken titleToken = null)
        {
            HttpClient client = ClientFactory("https://xsts.auth.xboxlive.com/");
            var request = new HttpRequestMessage(HttpMethod.Post, "xsts/authorize");
            var requestBody = new XSTSRequest(userToken,
                                              deviceToken: deviceToken,
                                              titleToken: titleToken);
            request.Headers.Add("x-xbl-contract-version", "1");
            request.Content = new JsonContent(requestBody);

            var response = await client.SendAsync(request);
            var data = await response.Content.ReadAsJsonAsync<XASResponse>();
            return new XToken(data);
        }

        public static string GetWindowsLiveAuthenticationUrl()
        {
            var parameters = new Model.WindowsLiveAuthenticationQuery();
            var url = QueryHelpers.AddQueryString(
                "https://login.live.com/oauth20_authorize.srf",
                parameters.GetQuery());

            return url;
        }

        public static WindowsLiveResponse ParseWindowsLiveResponse(string url)
        {
            if (!url.StartsWith(WindowsLiveConstants.RedirectUrl))
            {
                throw new InvalidDataException(String.Format("Invalid URL to parse: {0}", url));
            }

            string urlFragment = new Uri(url).Fragment;
            if (String.IsNullOrEmpty(urlFragment) || !urlFragment.StartsWith("#access_token"))
            {
                throw new InvalidDataException(String.Format("Invalid URL fragment: {0}", urlFragment));
            }

            // Cut off leading '#'
            urlFragment = urlFragment.Substring(1);

            NameValueCollection queryParams = System.Web.HttpUtility.ParseQueryString(
                urlFragment, System.Text.Encoding.UTF8);

            string[] expectedKeys = {
                "expires_in", "access_token", "token_type",
                "scope", "refresh_token", "user_id"};

            foreach (string key in expectedKeys)
            {
                string val = queryParams[key];
                if (String.IsNullOrEmpty(val))
                    throw new InvalidDataException(
                        String.Format("Key not found: {0} || Invalid value: {1}", key, val));
            }

            return new WindowsLiveResponse(queryParams);
        }

        public static AuthenticationService LoadFromFile(FileStream fs)
        {
            byte[] buf = new byte[fs.Length];
            fs.Read(buf, 0, buf.Length);
            string s = Encoding.UTF8.GetString(buf);
            return JsonConvert.DeserializeObject<AuthenticationService>(s);
        }

        public void DumpToFile(FileStream fs)
        {
            string s = JsonConvert.SerializeObject(this, Formatting.Indented);
            byte[] bytes = Encoding.UTF8.GetBytes(s);
            fs.Write(bytes, 0, bytes.Length);
        }
    }
}
