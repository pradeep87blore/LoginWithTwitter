using Amazon;
using Amazon.CognitoIdentity;
using Amazon.S3;
using Hammock;
using Hammock.Authentication.OAuth;
using Hammock.Web;
using Spring.Social.OAuth1;
using Spring.Social.Twitter.Api;
using Spring.Social.Twitter.Connect;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Web;
using System.Windows;
using System.Windows.Navigation;
using TweetSharp;

namespace LoginWithTwitter
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        AmazonS3Client client;

        string consumerKey = "grRaaaaaYbbb7gNjPS5fYqId";

        string consumerSecret = "aaaDV0bbb7rPMPUbym2djFhJOephGcccVMncBZDtQfhOhCHq16";

        OAuthRequestToken requestToken;

        TwitterService service;

        public MainWindow()
        {
            InitializeComponent();

           


        }

        private void ButtonExit_Click(object sender, RoutedEventArgs e)
        {
            Application.Current.Shutdown();
        }

        private async void Button_login_Click(object sender, RoutedEventArgs e)
        {
            try
            {
                Login();

            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }
        }

        private void Login()
        {
            service = new TwitterService(consumerKey, consumerSecret);

            // Step 1 - Retrieve an OAuth Request Token
            requestToken = service.GetRequestToken();

            Uri uri = service.GetAuthorizationUri(requestToken);
            StartTwitterLoginDialog(uri.ToString());

        }


        private void StartTwitterLoginDialog(string url)
        {

            webBrowser.Navigated += WebBrowser_Navigated; // webBrowser_Navigated;
            webBrowser.Navigate(url);
        }


        

        private readonly Func<FunctionArguments, RestRequest> _accessTokenQuery
                = args =>
                {
                    var request = new RestRequest
                    {
                        Credentials = new OAuthCredentials
                        {
                            ConsumerKey = args.ConsumerKey,
                            ConsumerSecret = args.ConsumerSecret,
                            Token = args.Token,
                            TokenSecret = args.TokenSecret,
                            Verifier = args.Verifier,
                            ParameterHandling = OAuthParameterHandling.HttpAuthorizationHeader,
                            SignatureMethod = OAuthSignatureMethod.HmacSha1,
                            Type = OAuthType.AccessToken
                        },
                        Method = WebMethod.Post,
                        Path = "https://api.twitter.com/oauth/access_token"
                    };
                    return request;
                };


        private void WebBrowser_Navigated(object sender, NavigationEventArgs e)
        {
            try
            {
                if ((e.Uri != null) && (e.Uri.ToString().Contains("oauth_token")) && (e.Uri.ToString().Contains("oauth_verifier")))
                {
                    Console.WriteLine(e.Uri.PathAndQuery);

                    string[] query = e.Uri.Query.Split("oauth_verifier=");
                    var verifier = query[1];

                    var args = new FunctionArguments();

                    args.ConsumerKey = consumerKey;
                    args.ConsumerSecret = consumerSecret;
                    args.Token = requestToken.Token;
                    args.TokenSecret = requestToken.TokenSecret;
                    args.Verifier = verifier;


                    RestClient _oauth = new RestClient();

                    var request = _accessTokenQuery.Invoke(args);
                    var response = _oauth.Request(request);

                    var queryParams = HttpUtility.ParseQueryString(response.Content);
                    var accessToken = new OAuthAccessToken
                    {
                        Token = queryParams["oauth_token"] ?? "?",
                        TokenSecret = queryParams["oauth_token_secret"] ?? "?",
                        UserId = (int)Convert.ToInt64(queryParams["user_id"] ?? "0"),
                        ScreenName = queryParams["screen_name"] ?? "?"
                    };

                    Console.WriteLine(accessToken);

                    // Step 4 - User authenticates using the Access Token
                    service.AuthenticateWith(accessToken.Token, accessToken.TokenSecret);
                    
                    // NEXT: See how to access some resources of the logged in user

                }
            }

            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }


        }
    }
}
