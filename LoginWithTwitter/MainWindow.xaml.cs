using Amazon;
using Amazon.CognitoIdentity;
using Amazon.S3;
using Hammock;
using Hammock.Authentication.OAuth;
using Hammock.Web;
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using System.Web;
using System.Windows;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using TweetSharp;

/// <summary>
/// Info:
/// This page demonstrates how to log in with Twitter
/// For the first hand information on what is being done, check the official website:
/// https://developer.twitter.com/en/docs/twitter-for-websites/log-in-with-twitter/guides/implementing-sign-in-with-twitter
/// TweetSharp is being used to abstract a few of the underlying details, where possible
/// 
/// Information on how to use TweetSharp: https://github.com/Yortw/tweetmoasharp
/// </summary>


namespace LoginWithTwitter
{

    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        string consumerKey = null;
        string consumerSecret = null;
        string awsIdentityPoolId = null;
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

        private void Window_Initialized(object sender, EventArgs e)
        {
            if (!LoadSecrets())
            {
                string msg = "Failed to read the Twitter secrets. Ensure that the file secrets.txt is correctly located with the exe and its contents are properly filled\n";
                msg += "Sample contents of the file: \n";
                msg += "ConsumerKey=rDt8YmVT7gNYqIdHjPSbgrR5f\nConsumerSecret=CHq16rf72dRVtQfhPMPUbOhhgfgjFMncBZDhJbfmhrykaDV0j5\nIdentityPool=ap-southeast-2:39763976-9bda-4195-4195-53b439bda407";

                MessageBox.Show(msg);
            }
        }

        private void Button_login_Click(object sender, RoutedEventArgs e)
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

        /// <summary>
        /// Initiate the login flow
        /// </summary>
        private void Login()
        {
            // Use the Consumer Key and Consumer Secret Key to fetch a valid Twitter Service handle
            service = new TwitterService(consumerKey, consumerSecret);

            // Retrieve an OAuth Request Token
            requestToken = service.GetRequestToken();

            // Obtain the URI that shall be used for the login
            Uri twitterLoginUrl = service.GetAuthorizationUri(requestToken);
            StartTwitterLoginDialog(twitterLoginUrl.ToString());

        }

        /// <summary>
        /// Navigate to the Twitter login URL
        /// </summary>
        /// <param name="url"></param>
        private void StartTwitterLoginDialog(string twitterLoginUrl)
        {
            webBrowser.Navigated += WebBrowser_Navigated; // Subscribe to the Navigated event
            webBrowser.Navigate(twitterLoginUrl);
        }

        /// <summary>
        /// This is to set the parameters up for querying for the access token
        /// </summary>
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

        /// <summary>
        /// The event triggered when the web browser control navigates to a specified URL
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private async void WebBrowser_Navigated(object sender, NavigationEventArgs e)
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

                    webBrowser.Visibility = Visibility.Collapsed;
                    label_buckets.Content = "Fetching S3 buckets, please wait";
                    GetUserInfo(accessToken);
                    await ListS3Buckets(accessToken);

                }
            }

            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }


        }

        /// <summary>
        /// Fetch some user info and update this on to the UI
        /// </summary>
        /// <param name="accessToken"></param>
        private void GetUserInfo(OAuthAccessToken accessToken)
        {
            try
            {
                service.AuthenticateWith(accessToken.Token, accessToken.TokenSecret);

                GetUserProfileOptions userInfo = new GetUserProfileOptions()
                {
                    IncludeEntities = true,
                    SkipStatus = false
                };

                var result = service.BeginGetUserProfile(userInfo);
                var user = service.EndGetUserProfile(result);

                var imgUrlString = user.ProfileImageUrlHttps;
                if (imgUrlString.Contains("normal", StringComparison.OrdinalIgnoreCase))
                {
                    // To get a bigger image. Refer to https://developer.twitter.com/en/docs/accounts-and-users/user-profile-images-and-banners
                    imgUrlString = imgUrlString.Replace("normal", "bigger", StringComparison.OrdinalIgnoreCase);
                }
                Uri profileImgUrl = new Uri(imgUrlString);
                
                image_profileImg.Source = new BitmapImage(profileImgUrl);

                label_screenName.Content = user.ScreenName;

                if(user.Status != null)
                    label_latestTweet.Content = "Latest Tweet: " + user.Status.Text;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
            }

        }

        /// <summary>
        /// Use the fetched token to access the S3 buckets
        /// </summary>
        /// <param name="accessToken"></param>
        /// <returns></returns>
        private async Task ListS3Buckets(OAuthAccessToken accessToken)
        {
            CognitoAWSCredentials credentials = new CognitoAWSCredentials(
                awsIdentityPoolId, // Identity pool ID
                RegionEndpoint.APSoutheast2);

            credentials.AddLogin("api.twitter.com", accessToken.Token + ";" + accessToken.TokenSecret);
            var cred = await credentials.GetCredentialsAsync();

            using (var s3Client = new AmazonS3Client(cred.AccessKey, cred.SecretKey, cred.Token, RegionEndpoint.APSoutheast2))
            {
                // This call is performed with the authenticated role and credentials
                var bucketList = await s3Client.ListBucketsAsync();

                label_buckets.Content = "S3 Buckets";
                foreach (var bucket in bucketList.Buckets)
                {
                    listBox_s3Buckets.Items.Add(bucket.BucketName);
                }
            }
        }


        /// <summary>
        /// Read the Secrets file
        /// </summary>
        /// <returns></returns>
        private bool LoadSecrets()
        {
            try
            {
                string line;

                /* The file contents are as follows:
                ConsumerKey=rDt8YmVT7gNYqIdHjPSbgrR5f
                ConsumerSecret=CHq16rf72dRVtQfhPMPUbOhhgfgjFMncBZDhJbfmhrykaDV0j5
                IdentityPool=ap-southeast-2:39763976-9bda-4195-4195-53b439bda407
                */

                System.IO.StreamReader secretsFile = new System.IO.StreamReader("secrets.keys");
                while ((line = secretsFile.ReadLine()) != null)
                {
                    if (line.Contains("ConsumerKey"))
                    {
                        var split = line.Split('=');
                        consumerKey = split[1];
                    }
                    else if (line.Contains("ConsumerSecret"))
                    {
                        var split = line.Split('=');
                        consumerSecret = split[1];
                    }
                    else  if(line.Contains("IdentityPool"))
                    {
                        var split = line.Split('=');
                        awsIdentityPoolId = split[1];
                    }
                    System.Console.WriteLine(line);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
                return false;
            }

            return true;
        }
    }
}
