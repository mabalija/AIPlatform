using System;
using System.Globalization;
using System.Security.Cryptography;
using System.Text;

namespace Luna.Clients.Azure.APIM
{
    public class APIMAuthHelper
    {
        private string _id;
        private string _primaryKey;
        private string _secondaryKey;
        private DateTime expireTime;
        public APIMAuthHelper(string id, string primaryKey, string secondaryKey)
        {
            _id = id;
            _primaryKey = primaryKey;
            _secondaryKey = secondaryKey;
            expireTime = DateTime.Now;
        }
        public string GetSharedAccessToken()
        {
            var key = string.Format("{0}/{1}", _primaryKey, _secondaryKey);
            if (expireTime.Subtract(DateTime.Now).TotalDays < 1) expireTime = DateTime.UtcNow.AddDays(10);
            var expiry = expireTime;
            using (var encoder = new HMACSHA512(Encoding.UTF8.GetBytes(key)))
            {
                var dataToSign = _id + "\n" + expiry.ToString("O", CultureInfo.InvariantCulture);
                var hash = encoder.ComputeHash(Encoding.UTF8.GetBytes(dataToSign));
                var signature = Convert.ToBase64String(hash);
                var encodedToken = string.Format("SharedAccessSignature {0}&{1:o}&{2}", _id, expiry, signature);
                return encodedToken;
            }
        }
    }
}
