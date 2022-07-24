using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Web;

namespace LS.Foundation.Salesforce.Services
{
  public class SalesforceJwtService : ISalesforceJwtService
    {

        /// <summary>
        /// Property stores generated assertion.
        /// </summary>
        private string _assertion { get; set; }

        /// <summary>
        /// Salesforce configuration service.
        /// </summary>
        private readonly ISalesforceConfigurationService _salesforceConfigurationService;

        /// <summary>
        /// Initializes a new instance of the <see cref="SalesforceJwtService"/> class.
        /// </summary>
        /// <param name="salesforceConfigurationService">Salesforce configuration service</param>
        public SalesforceJwtService(ISalesforceConfigurationService salesforceConfigurationService)
        {
            this._salesforceConfigurationService = salesforceConfigurationService;
            this._assertion = string.Empty;
        }

        /// <summary>
        /// Generates assertion value for API communication - if assertion has been generated before, returns previously generated valued
        /// </summary>
        /// <returns>Base64 encoded assertion value.</returns>
        public string GenerateAssertion()
        {
            if (this._assertion.Equals(string.Empty))
            {
                var assertion = this.GenerateJwtHeaderString();
                assertion += ".";
                assertion += this.GenerateClaimsString();
                this._assertion = assertion + "." + this.SignAndGeneratePayloadString(assertion);
            }

            return this._assertion;
        }

        /// <summary>
        /// Generates base64 encoded value for expected JWT header.
        /// </summary>
        /// <returns>Base 64 encoded header.</returns>
        private string GenerateJwtHeaderString()
        {
            var headerValue = SalesforceConstants.Api.Values.Header;
            return this.Base64Encoder(headerValue);
        }

        /// <summary>
        /// Generates base64 encoded value for claims.
        /// </summary>
        /// <returns>Base 64 encoded claims.</returns>
        private string GenerateClaimsString()
        {
            var iss = this._salesforceConfigurationService.GetJwtClaimsIss();
            var sub = this._salesforceConfigurationService.GetJwtClaimsSub();
            var aud = this._salesforceConfigurationService.GetJwtClaimsAud();
            var exp = this._salesforceConfigurationService.GetJwtClaimsExp();
            var claims = $"{{\"iss\": \"{iss}\", \"sub\": \"{sub}\", \"aud\": \"{aud}\", \"exp\": \"{exp}\"}}";
            return this.Base64Encoder(claims);
        }

        private string SignAndGeneratePayloadString(string payload)
        {
            X509Certificate2 certificate = new X509Certificate2(this._salesforceConfigurationService.GetCertPath(), this._salesforceConfigurationService.GetCertPass(), X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
            using (var privateKey = certificate.GetRSAPrivateKey())
            {
                var signedData = privateKey.SignData(System.Text.Encoding.UTF8.GetBytes(payload), HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
                return Convert.ToBase64String(signedData).TrimEnd('=').Replace('+', '-').Replace('/', '_');
            }
        }

        /// <summary>
        /// Encodes any string to base 64 string.
        /// </summary>
        /// <param name="valueToEncode">String that we want to encode into base64 string.</param>
        /// <returns>Base64 string.</returns>
        private string Base64Encoder(string valueToEncode)
        {
            byte[] valueToEncodeAsBytes = System.Text.Encoding.UTF8.GetBytes(valueToEncode);
            return Convert.ToBase64String(valueToEncodeAsBytes).TrimEnd('=').Replace('+', '-').Replace('/', '_');
        }
    }
}
