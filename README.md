
# AEM-CS API Client Library PHP

> This project is a copy of this project:
> https://github.com/adobe/aemcs-api-client-lib, But using the PHP
> language.

This repository contains code that can be used to exchange AEM-CS API Integration JSON for Access Tokens with IMS. It is meant to be used as a starting point (i.e. an example) for an application that is to use IMS programmatically.
 
AEM-CS API Integration JSON may be retrieved from the AEM-CS Developer Console either by the UI or using an API with Bearer token.

Retrieving the JSON

curl -H "Authorization: Bearer <your_ims_access_token>" https://dev-console-ns-team-aem-cm-n3003.ethos14-prod-va7.dev.adobeaemcloud.com/api/releases/ns-team-aem-cm-n3003/integration/service_token_cm-p9503-e11454.json

Where

dev-console-ns-team-aem-cm-n3003.ethos14-prod-va7.dev.adobeaemcloud.com is the FQDN of your AEM-CS developer console instance, linked from Cloud Manager UI.

ns-team-aem-cm-n3003 is the namespace, see the FQDN

cm-p9503-e11454 is your release name

your_ims_access_token is your IMS Access token which can be retrieved from the AEM-CS Dev Console UI.

  

A user who has access to the Adobe Admin Console as an Administration create the integration by accessing the UI or this URL for the first time, but after that any developer who has administrative access to the AEM-CS Environment may retrieve the integration JSON.

  

The JSON takes the following form (secrets have been redacted)

  

```javascript

{

"ok": true,

"integration": {

"imsEndpoint": "ims-na1.adobelogin.com",

"metascopes": "ent_aem_cloud_api",

"technicalAccount": {

"clientId": "cm-p7603-e12614-integration",

"clientSecret": "4b2__REDACTED__1d47"

},

"email": "c9adf360-3840-41b2-ade3-efc09df14811@techacct.adobe.com",

"id": "D8E157165FC0EAE10A495E8C@techacct.adobe.com",

"org": "907136ED5D35CBF50A495CD4@AdobeOrg",

"privateKey": "-----BEGIN RSA PRIVATE KEY-----\r\nREDACTED\r\n-----END RSA PRIVATE KEY-----\r\n",

"publicKey": "-----BEGIN CERTIFICATE-----\r\nMIIDFDCCAfygAwIBAgIJeFhHzqB0j4woMA0GCSqGSIb3DQEBCwUAMCYxJDAiBgNV\r\nBAMTG2NtLXA3NjAzLWUxMjYxNC1pbnRlZ3JhdGlvbjAeFw0yMDExMjcxMjAyNDFa\r\nFw0yMTExMjcxMjAyNDFaMCYxJDAiBgNVBAMTG2NtLXA3NjAzLWUxMjYxNC1pbnRl\r\nZ3JhdGlvbjCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOeT6J4L+/NO\r\nyyj8AWvuKxHla+g1RX16CDXmnPSLqgJLzA+pu/rVe9It89tAodn+kqObfD8QeL2P\r\nUR+CzfndpvzKmUJ7wqMSHt6gzAe9ogGztYqTVUufBqmY83DFUhmWw4fIyj7JGNpr\r\n44Uf/7jFwz9IEt2a6p275wu2tJ9ZLporTaSk3LjlHDHiINWBZ9s9clu8sl9xei6p\r\nVqlh+FBFyE1lh+4n9KNH9UZ9ayL1aLAMFawhv33BKooWxsYE/veEEogogylpeGRC\r\nwJXgnEyYuA3QmSw1EYSM7mDXkTHlQr1mKzvuE/5cs0kOwh+mdFMsgfKaqgK5jodk\r\nPC8pWl/+4Z0CAwEAAaNFMEMwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAvQwJgYD\r\nVR0RBB8wHYYbaHR0cDovL2V4YW1wbGUub3JnL3dlYmlkI21lMA0GCSqGSIb3DQEB\r\nCwUAA4IBAQA8A4aDmt+WVAeQaK0/oKS+VgUItqGPr2oy9yb300Fa9DtgVf+sLi/2\r\ndKcnhtgGT4ZqBION6fNYgkK0WmHKy+1iHWxiRuH3Zh8lXHPqUJDiIkjAMFIZkv7f\r\nQmI2PDfGEBXYAC8pUaPj6ZMvYbNIPXyfIkDoJmQTfmtOb5WkUh1/1N9LABNFUL+C\r\nbDaKvsnKKAm9nqK2ifuY6zfUfADaPXd7NkordQ3zPOlra9pWMn4cpEuVYvai3pKH\r\nlgEymr/f9lEMSGM9G+xfu1/ouTjaNZIHrIBTvupkqZ0yyY7ceUhNvk9dVb4KJBL/\r\nihlV7nIosONuitjxM93ATjKE+3ZY3hyC\r\n-----END CERTIFICATE-----\r\n"

},

"statusCode": 200

}

```

  

# PHP

  

To use

  

```php

// Generate Token
// Include required dependencies
use \IMSJWTTokenExchange;
use \Exception;
  
try {
	if(!isset($argv[1])){
		throw new Exception("Please!, add certificate Json");
	}
	
	$jsonFileName = $argv[1];
	$jsonFile = file_get_contents($jsonFileName);

	// Check if the file was read successfully
	if ($jsonFile === false) {
		throw new Exception("Error!, not reading the JSON file");
	}

	// Decode the JSON file
	$json_data = json_decode($jsonFile, true);

	// Check if the JSON was decoded successfully
	if ($json_data === null) {
		throw new Exception("Error!, not decoding the JSON file");
	}

	$token = exchangeToken($json_data);
	print_r($token);
} catch (\Throwable $th) {
	print_r($th);
}  

```

  

Or use the CLI


php client.php downloaded_integration.json

  
output:
```php
Array
(
    [token_type] => bearer
    [access_token] => eyJhbGciOiJSUzI1NiIsIng1dSI6Imltc19uYTEta2V5LWF0LTEuY2VyIiwia2lkIjoiaW1zX25hMS1rZXktYXQtMSIsIml0dCI6ImF0In0.....
    [expires_in] => 86399998
)
``` 

### Demo
  
* [Integration with a workflow engine](https://github.com/tmaret/adobe-developers-live-api-auth-demo) shown at Adobe Developers Live conference

  

  

### Contributing

  

Contributions are welcomed! Read the [Contributing Guide](./.github/CONTRIBUTING.md) for more information.

### Licensing


This project is licensed under the Apache V2 License. See [LICENSE](LICENSE) for more information.