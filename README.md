
# OAuth 1.0 Authorization Header Generator

This code collects the required paramters for OAuth v1 and builds and signs the header value.




## Usage/Examples

Here's the sample code to use the library to generate the header.
```java

String header = new OAuth1AuthorizationHeaderGenerator().httpMethodType("GET")
            .setURL("<Request_URL>")
            .addConsumerKey("<Consumer_Key>")
            .addConsumerSecret("<Consumer_Secret>")
            .addOAuthToken("<OAuth_Token>")
            .addOAuthTokenSecret("<OAuth_Token_Secret>")
            .addParameters("oauth_callback", "<Callback_URL>")
            .generate();

HttpHeaders headers = new HttpHeaders();
headers.add("Authorization", header);
HttpEntity<String> httpEntity = new HttpEntity<String>(headers);
ResponseEntity<Object> someModelEntity= restTemplate.exchange("<Request_URL>",
                    HttpMethod.GET, httpEntity, Object.class);
```

Examples header generated = OAuth oauth_callback="%3CCallback_URL%3E", oauth_consumer_key="%3CConsumer_Key%3E", oauth_nonce="QAn0EFpHUAulnw1", oauth_signature_method="HmacSHA1", oauth_timestamp="1649144568", oauth_token="%3COAuth_Token%3E", oauth_version="1.0", oauth_signature="r3vpRPJSnlOp9Uouw381nA6wu44%3D"

## Reference

[OAuth 1.0 Protocol](https://datatracker.ietf.org/doc/html/rfc5849)

[EncodeURIComponent](https://stackoverflow.com/a/51754473/3892636)
