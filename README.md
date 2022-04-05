
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
            ..addParameters("oauth_callback", "secret")
            .generate();

HttpHeaders headers = new HttpHeaders();
headers.add("Authorization", header);
HttpEntity<String> httpEntity = new HttpEntity<String>(headers);
ResponseEntity<Object> someModelEntity= template.exchange("<Request_URL>",
                    HttpMethod.GET, httpEntity, Object.class);
```

Examples header generated = 

## Reference

[OAuth 1.0 Protocol](https://datatracker.ietf.org/doc/html/rfc5849)

[EncodeURIComponent](https://stackoverflow.com/a/51754473/3892636)