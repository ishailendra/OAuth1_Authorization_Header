package com.shail.tester;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;


/**
 * @author Shailendra Singh [http://shailendra.dev]
 */
public class OAuth1AuthorizationHeaderGenerator {

    private static final String oauth_consumer_key = "oauth_consumer_key";
    private static final String oauth_token = "oauth_token";
    private static final String oauth_signature_method = "oauth_signature_method";
    private static final String oauth_timestamp = "oauth_timestamp";
    private static final String oauth_nonce = "oauth_nonce";
    private static final String oauth_version = "oauth_version";
    private static final String oauth_signature = "oauth_signature";
    private static final String version = "1.0";
    private static final String HMAC_SHA1 = "HmacSHA1";

    // https://tools.ietf.org/html/rfc3986#section-2.3
    private static final HashSet<Character> UnreservedChars = new HashSet<Character>(Arrays.asList(
            'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
            'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
            '0','1','2','3','4','5','6','7','8','9',
            '-','_','.','~'));

    private String consumerKey;
    private String consumerSecret;
    private String accessToken;
    private String accessTokenSecret;
    private Map<String, String> parameters = new LinkedHashMap<>();
    private String url;
    private String httpMethod;
    private String signature;

    public OAuth1AuthorizationHeaderGenerator() {}

    public OAuth1AuthorizationHeaderGenerator addConsumerKey(String consumerKey) {
        this.consumerKey = consumerKey;
        return this;
    }

    public OAuth1AuthorizationHeaderGenerator addConsumerSecret(String consumerSecret) {
        this.consumerSecret = consumerSecret;
        return this;
    }

    public OAuth1AuthorizationHeaderGenerator addOAuthToken(String accessToken) {
        this.accessToken = accessToken;
        return this;
    }

    public OAuth1AuthorizationHeaderGenerator addOAuthTokenSecret(String accessTokenSecret) {
        this.accessTokenSecret = accessTokenSecret;
        return this;
    }
    /**
     * Generate nonce of length 15
     * @return generated nonce
     */
    private String generateNonce() {
        int lowerBound = 48;
        int upperBound = 122;
        int nonceLength = 15;

        SecureRandom random = new SecureRandom();

        String nonce = random.ints(lowerBound, upperBound + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(nonceLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();

        return nonce;
    }

    private String getTimeStamp() {
        return Math.round(new Date().getTime() / 1000.0) + "";
    }

    /***
     * Replaces any character not specifically unreserved to an equivalent
     * percent sequence.
     * @param s
     * @return
     * @see <a href="https://stackoverflow.com/a/51754473/3892636">https://stackoverflow.com/a/51754473/3892636</a>}
     */
    private String encodeURIComponent(String s) {
        StringBuilder o = new StringBuilder();
        for (char ch : s.toCharArray()) {
            if (isSafe(ch)) {
                o.append(ch);
            }
            else {
                o.append('%');
                o.append(toHex(ch / 16));
                o.append(toHex(ch % 16));
            }
        }
        return o.toString();
    }

    private char toHex(int ch) {
        return (char)(ch < 10 ? '0' + ch : 'A' + ch - 10);
    }

    private boolean isSafe(char ch) {
        return UnreservedChars.contains(ch);
    }

    /**
     * Set the request URL in the generator
     * @param url
     * @return
     */
    public OAuth1AuthorizationHeaderGenerator setURL(String url) {
        this.url = url;
        return this;
    }

    /**
     * Add parameters to be included when generating the signature
     * @param name parameter key
     * @param value parameter value
     * @return
     */
    public OAuth1AuthorizationHeaderGenerator addParameters(String name, String value) {
        parameters.put(name, value);
        return this;
    }

    /**
     * Set the request type of HTTP method eg GET, POST, PUT, DELETE
     * @param method
     * @return
     */
    public OAuth1AuthorizationHeaderGenerator httpMethodType(String method) {
        this.httpMethod = method.toUpperCase();
        return this;
    }

    /**
     * Generate the header using the parameters provided and oauth signature
     * @return
     */
    public String generate() {
        if (!parameters.containsKey(oauth_timestamp)) {
            parameters.put(oauth_timestamp, getTimeStamp());
        }

        //Add boilerplate parameters
        parameters.put(oauth_signature_method, HMAC_SHA1);
        parameters.put(oauth_version, version);

        //Build signature base string
        String baseSignatureString = generateSignatureBaseString();

        //Generate signature by encoding the consumer secret + the token secret
        if (signature == null) {
            signature = generateSignature(baseSignatureString);
        }

        //Addoing signature into the parameters map to include in header
        parameters.put(oauth_signature, signature);

        String header =  "OAuth " + parameters.entrySet().stream()
                .map(e -> encodeURIComponent(e.getKey()) + "=\"" + encodeURIComponent(e.getValue()) + "\"")
                .collect(Collectors.joining(", "));

        return header;
    }

    /**
     * Generate base string for signature HTTPMethod + URL + Parameter_String
     * @return
     */
    private String generateSignatureBaseString() {
        parameters.put(oauth_consumer_key, consumerKey);
        parameters.put(oauth_nonce, generateNonce());
        parameters.put(oauth_token, accessToken);
        parameters.put(oauth_version, version);

        //Sorting parameters on by key
        parameters = parameters
                .entrySet()
                .stream()
                .sorted(Map.Entry.comparingByKey())
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (oldValue, newValue) -> oldValue, LinkedHashMap::new));

        StringBuilder parameterString = new StringBuilder();
        parameters.entrySet().forEach(entry -> {
            parameterString.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        });

        parameterString.deleteCharAt(parameterString.length() - 1);

        String baseString = httpMethod.toUpperCase() + "&" + encodeURIComponent(url) + "&" + encodeURIComponent(parameterString.toString());

        return baseString;
    }

    /**
     * Generate signature by signing signature base string
     * @param baseSignatureString
     * @return
     */
    private String generateSignature(String baseSignatureString) {
        String secret = new StringBuilder().append(encodeURIComponent(consumerSecret)).append("&").append((accessTokenSecret == null ? "" : encodeURIComponent(accessTokenSecret))).toString();
        byte[] keyBytes = secret.getBytes(StandardCharsets.UTF_8);
        SecretKey key = new SecretKeySpec(keyBytes, HMAC_SHA1);
        Mac mac;
        try {
            mac = Mac.getInstance(HMAC_SHA1);
            mac.init(key);
        }
        catch (NoSuchAlgorithmException | InvalidKeyException e) {
            e.printStackTrace();
            return null;
        }

        byte[] signatureBytes = mac.doFinal(baseSignatureString.getBytes(StandardCharsets.UTF_8));
        return new String(Base64.getEncoder().encode(signatureBytes)).trim();
    }
}
