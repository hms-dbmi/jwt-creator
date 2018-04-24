package edu.harvard.hms.dbmi.avillach.jwt;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.spec.SecretKeySpec;

public class App
{
    public static void main( String[] args )
    {
        if(args.length != 3 && args.length != 4 && args.length != 5){
            System.out.println("Please pass the path to your client secret and the email "
                    + "address to generate a JWT for as the only arguments to this tool.\n\n"
                    + "java -jar generateJwt.jar <path to client secret> <claim key> <claim value>,\n"
                    + "e.g. java -jar generateJwt.jar /path/to/secret.txt email test@example.com, \n\n"
                    + "or: java -jar generateJwt.jar <path to client secret> <claim key> <claim value> <ttl mill seconds>, \n\n"
                    + "or: java -jar generateJwt.jar <path to client secret> <claim key> <claim value> <ttl> <unit>, \n"
                    + "e.g. java -jar generateJwt.jar /path/to/secret.txt email test@example.com 5 day");
            System.exit(-1);
        }


        long defaultTTLMillis = 1000 * 60 * 60 * 24 * 7;
        long ttlMillis = defaultTTLMillis;
        String defaultUnit = "day";

        if (args.length >= 4 ){
            ttlMillis = parseTTLField(args[3], defaultTTLMillis);
        }

        if (args.length >= 5 ){
            ttlMillis = parseTTLBasedOnUnit(parseTTLField(args[3],ttlMillis), defaultTTLMillis, args[4], defaultUnit);
        }
        try {
            System.out.println("Generating token................................");
            System.out.println(createJWT(new FileInputStream(args[0]), "Foo", "bar", args[1], args[2], ttlMillis));
        } catch (FileNotFoundException e) {
            System.out.println("The only argument you pass to this tool should be the path to your client secret. We did not find your client secret at : " + args[0]);
        } catch (IOException e) {
            System.out.println("An IOException was encountered trying to read : " + args[0]);
            e.printStackTrace();
        }
    }

    private static Long parseTTLField(String ttl, long defaultTTL){
        if (ttl.isEmpty())
            return defaultTTL;

        try {
            return Long.parseLong(ttl);
        } catch (NumberFormatException ex){
            System.out.println("The forth argument: " + ttl + " is not a valid long value.\n" +
                    "Use "+ defaultTTL + " as ttl in milli-seconds");
            return defaultTTL;
        }
    }

    private static Long parseTTLBasedOnUnit(long ttl, long defaultTTL, String unit, String defaultUnit){
        if (ttl <= 0)
            return defaultTTL;

        if (unit.isEmpty())
            return defaultTTL;

        switch (unit){
            case "day":
                return ttl*1000 * 60 * 60 * 24;
            case "ms":
                return ttl;
            default:
                System.out.println("Your entered unit is: " + unit +
                        ", which is not supported. Currently only support day/ms.\n" +
                        "Using ms(default unit) to generate the token");
                return defaultTTL;
        }
    }

    private static String createJWT(FileInputStream clientSecret, String id, String issuer, String claim_key, String subject, long ttlMillis) throws IOException{
        SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;

        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);

        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = new BufferedReader(new InputStreamReader(clientSecret)).readLine().getBytes();
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());


        Map<String, Object> claims = new HashMap<String, Object>();
        Jwts.builder().setClaims(claims);



        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder()
                .setClaims(claims)
                .setId(id)
                .setIssuedAt(now)
                .setSubject(subject)
                .setIssuer(issuer)
                .signWith(signatureAlgorithm, signingKey);

        // available PIC-SURE userFields allowed for JWT Tokens.
        // see: global field java:global/userField in standalone.xml, IRCT_USER_FIELD in 
        // docker-images/pic-sure/Dockerfile, docker-images/deployments/pic-sure for userField configuration - Andre
        claims.put(claim_key, subject);

        //if it has been specified, let's add the expiration
        if (ttlMillis >= 0) {
            long expMillis = nowMillis + ttlMillis;
            Date exp = new Date(expMillis);
            builder.setExpiration(exp);
        }

        //Builds the JWT and serializes it to a compact, URL-safe string
        return builder.compact();
    }
}
