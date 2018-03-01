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
    	if(args.length != 3){
    		System.out.println("Please pass the path to your client secret and the email "
    				+ "address to generate a JWT for as the only arguments to this tool.\n\n"
    				+ "java -jar generateJwt.jar <path to client secret> <claim key> <claim value>,\n"
    				+ "e.g. java -jar generateJwt.jar /path/to/secret.txt email test@example.com");
    		System.exit(-1);
    	}
    	try {
			System.out.println(createJWT(new FileInputStream(args[0]), "Foo", "bar", args[1], args[2], 1000 * 60 * 60 * 24 * 7));
		} catch (FileNotFoundException e) {
			System.out.println("The only argument you pass to this tool should be the path to your client secret. We did not find your client secret at : " + args[0]);
		} catch (IOException e) {
			System.out.println("An IOException was encountered trying to read : " + args[0]);
			e.printStackTrace();
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
