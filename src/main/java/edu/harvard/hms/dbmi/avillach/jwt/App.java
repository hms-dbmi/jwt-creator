package edu.harvard.hms.dbmi.avillach.jwt;

import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Key;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.io.IOUtils;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class App 
{
    public static void main( String[] args )
    {
    	if(args.length != 2){
    		System.out.println("Please pass the path to your client secret and the email "
    				+ "address to generate a JWT for as the only arguments to this tool.\n\n"
    				+ "java -jar generateJwt.jar <path to client secret> <email address");
    		System.exit(-1);
    	}
    	try {
			System.out.println(createJWT(new FileInputStream(args[0]), "Foo", "bar", args[1], 1000 * 60 * 60 * 24 * 7));
		} catch (FileNotFoundException e) {
			System.out.println("The only argument you pass to this tool should be the path to your client secret. We did not find your client secret at : " + args[0]);
		} catch (IOException e) {
			System.out.println("An IOException was encountered trying to read : " + args[0]);
			e.printStackTrace();
		}
    }
    
    private static String createJWT(FileInputStream clientSecret, String id, String issuer, String subject, long ttlMillis) throws IOException{
    	SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS256;
   	 
        long nowMillis = System.currentTimeMillis();
        Date now = new Date(nowMillis);
     
        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = new BufferedReader(new InputStreamReader(clientSecret)).readLine().getBytes();
        Key signingKey = new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
     
        //Let's set the JWT Claims
        JwtBuilder builder = Jwts.builder().setId(id)
                                    .setIssuedAt(now)
                                    .setSubject(subject)
                                    .setIssuer(issuer)
                                    .signWith(signatureAlgorithm, signingKey);
     
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
