package com.kostas.spring.authentication.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.cglib.core.internal.Function;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

@Service
public class JwtService {
    private static final String SECRET_KEY = "7A25432A462D4A614E645267556B58703272357538782F413F4428472B4B6250"; //256bits ,nes tiek reik minimum jwt tokenui
    public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject); //subject of the token.
    }

    public String generateToken(UserDetails userDetails){
        return generateToken(new HashMap<>(), userDetails);
    }

    public String generateToken(
            Map<String, Object> extractClaims,
            UserDetails userDetails
    ){
return Jwts
        .builder()
        .setClaims(extractClaims)
        .setSubject(userDetails.getUsername())//emailas musu
        .setIssuedAt(new Date(System.currentTimeMillis())) //expiration date
        .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24)) //24h + 1000 mls
        .signWith(getSignInKey(), SignatureAlgorithm.HS256)//256bit
        .compact();
    }
    public boolean isTokenValid(String token, UserDetails userDetails) // tikrinam ar token priklauso userdetails
    {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpires(token);

    }

    private boolean isTokenExpires(String token) { //tikrinam ar ne senas
    return extractExpiration(token).before(new Date());

    }

    private Date extractExpiration(String token) { //extractinam expirationdate is tokeno
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimResolver){ //extraktinam viena
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }
    private Claims extractAllClaims(String token){ //extraktinam visus
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    private Key getSignInKey() {  //to sign jwt
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
