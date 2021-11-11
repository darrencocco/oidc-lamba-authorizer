package edu.monash.aws.oidc_lambda_authorizer.authorizers;

import com.okta.jwt.AccessTokenVerifier;
import com.okta.jwt.Jwt;
import com.okta.jwt.JwtVerificationException;
import com.okta.jwt.JwtVerifiers;
import edu.monash.aws.oidc_lambda_authorizer.OidcConfig;
import edu.monash.aws.oidc_lambda_authorizer.OidcTokenAuthorizer;
import lombok.NoArgsConstructor;

import java.util.Map;

@NoArgsConstructor
public class Okta implements OidcTokenAuthorizer {
    Jwt jwt = null;
    OidcConfig config;
    String rawToken = null;

    @Override
    public OidcTokenAuthorizer addConfig(OidcConfig config) {
        this.config = config;
        this.jwt = null;
        return this;
    }

    @Override
    public OidcTokenAuthorizer addToken(String rawToken) {
        this.rawToken = rawToken;
        this.jwt = null;
        return this;
    }

    @Override
    public OidcTokenAuthorizer process() {
        AccessTokenVerifier jwtVerifier = JwtVerifiers.accessTokenVerifierBuilder()
                .setIssuer(config.getIssuer())
                .setAudience(config.getAudience())
                .build();
        try {
            jwt = jwtVerifier.decode(rawToken);
        } catch (JwtVerificationException e) {
            e.printStackTrace();
            jwt = null;
        }
        return this;
    }

    @Override
    public boolean isValid() {
        // TODO: Not sure if the jwt will be null if it is outside the valid time frames.
        // Might need to do extra checks to defend against expired/early tokens.
        if (jwt == null) {
            return false;
        } else {
            return true;
        }
    }

    @Override
    public String getPrincipal() {
        if (jwt == null || !jwt.getClaims().containsKey(config.getPrincipalIdField())) {
            throw new RuntimeException("Unauthorised");
        }

        return (String) jwt.getClaims().get(config.getPrincipalIdField());
    }

    @Override
    public Map<String, Object> getContext() {
        if (jwt == null) {
            throw new RuntimeException("Unauthorised");
        }

        // TODO: Pull claims from the access_token
        return null;
    }
}