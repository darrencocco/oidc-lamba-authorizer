package edu.monash.aws.oidc_lambda_authorizer;

import java.util.Map;

public interface OidcTokenAuthorizer {

    OidcTokenAuthorizer addConfig(OidcConfig config);

    OidcTokenAuthorizer addToken(String rawToken);

    OidcTokenAuthorizer process();

    boolean isValid();

    String getPrincipal();

    Map<String, Object> getContext();

}
