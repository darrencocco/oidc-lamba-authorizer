package edu.monash.aws.oidc_lambda_authorizer;

import lombok.Getter;

@Getter
public class OidcConfig {
    String provider;
    String issuer;
    String audience;
    String principalIdField;
}
