package edu.monash.aws.oidc_lambda_authorizer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponseV1;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponseV1.Statement;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponseV1.PolicyDocument;
import com.nimbusds.jwt.JWTClaimsSet;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.Map;

public class V1 implements RequestHandler<APIGatewayCustomAuthorizerEvent, IamPolicyResponseV1> {
    protected static String tokenNotValidBefore = "nbf";
    protected static String tokenIssuedAt = "iat";
    protected static String tokenExpires = "exp";

    @Override
    public IamPolicyResponseV1 handleRequest(APIGatewayCustomAuthorizerEvent event, Context context) {
        context.getLogger().log(event.toString());
        String token = event.getAuthorizationToken() != null ? event.getAuthorizationToken() : event.getIdentitySource();


        TokenProcessor tokenProcessor = null;
        try {
            tokenProcessor = new TokenProcessor(token, context);
        } catch (Exception e) {
            e.printStackTrace();
            throw new RuntimeException("Unauthorized");
        }

        if (tokenProcessor.isValid()) {
            return buildResponse(tokenProcessor.getPrincipalId(),
                    IamPolicyResponseV1.ALLOW, "*",
                    tokenProcessor.getContext(),
                    tokenProcessor.getClaims());
        } else {
            throw new RuntimeException("Unauthorised");
        }
    }

    protected IamPolicyResponseV1 buildResponse(String principalId, String granted, String resource, Map<String, Object> context, JWTClaimsSet claims) {
        return IamPolicyResponseV1.builder()
                .withPrincipalId(principalId)
                .withPolicyDocument(PolicyDocument.builder()
                        .withVersion(IamPolicyResponseV1.VERSION_2012_10_17)
                        .withStatement(List.of(Statement.builder()
                                .withAction(IamPolicyResponseV1.EXECUTE_API_INVOKE)
                                .withEffect(granted)
                                .withResource(List.of(resource))
                                .withCondition(Map.ofEntries(
                                        withConditionNotBefore(claims),
                                        withConditionNotAfter(claims)))
                                .build()))
                        .build())
                .withContext(context)
                .build();
    }

    protected Map.Entry<String, Map<String, Object>> withConditionNotBefore(JWTClaimsSet claims) {
        if (claims.getClaim(tokenNotValidBefore) != null) {
            return timedCondition("DateGreaterThan", claims.getNotBeforeTime());
        } else if (claims.getClaim(tokenIssuedAt) != null) {
            return timedCondition("DateGreaterThan", claims.getIssueTime());
        } else {
            return null;
        }
    }

    private Map.Entry<String, Map<String, Object>> timedCondition(String a, Date epoch) {
        return Map.entry(a, Map.of("aws:CurrentTime", ZonedDateTime
                .ofInstant(epoch.toInstant(), ZoneId.of("UTC"))
                .format(DateTimeFormatter.ISO_INSTANT)));
    }

    protected Map.Entry<String, Map<String, Object>> withConditionNotAfter(JWTClaimsSet claims) {
        if (claims.getClaim(tokenExpires) != null) {
            return timedCondition("DateLessThan", claims.getExpirationTime());
        } else {
            return null;
        }
    }
}