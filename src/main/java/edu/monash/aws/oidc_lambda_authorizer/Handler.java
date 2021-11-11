package edu.monash.aws.oidc_lambda_authorizer;
import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayCustomAuthorizerEvent;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponseV1;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponseV1.Statement;
import com.amazonaws.services.lambda.runtime.events.IamPolicyResponseV1.PolicyDocument;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.lang.reflect.InvocationTargetException;
import java.text.ParseException;
import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class Handler implements RequestHandler<APIGatewayCustomAuthorizerEvent, IamPolicyResponseV1> {

    protected static String tokenPrefix = "Bearer: ";

    protected static String tokenNotValidBefore = "nbf";
    protected static String tokenIssuedAt = "iat";
    protected static String tokenExpires = "exp";

    protected static String tokenAuthorizers = "authorizers";

    protected Map<String, OidcConfig> configs = null;

    @Override
    public IamPolicyResponseV1 handleRequest(APIGatewayCustomAuthorizerEvent event, Context context) {
        LambdaLogger logger = context.getLogger();
        // Check that it follows the correct format.
        String token = event.getAuthorizationToken();
        if (!token.startsWith(tokenPrefix)) {
            lolNope();
        }
        logger.log("Encoded token has correct prefix.");

        token = token.substring(tokenPrefix.length());

        JWTClaimsSet claims = new JWTClaimsSet.Builder().build();
        try {
            SignedJWT jwt = SignedJWT.parse(token);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            lolNope();
        }
        logger.log("Token is decodeable JWT.");

        // Load configuration if not already loaded.
        if (configs == null) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                configs = mapper.readValue(System.getenv("OIDC_CONFIG"), new TypeReference<List<OidcConfig>>() {})
                        .stream().collect(Collectors.toMap(OidcConfig::getIssuer, Function.identity()));
            } catch (JsonProcessingException e) {
                lolNope();
            }
        }
        logger.log("Config read successfully.");

        // Doesn't match any of the configured issuers
        if (!configs.containsKey(claims.getIssuer())) {
            lolNope();
        }

        OidcConfig matchingConfig = configs.get(claims.getIssuer());
        String className = this.getClass().getPackageName() +
                "." + tokenAuthorizers + "." +
                matchingConfig.getProvider();

        Class<?> processorClass = null;
        try {
            processorClass = Class.forName(className);
        } catch (ClassNotFoundException e) {
            lolNope();
        }
        assert processorClass != null;
        if (!OidcTokenAuthorizer.class.isAssignableFrom(processorClass)) {
            lolNope();
        }
        logger.log("Found matching authorisation provider: " + processorClass.getCanonicalName());

        OidcTokenAuthorizer tokenProcessor = null;
        try {
            tokenProcessor = (OidcTokenAuthorizer) processorClass.getConstructor().newInstance();
        } catch (InstantiationException e) {
            e.printStackTrace();
        } catch (IllegalAccessException e) {
            e.printStackTrace();
        } catch (InvocationTargetException e) {
            e.printStackTrace();
        } catch (NoSuchMethodException e) {
            e.printStackTrace();
        }
        assert tokenProcessor != null;
        tokenProcessor
                .addConfig(matchingConfig)
                .addToken(token)
                .process();

        if (tokenProcessor.isValid()) {
            return buildResponse(tokenProcessor.getPrincipal(), IamPolicyResponseV1.ALLOW, "*", tokenProcessor.getContext(), claims);
        } else {
            throw new RuntimeException("Unauthorised");
        }
    }

    protected void lolNope() {
        throw new RuntimeException("Unauthorized");
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