package edu.monash.aws.oidc_lambda_authorizer;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.LambdaLogger;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import lombok.Getter;

import java.lang.reflect.InvocationTargetException;
import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

public class TokenProcessor {
    protected static String tokenPrefix = "Bearer: ";
    protected static String tokenAuthorizers = "authorizers";
    protected static Map<String, OidcConfig> configs = null;

    protected OidcTokenAuthorizer tokenProcessor;

    @Getter
    protected String principalId = null;
    @Getter
    protected JWTClaimsSet claims = null;
    @Getter
    protected Map<String, Object> context = null;

    public TokenProcessor(String authHeader, Context context) throws Exception {
        LambdaLogger logger = context.getLogger();
        // Check that it follows the correct format.
        if (!authHeader.startsWith(tokenPrefix)) {
            throw new Exception("Doesn't match prefix");
        }
        logger.log("Encoded token has correct prefix.");

        String token = authHeader.substring(tokenPrefix.length());

        try {
            SignedJWT jwt = SignedJWT.parse(token);
            claims = jwt.getJWTClaimsSet();
        } catch (ParseException e) {
            throw new Exception("Not a valid JWT");
        }
        assert claims != null;
        logger.log("Token is decodeable JWT.");

        // Load configuration if not already loaded.
        if (configs == null) {
            ObjectMapper mapper = new ObjectMapper();
            try {
                configs = mapper.readValue(System.getenv("OIDC_CONFIG"), new TypeReference<List<OidcConfig>>() {})
                        .stream().collect(Collectors.toMap(OidcConfig::getIssuer, Function.identity()));
            } catch (JsonProcessingException e) {
                throw new Exception("Can't parse configs");
            }
        }
        logger.log("Config read successfully.");

        // Doesn't match any of the configured issuers
        if (!configs.containsKey(claims.getIssuer())) {
            throw new Exception("Doesn't match config");
        }

        OidcConfig matchingConfig = configs.get(claims.getIssuer());
        String className = this.getClass().getPackageName() +
                "." + tokenAuthorizers + "." +
                matchingConfig.getProvider();

        Class<?> processorClass = null;
        try {
            processorClass = Class.forName(className);
        } catch (ClassNotFoundException e) {
            throw new Exception("Fail whale");
        }

        if (!OidcTokenAuthorizer.class.isAssignableFrom(processorClass)) {
            throw new Exception("Fail whale");
        }
        logger.log("Found matching authorisation provider: " + processorClass.getCanonicalName());

        tokenProcessor = null;
        try {
            tokenProcessor = (OidcTokenAuthorizer) processorClass.getConstructor().newInstance();
        } catch (InstantiationException | IllegalAccessException | InvocationTargetException | NoSuchMethodException e) {
            e.printStackTrace();
        }
        assert tokenProcessor != null;
        tokenProcessor
                .addConfig(matchingConfig)
                .addToken(token)
                .process();

        principalId = tokenProcessor.getPrincipal();
    }

    public boolean isValid() {
        return tokenProcessor.isValid();
    }
}
