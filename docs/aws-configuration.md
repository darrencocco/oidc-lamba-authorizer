AWS Configuration
=================

### Lambda
Use the Java 11 (Corretto) environment, it will work on either arm64 or x64.
Depending on your requirements for API Gateway functionality you need you can
use the V2 (current but not fully supported by all API Gateway resources) or
V1 (obsolete but supported by all API Gateway resources).

For the `Handler`
* V1: `edu.monash.aws.oidc_lambda_authorizer.V1::handleRequest`
* V2: `edu.monash.aws.oidc_lambda_authorizer.V2::handleRequest`

The recommended resources and runtime is 256mb of RAM and 30 seconds runtime.

An environment variable must be set with the key `OIDC_CONFIG` following the
example set in sample_oidc_config.json file.

NB the `provider` is the name of the class for processing your OIDC providers
specific flow. They are stored in the `authorizers` sub-directory/package.

### API Gateway
Setup a new Lambda Authorizer in the API Gateway.
`Payload format version` will be either 1.0(legacy) or 2.0 depending depending
on your requirements.

The `Response mode` must be set to IAM Policy.

It is recommended to use `Authorizer caching` unless you have a security
requirement to re-confirm the validity of the token with the external OIDC
provider. We recommend using the maximum cache duration.

The identity source must be set to `$request.header.Authorization` which
should be the default value.