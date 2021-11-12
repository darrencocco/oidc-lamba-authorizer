Notes on Okta configuration for API Gateway
===========================================

You must not use the standard `Authorization Server`.
A new one can be set up through Security > API on the Okta administration page.

To use the custom Authorization Server you simple have to use the issuer URL
in the configuration of the Lambda through the AWS environment variables.