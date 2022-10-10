import json
import logging
import re

import azure.functions as func
import boto3


def main(req: func.HttpRequest) -> func.HttpResponse:
    """
    The function expects three query parameters:
    - role_arn - the ARN of the IAM role that the caller wants to assume to read Secrets Manager
    - secret_name - the name of the Secrets Manager secret to retrieve
    - region - the Secrets Manager region
    """

    role_arn = req.params.get('role_arn')
    secret_name = req.params.get('secret_name')
    region = req.params.get('region')

    # Check the required query parameters were provided
    if not (role_arn and secret_name and region):
        return func.HttpResponse(
            json.dumps(
                {"message": "role_arn, secret_name or region were not specified."}),
            status_code=400,
            mimetype="application/json",
        )

    # Ensure there is an authorization header
    if not ("authorization" in req.headers):
        return func.HttpResponse(
            json.dumps(
                {"message": "Unauthorized."}),
            status_code=401,
            mimetype="application/json",
        )

    # Extract the bearer token.
    # Fail if the authorization header is in any other format
    m = re.match("Bearer (.+)", req.headers["authorization"])
    if not m:
        return func.HttpResponse(
            json.dumps(
                {"message": "Unexpected token format."}),
            status_code=400,
            mimetype="application/json",
        )
    access_token = m.group(1)

    # Instantiate the client for STS
    sts_client = boto3.client('sts')

    # Assume the desired role
    response = sts_client.assume_role_with_web_identity(
        RoleArn=role_arn,
        RoleSessionName="test",
        WebIdentityToken=access_token
    )

    # Use the credentials of the assumed role
    credentials = response['Credentials']
    session = boto3.Session(
        aws_access_key_id=credentials['AccessKeyId'],
        aws_secret_access_key=credentials['SecretAccessKey'],
        aws_session_token=credentials['SessionToken']
    )

    # Instantiate the Secrets Manager client
    sm_client = session.client(
        service_name='secretsmanager',
        region_name=region
    )

    # Retrieve the secret
    secret = sm_client.get_secret_value(
        SecretId=secret_name
    )

    # Return the secret to the caller
    return func.HttpResponse(
        secret["SecretString"],
        status_code=200,
        mimetype="application/json",
    )
