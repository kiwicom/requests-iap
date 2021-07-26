import logging

import requests
from google.oauth2.service_account import IDTokenCredentials
from google.auth.transport.requests import Request

# https://cloud.google.com/iap/docs/authentication-howto

log = logging.getLogger("requests_iap")


class IAPAuth(requests.auth.AuthBase):
    """Custom requests Auth class used to authenticate HTTP requests to OIDC-authenticated resources using a service account.

    The major use case is to use this flow to make requests to resources behind an Identity-Aware Proxy (https://cloud.google.com/iap).
    This works by generating a JWT with an additional `target_audience` claim set to the OAuth2 client id which
    is signed using the GCP service account credentials.

    This JWT is then exchanged for a Google-signed OIDC token for the client id specified in the JWT claims.
    Authenticated requests are made by setting the token in the `Authorization: Bearer` header.

    This token has roughly a 1-hour expiration and is renewed transparently by this authentication class.
    The renewal interval is 30 minutes (to keep requests working with the old token for roughly 30 more minutes in case Google API is down).
    This can be configured via the `jwt_soft_expiration` parameter.
    """

    client_id: str
    credentials: IDTokenCredentials

    def __init__(
        self,
        client_id: str,
        service_account_secret_dict: dict,
    ):
        self.client_id = client_id
        self.credentials = IDTokenCredentials.from_service_account_info(
            info=service_account_secret_dict, target_audience=self.client_id
        )

    def __call__(self, r):
        if not self.credentials.token or self.credentials.expired:
            self.credentials.refresh(Request())

        r.headers["Authorization"] = "Bearer {}".format(self.credentials.token)
        return r
