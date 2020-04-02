import time
import json
import logging

import jwt
import requests

from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.backends import default_backend

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

    google_iap_jwt = None

    def __init__(
        self,
        client_id,
        service_account_secret_dict,
        jwt_soft_expiration=1800,
        oauth_token_uri="https://www.googleapis.com/oauth2/v4/token",
        jwt_bearer_token_grant_type="urn:ietf:params:oauth:grant-type:jwt-bearer",
    ):
        self.client_id = client_id

        self.service_account_secret_dict = service_account_secret_dict

        if jwt_soft_expiration > 3600:
            raise ValueError(
                "`jwt_soft_expiration` should NOT be larger than 3600 seconds (1 hour)!"
            )

        self.jwt_soft_expiration = jwt_soft_expiration

        # You shouldn't need to change those
        self.oauth_token_uri = oauth_token_uri
        self.jwt_bearer_token_grant_type = jwt_bearer_token_grant_type

    def __call__(self, r):
        if IAPAuth.google_iap_jwt is None or self.is_jwt_expired(
            IAPAuth.google_iap_jwt
        ):
            try:
                IAPAuth.google_iap_jwt = self.get_google_open_id_connect_token()
            except requests.exceptions.RequestException:
                log.exception("Google OAuth2 API returned an unexpected response!")
            except Exception:
                # Some token will be always better than none, so we will swallow and attempt to make the request anyway with the old token.
                log.exception(
                    "Something terribly unexpected happened during the OIDC token generation!"
                )

        if IAPAuth.google_iap_jwt is None:
            raise RuntimeError("OIDC token generation failed!")

        r.headers["Authorization"] = "Bearer {}".format(IAPAuth.google_iap_jwt)
        return r

    def get_jwt_assertion(self):
        message = {
            "kid": self.service_account_secret_dict["private_key_id"],
            "iss": self.service_account_secret_dict["client_email"],
            "sub": self.service_account_secret_dict["client_email"],
            "aud": self.oauth_token_uri,
            "iat": int(time.time()),
            "exp": int(time.time()) + 60 * 60,
            "target_audience": self.client_id,
        }

        return jwt.encode(
            message,
            load_pem_private_key(
                jwt.utils.force_bytes(self.service_account_secret_dict["private_key"]),
                password=None,
                backend=default_backend(),
            ),
            algorithm="RS256",
        )

    def is_jwt_expired(self, jwt_token):
        if (
            jwt.decode(IAPAuth.google_iap_jwt, verify=False)["iat"]
            + self.jwt_soft_expiration
        ) < time.time():
            return True

        return False

    def get_google_open_id_connect_token(self):
        session = IAPAuth.retry_session()
        r = session.post(
            self.oauth_token_uri,
            timeout=3,
            data={
                "assertion": self.get_jwt_assertion(),
                "grant_type": self.jwt_bearer_token_grant_type,
            },
        )
        r.raise_for_status()
        log.debug("Successfully requested id_token from Google API.")
        return r.json()["id_token"]

    @staticmethod
    def retry_session():
        session = requests.Session()
        retries = 3
        retry = Retry(
            total=retries,
            read=retries,
            connect=retries,
            backoff_factor=0.3,
            method_whitelist=False,
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        return session
