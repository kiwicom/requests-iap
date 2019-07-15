# requests-iap
Auth class for [requests](https://github.com/kennethreitz/requests) used to authenticate HTTP requests to OIDC-authenticated resources ([Cloud Identity-Aware Proxy](https://cloud.google.com/iap/)) using a Google service account. In addition, it transparently caches the OIDC token returned by google in-memory of the program.

## Installation
```bash
$ pip install requests-iap
```

## Usage

```python
import requests
from requests_iap import IAPAuth

# https://console.cloud.google.com/iam-admin/serviceaccounts (Actions -> Create key -> JSON)
with open("google-serviceaccount-creds.json") as f:
    service_account_secret_dict = json.load(f)

# https://console.cloud.google.com/apis/credentials (pick client ID of the application you are connecting to)
client_id = "1337-very-long-client-id.apps.googleusercontent.com"

resp = requests.get(
    "https://service.behind.iap.example.com",
    auth=IAPAuth(
        client_id=client_id,
        service_account_secret_dict=service_account_secret_dict,
    ),
)
```

### Caching
`IAPAuth` transparently caches the OIDC token from Google for `jwt_soft_expiration` seconds (by default 1800 => 30min). From Google, it requests token for roughly 60 minutes, so the token should keep working for 30min in case Google OAuth2 API would be down.

```python
resp = requests.get(
    "https://service.behind.iap.example.com",
    auth=IAPAuth(
        client_id=client_id,
        service_account_secret_dict=service_account_secret_dict,
        jwt_soft_expiration=600, # try to refresh token every 600 seconds, just to be super safe
    ),
)
```

## Code formatting

[black](https://github.com/ambv/black/)

## Testing

To run all tests:

```
tox
```

Note that tox doesn't know when you change the `requirements.txt`
and won't automatically install new dependencies for test runs.
Run `pip install tox-battery` to install a plugin which fixes this silliness.

## Thanks 

- [@bayotop](https://github.com/bayotop/) for [this snippet](https://gist.github.com/bayotop/7df8a36aab7308ef723afc70ff3cd2a2)
- Google for creating [IAP](https://cloud.google.com/iap) :-)

Create a merge request and assign it to jan.masarik for review.
Ping jan.masarik in the discussion channel linked above.
