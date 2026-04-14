# File: main.py
...
from middleware.identify import IdentifyMiddleware
from middleware.validators import SessionPersistenceValidator, IAPCookieValidator

IAP_AUDIENCE = "/projects/123/apps/456"
# This is the URL of *your* Nginx proxy
IAP_RENEWAL_URL = "[https://my-proxy.com/renew-iap](https://my-proxy.com/renew-iap)"

validators = [
    SessionPersistenceValidator(),
    IAPCookieValidator(
        audience=IAP_AUDIENCE,
        iap_renewal_url=IAP_RENEWAL_URL  # <-- Configuration is here
    )
]

app = FastAPI()
app.add_middleware(IdentifyMiddleware, validators=validators)
...