from abc import ABC
from typing import Union, Literal
import hmac
import hashlib
import requests
from urllib.parse import urlencode
import logging
import time

logger = logging.getLogger(__name__)

class MexcAPIError(Exception): 
    pass

class MexcSDK(ABC):
    """
    Initializes a new instance of the class with the given `api_key` and `api_secret` parameters.

    :param api_key: A string representing the API key.
    :param api_secret: A string representing the API secret.
    :param base_url: A string representing the base URL of the API.
    """
    def __init__(self, api_key: str, api_secret: str, base_url: str, proxies: dict = None):
        self.api_key = api_key
        self.api_secret = api_secret

        self.recvWindow = 5000

        self.base_url = base_url

        self.session = requests.Session()
        self.session.headers.update({
            "Content-Type": "application/json",
        })

        if proxies:
            self.session.proxies.update(proxies)


    @classmethod
    def sign(self, **kwargs) -> str:
        ...
    
    @classmethod
    def call(self, method: Union[Literal["GET"], Literal["POST"], Literal["PUT"], Literal["DELETE"]], router: str, *args, **kwargs) -> dict:
        ...

class _SpotHTTP(MexcSDK):
    def __init__(self, api_key: str = None, api_secret: str = None, proxies: dict = None):
        super().__init__(api_key, api_secret, "https://api.mexc.com", proxies = proxies)

        self.session.headers.update({
            "X-MEXC-APIKEY": self.api_key
        })

    def sign(self, query_string: str) -> str:
        """
        Generates a signature for an API request using HMAC SHA256 encryption.

        Args:
            **kwargs: Arbitrary keyword arguments representing request parameters.

        Returns:
            A hexadecimal string representing the signature of the request.
        """
        # Generate signature
        signature = hmac.new(self.api_secret.encode('utf-8'), query_string.encode('utf-8'), hashlib.sha256).hexdigest()
        return signature

    def call(self, method: Union[Literal["GET"], Literal["POST"], Literal["PUT"], Literal["DELETE"]], router: str, auth: bool = True, *args, **kwargs) -> dict:
        if not router.startswith("/"):
            router = f"/{router}"

        # clear None values
        kwargs = {k: v for k, v in kwargs.items() if v is not None}

        if kwargs.get('params'):
            kwargs['params'] = {k: v for k, v in kwargs['params'].items() if v is not None}
        else:
            kwargs['params'] = {}

        timestamp = str(int(time.time() * 1000))
        kwargs['params']['timestamp'] = timestamp
        kwargs['params']['recvWindow'] = self.recvWindow

        kwargs['params'] = {k: v for k, v in sorted(kwargs['params'].items())}
        params = urlencode(kwargs.pop('params'), doseq=True).replace('+', '%20')

        if self.api_key and self.api_secret and auth:
            params += "&signature=" + self.sign(params)


        response = self.session.request(method, f"{self.base_url}{router}", params = params, *args, **kwargs)

        if not response.ok:
            raise MexcAPIError(f'(code={response.json()["code"]}): {response.json()["msg"]}')

        return response.json()
    
class _FuturesHTTP:
    def __init__(self, api_key: str = None, api_secret: str = None, proxies: dict = None):
        self.api_key = api_key
        self.api_secret = api_secret
        self.base_url = "https://contract.mexc.com"
        self.session = requests.Session()
        if proxies:
            self.session.proxies.update(proxies)

        # Se quiser setar content-type fixo, faça somente em requests POST.
        # Aqui deixarei sem setar, pois no GET não é application/json.
        self.session.headers.update({
            "ApiKey": self.api_key,
        })

    def sign(
        self, 
        method: Literal["GET", "POST", "PUT", "DELETE"], 
        timestamp: str, 
        params_dict: dict = None
    ) -> str:
        """
        Gera a assinatura HMAC SHA256 de acordo com a doc:
        - GET/DELETE => sort + & + URL encode
        - POST       => JSON string sem sorting
        """
        if not params_dict:
            params_dict = {}

        if method in ["GET", "DELETE"]:
            # Monta string "k1=v1&k2=v2..." em ordem lexicográfica
            sorted_items = sorted(params_dict.items())
            encoded_pairs = []
            for k, v in sorted_items:
                # se valor for None, não passa
                if v is None:
                    continue
                # URL-encode do valor (principalmente se tiver vírgula, espaço etc.)
                encoded_val = urllib.parse.quote(str(v), safe="")
                encoded_pairs.append(f"{k}={encoded_val}")
            signature_string = "&".join(encoded_pairs)
        else:
            # POST => pega o corpo inteiro em JSON (sem sorting)
            signature_string = json.dumps(params_dict, separators=(',', ':'))

        # Concatena: accessKey + timestamp + (paramString ou jsonString)
        string_to_sign = self.api_key + timestamp + signature_string

        # Faz HMAC SHA256 e converte para hexdigest
        signature = hmac.new(
            self.api_secret.encode("utf-8"),
            string_to_sign.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        return signature

    def call(
        self,
        method: Union[Literal["GET"], Literal["POST"], Literal["PUT"], Literal["DELETE"]],
        router: str,
        params: dict = None,
        data: dict = None,
        **kwargs
    ) -> dict:
        """
        Faz a requisição HTTP e já monta a assinatura caso seja endpoint privado.
        """
        if not router.startswith("/"):
            router = f"/{router}"

        # Se for uma rota pública, não precisa assinar
        # Mas em geral, assumimos que se tiver api_key/api_secret, é privado
        is_private = self.api_key and self.api_secret

        # Garantindo que não terá valores None
        params = {k: v for k, v in (params or {}).items() if v is not None}
        data   = {k: v for k, v in (data   or {}).items() if v is not None}

        # Pega timestamp (ms)
        timestamp = str(int(time.time() * 1000))

        # Headers básicos
        headers = {}
        # Se for private, gera signature
        if is_private:
            if method in ["GET", "DELETE"]:
                # Assina os params
                sign_data = params
            else:
                # method == POST ou PUT => assina o JSON data
                sign_data = data

            signature = self.sign(method, timestamp, sign_data)
            headers.update({
                "Request-Time": timestamp,
                "Signature": signature,
            })

        # Se for POST, precisamos passar application/json no content-type
        if method == "POST":
            headers["Content-Type"] = "application/json"

        # Faz a request
        url = f"{self.base_url}{router}"
        resp = self.session.request(
            method=method,
            url=url,
            params=params if method in ["GET", "DELETE"] else None,  # GET/DELETE => params=...
            json=data if method == "POST" else None,                 # POST => body JSON
            headers=headers,
            **kwargs
        )

        # Tenta decodificar JSON
        try:
            return resp.json()
        except Exception:
            return {
                "success": False,
                "code": resp.status_code,
                "message": resp.text
            }
