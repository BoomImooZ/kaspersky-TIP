import requests
import hashlib


class API():
    """Работа с API Kaspersky Threat Intelligence Portal\n
    Для работы с Kaspersky Threat Intelligence Portal API необходимо запросить токен API\n
    https://opentip.kaspersky.com/Help_ru/Doc_data/WorkingWithAPI.htm
    """
    def __init__(self, 
                 apikey:str):
        """Initialize the client with the provided API key."""

        if not isinstance(apikey, str):
            raise ValueError('API key must be a string')

        if not apikey:
            raise ValueError('API key can not be an empty string')

        self._apikey = apikey


    def request_hash(self,
                     hash:str):
        """Поиск Хеша\n
        https://opentip.kaspersky.com/Help_ru/Doc_data/HashLookupAPI.htm
        """
        if not isinstance(hash, str):
            raise ValueError('hash must be a string')
        _headers = {
                "x-api-key": self._apikey
        }
        return requests.get('https://opentip.kaspersky.com/api/v1/search/hash?request='+hash, headers=_headers)
    

    def request_ip(self,
                   ip:str):
        """Поиск IP-адреса\n
        https://opentip.kaspersky.com/Help_ru/Doc_data/IPLookupAPI.htm
        """
        if not isinstance(ip, str):
            raise ValueError('IP-address must be a string')
        _headers = {
                "x-api-key": self._apikey
        }
        return requests.get('https://opentip.kaspersky.com/api/v1/search/ip?request='+ip, headers=_headers)
    

    def request_domain(self,
                       domain:str):
        """Поиск Домена\n
        https://opentip.kaspersky.com/Help_ru/Doc_data/DomainLookupAPI.htm
        """
        if not isinstance(domain, str):
            raise ValueError('domain must be a string')
        _headers = {
                "x-api-key": self._apikey
        }
        return requests.get('https://opentip.kaspersky.com/api/v1/search/domain?request='+domain, headers=_headers)
    

    def request_url(self,
                    URL:str):
        """Поиск веб-адресов\n
        https://opentip.kaspersky.com/Help_ru/Doc_data/URLLookupAPI.htm
        """
        if not isinstance(URL, str):
            raise ValueError('URL must be a string')
        _headers = {
                "x-api-key": self._apikey
        }
        return requests.get('https://opentip.kaspersky.com/api/v1/search/domain?request='+URL, headers=_headers)
    
    
    def scan_file(self,
                  filename:str=None,
                  full_path_file:str=None,
                  mime_type:str='application/octet-stream'):
        """Получение базового отчета об анализе файлов\n
        https://opentip.kaspersky.com/Help_ru/Doc_data/SubmitFileAPI.htm
        """
        if not isinstance(filename, str):
            raise ValueError('filename must be a string')
        
        if full_path_file is None:
            raise ValueError('the full path to the file must not be empty')

        headers = {
                "x-api-key": self._apikey,
                "Content-Type": mime_type
        }
        payload = {
                    "data-binary": '@'+full_path_file
        }
        return requests.post('https://opentip.kaspersky.com/api/v1/scan/file?filename='+filename, headers=headers, data=payload)
    

    def getresult(self,
                  hash:str):
        """Получение полного отчета об анализе файлов\n
        https://opentip.kaspersky.com/Help_ru/Doc_data/GetFileReport.htm
        """
        if not isinstance(hash, str):
            raise ValueError('hash must be a string')
        _headers = {
                "x-api-key": self._apikey
        }
        return requests.post('https://opentip.kaspersky.com/api/v1/getresult/file?request='+hash, headers=_headers)
    

def hashs(full_path_file:str):
    """Вернет хеши MD5, SHA1, SHA256"""
    BUF_SIZE = 65536 

    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()

    with open(full_path_file, 'rb') as f:
        while True:
            data = f.read(BUF_SIZE)
            if not data:
                break
            md5.update(data)
            sha1.update(data)
            sha256.update(data)
    return {"MD5": format(md5.hexdigest().upper()),
            "SHA1": format(sha1.hexdigest().upper()),
            "SHA256": format(sha256.hexdigest().upper())
    }
