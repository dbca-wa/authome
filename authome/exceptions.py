from django.template.response import TemplateResponse
from django.http.multipartparser import MultiPartParserError
from django.http import HttpResponseRedirect
from django.urls import reverse
from django.contrib.auth import REDIRECT_FIELD_NAME

#borrow MultiPartParserError to convert a exception to redirect response
class UserDoesNotExistException(MultiPartParserError): 
    pass

class PolicyNotConfiguredException(MultiPartParserError): 
    pass

class HttpResponseException(MultiPartParserError): 
    http_code = None

    def get_response(self,request):
        code = self.http_code or 400
        return TemplateResponse(request,"authome/error.html",context={"message":str(self)},status=code)

class AzureADB2CAuthenticateFailed(HttpResponseException): 
    def __init__(self,request,http_code,error_code,message,ex):
        super().__init__(message.format(str(ex)))
        self.request = request
        self.http_code = http_code
        self.error_code = error_code
        self.ex = ex

    def get_response(self,request):
        if self.error_code == "AADB2C90118":
            #forgot password
            return HttpResponseRedirect(reverse('password_reset'))
        elif self.error_code == "AADB2C90091":
            next_url = self.request.session.get(REDIRECT_FIELD_NAME)
            if not next_url or "/sso/profile" in next_url:
                next_url = "/sso/setting"
            elif not next_url.startswith("http") and next_url[0] != "/":
                next_url = 'https://{}'.format(next_url)
            return HttpResponseRedirect(next_url)
        else:
            return None

class Auth2ClusterException(Exception):
    def __init__(self,message,ex=None):
        super().__init__(message)
        self.exception = ex
    pass

