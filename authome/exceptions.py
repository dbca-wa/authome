from django.template.response import TemplateResponse
from django.http.multipartparser import MultiPartParserError
from django.http import HttpResponseRedirect
from django.urls import reverse

#borrow MultiPartParserError to convert a exception to redirect response
class HttpResponseException(MultiPartParserError): 
    http_code = None

    def get_response(self,request):
        code = self.http_code or 400
        return TemplateResponse(request,"authome/error.html",context={"message":str(self)},status=code)

class AzureADB2CAuthenticateFailed(HttpResponseException): 
    def __init__(self,http_code,error_code,message,ex):
        super().__init__(message.format(str(ex)))
        self.http_code = http_code
        self.error_code = error_code
        self.ex = ex

    def get_response(self,request):
        if self.error_code == "AADB2C90118":
            #forgot password
            return HttpResponseRedirect(reverse('password_reset'))


        code = self.http_code or 400
        return TemplateResponse(request,"authome/error.html",context={"message":str(self)},status=code)

