from django.test import TestCase

from . import models
from . import utils

from .basetest import BaseTestCase

class UserEmailTestCase(BaseTestCase):
    def test_parse_url(self):
        print("============================================================================")
        testcases = [
            ("https://example.com/main?a=1",{"url":"https://example.com/main?a=1","domain":"example.com","port":None,"path":"/main","parameters":"a=1"}),
            ("http://example.com/main?a=1",{"url":"http://example.com/main?a=1","domain":"example.com","port":None,"path":"/main","parameters":"a=1"}),
            ("example.com/main?a=1",{"url":"example.com/main?a=1","domain":"example.com","port":None,"path":"/main","parameters":"a=1"}),
            ("https://example.com:8080/main?a=1",{"url":"https://example.com:8080/main?a=1","domain":"example.com","port":8080,"path":"/main","parameters":"a=1"}),
            ("https://example.com:8080/main#anchor?a=1",{"url":"https://example.com:8080/main#anchor?a=1","domain":"example.com","port":8080,"path":"/main#anchor","parameters":"a=1"}),
            ("https://example.com:8080/main#anchor?",{"url":"https://example.com:8080/main#anchor?","domain":"example.com","port":8080,"path":"/main#anchor","parameters":None}),
            ("httpd://example.com:8080/main#anchor?",{"url":"httpd://example.com:8080/main#anchor?","domain":"example.com","port":8080,"path":"/main#anchor","parameters":None}),
            ("/main#anchor?",{"url":"/main#anchor?","domain":None,"port":None,"path":"/main#anchor","parameters":None}),
            ("/main#anchor",{"url":"/main#anchor","domain":None,"port":None,"path":"/main#anchor","parameters":None}),
            ("#anchor",{"url":"#anchor","domain":None,"port":None,"path":"#anchor","parameters":None}),
            ("#anchor?",{"url":"#anchor?","domain":None,"port":None,"path":"#anchor","parameters":None}),
            ("#anchor?a=1",{"url":"#anchor?a=1","domain":None,"port":None,"path":"#anchor","parameters":"a=1"})
        ]
        for url, result in testcases:
            if isinstance(result,dict):
                r = utils.parse_url(url)
                print("utils.parse_url('{}') = {}".format(url,r))
                self.assertEqual(r,result,"Expect result '{}', but got '{}'".format(result,r))
            else:
                self.assertRaises(result,utils.parse_url,url)
                
    def test_get_domain(self):
        print("============================================================================")
        testcases = [
            ("https://example.com/main?a=1","example.com"),
            ("http://example.com/main?a=1","example.com"),
            ("example.com/main?a=1","example.com"),
            ("https://example.com:8080/main?a=1","example.com"),
            ("https://example.com:8080/main#anchor?a=1","example.com"),
            ("https://example.com:8080/main#anchor?","example.com"),
            ("/main#anchor?",None),
            ("/main#anchor",None),
            ("#anchor",None),
            ("#anchor?",None),
            ("#anchor?a=1",None),
            ("htt://example.com","example.com"),
            ("httpa://example.com","example.com")
        ]
        for url, result in testcases:
            r = utils.get_domain(url)
            print("utils.get_domain('{}') = {}".format(url,r))
            self.assertEqual(r,result,"get_domain('{}') : Expect result '{}', but got '{}'".format(url,result,r))
                
    def test_get_domain_path(self):
        print("============================================================================")
        testcases = [
            ("https://example.com/main?a=1",("example.com","/main?a=1")),
            ("http://example.com/main?a=1",("example.com","/main?a=1")),
            ("example.com/main?a=1",("example.com","/main?a=1")),
            ("https://example.com:8080/main?a=1",("example.com","/main?a=1")),
            ("https://example.com:8080/main#anchor?a=1",("example.com","/main#anchor?a=1")),
            ("https://example.com:8080/main#anchor?",("example.com","/main#anchor?")),
            ("/main#anchor?",(None,"/main#anchor?")),
            ("/main#anchor",(None,"/main#anchor")),
            ("#anchor",(None,"#anchor")),
            ("#anchor?",(None,"#anchor?")),
            ("#anchor?a=1",(None,"#anchor?a=1")),
            ("htt://example.com",("example.com",None)),
            ("httpa://example.com",("example.com",None))
        ]
        for url, result in testcases:
            r = utils.get_domain_path(url)
            print("utils.get_domain_path('{}') = {}".format(url,r))
            self.assertEqual(r,result,"get_domain_path('{}') : Expect result '{}', but got '{}'".format(url,result,r))
                
    def test_redis_re(self):
        print("============================================================================")
        from .redis import redis_re
        testcases = [
            ("redis://admin:12345@localhost:6379/1",{"protocol":"redis","user":"admin","password":"12345","host":"localhost","port":"6379","db":"1"}),
            ("  redis://admin:12345@localhost:6379/1  ",{"protocol":"redis","user":"admin","password":"12345","host":"localhost","port":"6379","db":"1"}),
            ("rediss://admin:12345@localhost:6379/1",{"protocol":"rediss","user":"admin","password":"12345","host":"localhost","port":"6379","db":"1"}),
            ("redis://admin:@localhost:6379/1",{"protocol":"redis","user":"admin","password":None,"host":"localhost","port":"6379","db":"1"}),
            ("redis://admin@localhost:6379/1",{"protocol":"redis","user":"admin","password":None,"host":"localhost","port":"6379","db":"1"}),
            ("redis://:12345@localhost:6379/1",{"protocol":"redis","user":None,"password":"12345","host":"localhost","port":"6379","db":"1"}),
            ("rediss://admin:12345@localhost/1",{"protocol":"rediss","user":"admin","password":"12345","host":"localhost","port":None,"db":"1"}),
            ("rediss://admin@localhost/1",{"protocol":"rediss","user":"admin","password":None,"host":"localhost","port":None,"db":"1"}),
            ("rediss://:12345@localhost/1",{"protocol":"rediss","user":None,"password":"12345","host":"localhost","port":None,"db":"1"}),
            ("rediss://:12345@localhost",{"protocol":"rediss","user":None,"password":"12345","host":"localhost","port":None,"db":None}),
            ("redis://:12345@localhost:6379",{"protocol":"redis","user":None,"password":"12345","host":"localhost","port":"6379","db":None}),
        ]
        for url, result in testcases:
            m = redis_re.search(url)
            if result:
                self.assertNotEqual(m,None,"The redis url({}) should be valid".format(url))
                for k,v in result.items():
                    self.assertEqual(m.group(k),v,"The {1} of the redis url('{0}') should be {2}, but got {3}".format(url,k,v,m.group(k)))
            else:
                self.assertEqual(m,None,"url({}) is invalid".format(url))

    def test_html_body_re(self):
        print("============================================================================")
        from .emails import html_body_re
        testcases = [
            ("<html>ss",True),
            (" <html>ss",True),
            (" <html ",True),
            (""" <html
""",True),
            (" html ",False),
            (" <htl ",False),
            (" <htmla",False),
            (" <html",False),
        ]
        for text, result in testcases:
            m = html_body_re.search(text)
            self.assertEqual(True if m else False,result,"Text({}) should{} be html".format(text,"" if m else " not"))

    def test_basic_auth_re(self):
        print("============================================================================")
        from .views.views import basic_auth_re
        testcases = [
            ("Basic 123456","123456"),
            ("Basic    123456","123456"),
            ("Basic    123456+=/","123456+=/"),
            (" Basic    123456",None),
            ("Basic    123456 ",None),
            ("Baasic 123456 ",None),
        ]
        for text, result in testcases:
            m = basic_auth_re.search(text)
            self.assertEqual(m.group(1) if m else None ,result,"Basic auth({}) should be {},but got {}".format(text,result,m.group(1) if m else None))

    def test_bearer_token_re(self):
        print("============================================================================")
        from .views.views import bearer_token_re
        testcases = [
            ("Bearer 123456","123456"),
            ("Bearer    123456","123456"),
            (" Bearer    123456",None),
            ("Bearer    123456 ","123456"),
            ("Bearer 123456 ", "123456"),
            ("Bearer 123456%^&$ ", "123456%^&$")
        ]
        for text, result in testcases:
            m = bearer_token_re.search(text)
            self.assertEqual(m.group(1) if m else None ,result,"The bearer token({}) should be {},but got {}".format(text,result,m.group(1) if m else None))

    def test_email_re(self):
        print("============================================================================")
        from .views.views import email_re
        testcases = [
            ("test@example.com",True),
            ("test@example.com.au",True),
            ("test@example-a.com.au",True),
            ("test@example-a.com-b.au",True),
            ("test.08@example-a.com-b.au",True),
            ("Test.08@example-a.com-b.au",True),
            ("Test.!#$%&’'*+/=?^_`{|}~-@example-a.com-b.au",True),
            (" test@example.com",False),
            ("test@example.com ",False),
            ("test@example_.com.au",False),
            ("test@example_a.com.au",False),
            ("test@example_a#.com.au",False)
        ]
        for email, result in testcases:
            m = email_re.search(email)
            self.assertEqual(True if m else False,result,"Email address({}) should be {}".format(email,"valid" if result else "invalid"))

