from django.test import TestCase

from . import models


class RequestDomainTestCase(TestCase):
    def test_type(self):
        testcases = [
            ("*",models.AllRequestDomain),
            ("**",models.AllRequestDomain),
            ("example.com",models.ExactRequestDomain),
            (".example.com",models.SufixRequestDomain),
            ("*.example.com",models.SufixRequestDomain),
            ("***.example.com",models.SufixRequestDomain),
            ("*example.com",models.RegexRequestDomain),
            ("example*.com",models.RegexRequestDomain),
            ("example*",models.RegexRequestDomain)
        ]
        for domain, domain_type in testcases:
            domain_obj = models.RequestDomain.get_instance(domain)
            self.assertEqual(domain_obj.__class__,domain_type,msg="The type of domain({}) should be {},but got {}".format(domain,domain_type,domain_obj.__class__))

    def test_match(self):
        testdata = [
            ("*",[("example.com",True)]),
            ("**",[("example.com",True)]),
            (".example.com",[
              ("example.com",False),
              ("dev.example.com",True),
              ("admin.dev.example.com",True),
              ("dev.example1.com",False)
            ]),
            ("*.example.com",[
              ("example.com",False),
              ("dev.example.com",True),
              ("admin.dev.example.com",True),
              ("dev.example1.com",False),
              ("dev.example.com.au",False)
            ]),
            ("example*.com",[
              ("example.com",True),
              ("example1.com",True),
              ("example.test.com",True),
              ("example.test.com.au",False),
              ("example.test.com1",False),
              ("dev.example.com",False)
            ]),
            ("*example*.com",[
              ("example.com",True),
              ("example1.com",True),
              ("example.test.com",True),
              ("testexample.com",True),
              ("test.example1.com",True),
              ("admin.test.example.test.com",True),
              ("example.test.com.au",False),
              ("example.test.com1",False),
              ("dev.example.com",True)
            ]),
            ("*example*.com*",[
              ("example.com",True),
              ("example1.com",True),
              ("example.test.com",True),
              ("testexample.com",True),
              ("test.example1.com",True),
              ("admin.test.example.test.com",True),
              ("example.test.com.au",True),
              ("example.test.com1",True),
              ("dev.example.com",True),
              ("dev.example.com1",True),
              ("dev.example.coam",False)
            ]),
        ]

        for domain_pattern, test_cases in testdata:
            domain_obj = models.RequestDomain.get_instance(domain_pattern)
            for test_domain,result in test_cases:
                self.assertEqual(domain_obj.match(test_domain),result,msg="The request domain({}) should {} matched by domain pattern({})".format(test_domain, "be" if result else "not be",domain_pattern))


