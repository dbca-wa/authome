from django.test import TestCase

from . import models


class UserEmailTestCase(TestCase):
    def test_type(self):
        testcases = [
            ("*",models.AllUserEmail),
            ("***",models.AllUserEmail),
            ("*@*",models.AllUserEmail),
            ("**@*",models.AllUserEmail),
            ("**@**",models.AllUserEmail),
            ("@dbca.wa.gov.au",models.DomainEmail),
            ("test@dbca.wa.gov.au",models.ExactUserEmail),
            ("test*@dbca.wa.gov.au",models.RegexUserEmail),
            ("t*est*@dbca.wa.gov.au",models.RegexUserEmail),
            ("*t*est*@dbca.wa.gov.au",models.RegexUserEmail),
            ("*t*est*@*.wa.gov.au",models.RegexUserEmail),
            ("*t*est*@*",models.RegexUserEmail)
        ]
        for email, email_type in testcases:
            email_obj = models.UserEmail.get_instance(email)
            self.assertEqual(email_obj.__class__,email_type,msg="The type of user email({}) should be {} instead of {}".format(email,email_type,email_obj.__class__))

    def test_match(self):
        testcases = [
            ("*","test@gmail.com",True),
            ("**","test@gmail.com",True),
            ("*@*","test@gmail.com",True),
            ("**@**","test@gmail.com",True),
            ("@gmail.com","test@gmail.com",True),
            ("@gmail.com","test@gmail.com.au",False),
            ("*@gmail.com.*","test@gmail.com.au",True),
            ("*@gmail.com.*","test@gmail.com",False),
            ("test*@gmail.com*","test@gmail.com",True),
            ("test*@gmail.com*","test@gmail.com.au",True),
            ("test*@gmail.com*","1test@gmail.com",False),
            ("test*@gmail.com*","1test@gmail.com.au",False),
            ("test*_dev*@gmail.com*","test@gmail.com.au",False),
            ("test*_dev*@gmail.com*","test_dev@gmail.com.au",True),
            ("test*_dev*@gmail.com*","test23_dev_ewr@gmail.com.au",True),
            ("test*_dev*@gmail.com*","test23_dedv_ewr@gmail.com.au",False),
        ]

        for email_pattern, test_email, result in testcases:
            email_obj = models.UserEmail.get_instance(email_pattern)
            self.assertEqual(email_obj.match(test_email),result,msg="The user email({}) should {} contained by email pattern({})".format(test_email, "be" if result else "not be",email_pattern))

    def test_contain(self):
        testcases = [
            ("*","*",True),
            ("*","test@gmail.com",True),
            ("*","@gmail.com",True),
            ("*","test*@gmail.com*",True),

            ("test@gmail.com","*",False),
            ("test@gmail.com","test@gmail.com",True),
            ("test@gmail.com","test@gmail.com.au",False),
            ("test@gmail.com","test1@gmail.com",False),
            ("test@gmail.com","@gmail.com",False),
            ("test@gmail.com","test*@gmail.com",False),

            ("@gmail.com","*",False),
            ("@gmail.com","test@gmail.com",True),
            ("@gmail.com","test1@gmail.com",True),
            ("@gmail.com","test1@gmail.com.au",False),
            ("@gmail.com","@gmail.com",True),
            ("@gmail.com","@gmail.com.au",False),
            ("@gmail.com","*@gmail.com",True),
            ("@gmail.com","*@gmail.com*",False),
            ("@gmail.com","test*@gmail.com",True),
            ("@gmail.com","test*@gmail.com*",False),

            ("test*dev*@gmail*.com","*",False),
            ("test*dev*@gmail*.com","test@gmail.com",False),
            ("test*dev*@gmail*.com","testdev@gmail.com",True),
            ("test*dev*@gmail*.com","test_dev@gmail.com",True),
            ("test*dev*@gmail*.com","test_dev01@gmail.com",True),
            ("test*dev*@gmail*.com","test_dee01@gmail.com",False),
            ("test*dev*@gmail*.com","test_dev01@gmail.com.au",False),

            ("test*dev*@gmail*.com","test@gmail1.com",False),
            ("test*dev*@gmail*.com","testdev@gmail1.com",True),
            ("test*dev*@gmail*.com","test_dev@gmail1.com",True),
            ("test*dev*@gmail*.com","test_dev01@gmail1.com",True),
            ("test*dev*@gmail*.com","test_dee01@gmail1.com",False),
            ("test*dev*@gmail*.com","test_dev01@gmail1.com.au",False),
            
            ("test*dev*@gmail*.com","test@gmail.test.com",False),
            ("test*dev*@gmail*.com","testdev@gmail.test.com",True),
            ("test*dev*@gmail*.com","test_dev@gmail.test.com",True),
            ("test*dev*@gmail*.com","test_dev01@gmail.test.com",True),
            ("test*dev*@gmail*.com","test_dee01@gmail.test.com",False),
            ("test*dev*@gmail*.com","test_dev01@gmail.test.com.au",False),

            ("test*dev*@gmail*.com*","test@gmail.test.com.au",False),
            ("test*dev*@gmail*.com*","testdev@gmail.test.com.au",True),
            ("test*dev*@gmail*.com*","test_dev@gmail.test.com.au",True),
            ("test*dev*@gmail*.com*","test_dev01@gmail.test.com.au",True),
            ("test*dev*@gmail*.com*","test_dee01@gmail.test.com.au",False),
        ]

        for email_pattern, child_email_pattern, result in testcases:
            email_obj = models.UserEmail.get_instance(email_pattern)
            child_email_obj = models.UserEmail.get_instance(child_email_pattern)
            self.assertEqual(email_obj.contain(child_email_obj),result,msg="The email pattern({}) should{} contain the child email pattern({})".format(email_pattern, "" if result else " not",child_email_pattern))

