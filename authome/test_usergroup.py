# -*- coding: utf-8 -*-
from datetime import timedelta

from django.contrib.auth.models import User
from django.urls import reverse
from django.utils import timezone
from django.test import TestCase
from django.conf import settings

import base64

from .models import UserGroup
from .cache import cache
from .basetest import BaseAuthTestCase

class UsergroupTestCase(BaseAuthTestCase):
    def test_sessiontimeout(self):
        self.test_usergroups = [
            ("staff","@staff.com",None,0,None),
            ("special user","*special*@test.com",None,1800,None),
            ("test user","@test.com",None,3600,[
                ("backend test user","*backend*@test.com",None,7200,None),
                ("frontend test user","*frontend*@test.com",None,600,None),
                ("manager user","*manager*@test.com",None,10800,None)
            ]),
        ]
        self.populate_testdata()
        for case in (
            ("test@example.com",UserGroup.public_group().session_timeout),
            ("test@staff.com",0),
            ("test1@test.com",3600),
            ("backend_test1@test.com",7200),
            ("frontend_test1@test.com",600),
            ("manager_test1@test.com",10800),
            ("manager_frontend_test1@test.com",10800),
            ("manager_backend_test1@test.com",10800),

            ("special_test1@test.com",3600),
            ("special_backend_test1@test.com",7200),
            ("special_frontend_test1@test.com",1800),
            ("special_manager_test1@test.com",10800),
            ("special_manager_frontend_test1@test.com",10800),
            ("special_manager_backend_test1@test.com",10800)
        ):
            usergroups = UserGroup.find_groups(case[0])[0]
            sessiontimeout = UserGroup.get_session_timeout(usergroups) or 0
            self.assertEqual(sessiontimeout,case[1],"The session timeout of user({0}) should be {1} instead of {2}".format(case[0],case[1],sessiontimeout))

 
