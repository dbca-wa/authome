# -*- coding: utf-8 -*-
from collections import OrderedDict
from datetime import timedelta

from django.urls import reverse
from django.test import TestCase, Client
from django.conf import settings

import base64

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access,UserToken,User
from .cache import cache
groupid = 0
class BaseAuthTestCase(TestCase):
    client = Client()
    home_url = reverse('home')
    auth_url = reverse('auth')
    auth_basic_url = reverse('auth_basic')
    test_usergroups = None
    test_usergroupauthorization = None
    test_userauthorization = None
    test_users = None


    def create_client(self):
        return Client()

    def setUp(self):
        if settings.RELEASE:
            print("Running in release mode")
        else:
            print("Running in dev mode")
        settings.AUTH_CACHE_SIZE=2000
        settings.AUTH_BASIC_CACHE_SIZE=1000
        settings.AUTH_BASIC_CACHE_EXPIRETIME=timedelta(seconds=3600)
        settings.AUTH_CACHE_EXPIRETIME=timedelta(seconds=3600)
        settings.AUTH_CACHE_CLEAN_HOURS = [0]
        settings.AUTHORIZATION_CACHE_CHECK_HOURS = [0,12]

        settings.CHECK_AUTH_BASIC_PER_REQUEST = False
        User.objects.filter(email__endswith="@gunfire.com").delete()
        User.objects.filter(email__endswith="@gunfire.com.au").delete()
        User.objects.filter(email__endswith="@hacker.com").delete()
        UserToken.objects.all().delete()
        UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()
        UserAuthorization.objects.all().delete()

        cache.refresh_authorization_cache(True)
        if not UserGroup.objects.filter(users=["*"], excluded_users__isnull=True).exists():
            public_group = UserGroup(name="Public User",groupid="PUBLIC",users=["*"])
            public_group.clean()
            public_group.save()

        cache.clean_auth_cache(True)
        cache.refresh_authorization_cache(True)


    def basic_auth(self, username, password):
        return 'Basic {}'.format(base64.b64encode('{}:{}'.format(username, password).encode('utf-8')).decode('utf-8'))

    def populate_testdata(self):
        #popuate UserGroup objects
        if self.test_usergroups:
            uncreated_usergroups = [(UserGroup.public_group(),self.test_usergroups)]
            while uncreated_usergroups:
                parent_obj,subgroup_datas = uncreated_usergroups.pop()
                for name,users,excluded_users,subgroups in subgroup_datas:
                    obj = UserGroup(name=name,groupid=name,users=users,excluded_users=excluded_users,parent_group=parent_obj)
                    obj.clean()
                    print("save usergroup={}".format(obj))
                    obj.save()
                    if subgroups:
                        uncreated_usergroups.append((obj,subgroups))

        users = OrderedDict()
        if self.test_users:
            for test_user in self.test_users:
                obj = User(username=test_user[0],email=test_user[1])
                obj.clean()
                obj.save()
                users[test_user[0]] = obj
                if len(test_user) >= 3 and test_user[2]:
                    token = UserToken(user=obj,enabled=True)
                    token.generate_token()
                    token.save()
        self.test_users = users

        if self.test_usergroupauthorization:
            for groupname,domain,paths,excluded_paths in self.test_usergroupauthorization :
                obj = UserGroupAuthorization(usergroup=UserGroup.objects.get(name=groupname),domain=domain,paths=paths,excluded_paths=excluded_paths)
                obj.clean()
                obj.save()
    
        if self.test_userauthorization: 
            for user,domain,paths,excluded_paths in self.test_userauthorization:
                obj = UserAuthorization(user=user,domain=domain,paths=paths,excluded_paths=excluded_paths)
                obj.clean()
                obj.save()

        cache.refresh_authorization_cache(True)

class BaseAuthCacheTestCase(BaseAuthTestCase):
    def setUp(self):
        super().setUp()
        settings.AUTH_CACHE_SIZE=3
        settings.AUTH_BASIC_CACHE_SIZE=3
        settings.AUTH_BASIC_CACHE_EXPIRETIME=timedelta(seconds=5)
        settings.AUTH_CACHE_EXPIRETIME=timedelta(seconds=5)
        settings.AUTH_CACHE_CLEAN_HOURS = [i for i in range(0,24)]
        settings.AUTHORIZATION_CACHE_CHECK_HOURS = [i for i in range(0,24)]

