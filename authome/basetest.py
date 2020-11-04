# -*- coding: utf-8 -*-
from collections import OrderedDict

from django.contrib.auth.models import User
from django.urls import reverse
from django.test import TestCase, Client

import base64

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access,UserToken
from .cache import cache

class BaseAuthTestCase(TestCase):
    client = Client()
    home_url = reverse('home')
    auth_url = reverse('auth')
    auth_token_url = reverse('auth_token')
    test_usergroups = None
    test_usergroupauthorization = None
    test_userauthorization = None
    test_users = None


    def create_client(self):
        return Client()

    def setUp(self):
        User.objects.filter(email__endswith="@gunfire.com").delete()
        UserToken.objects.all().delete()
        UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()
        UserAuthorization.objects.all().delete()

    def basic_auth(self, username, password):
        return 'Basic {}'.format(base64.b64encode('{}:{}'.format(username, password).encode('utf-8')).decode('utf-8'))

    def populate_testdata(self):
        #popuate UserGroup objects
        users = OrderedDict()
        if self.test_users:
            for test_user in self.test_users:
                obj = User(username=test_user[0],email=test_user[1])
                obj.save()
                users[test_user[0]] = obj
                if len(test_user) >= 3 and test_user[2]:
                    token = UserToken(user=obj,enabled=True)
                    token.generate_token()
                    token.save()
        self.test_users = users

        if self.test_usergroups:
            uncreated_usergroups = [(UserGroup.public_group(),self.test_usergroups)]
            while uncreated_usergroups:
                parent_obj,subgroup_datas = uncreated_usergroups.pop()
                for name,users,excluded_users,subgroups in subgroup_datas:
                    obj = UserGroup(name=name,users=users,excluded_users=excluded_users,parent_group=parent_obj)
                    obj.clean()
                    obj.save()
                    if subgroups:
                        uncreated_usergroups.append((obj,subgroups))

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



