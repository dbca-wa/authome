# -*- coding: utf-8 -*-
from django.contrib.auth.models import User
from django.urls import reverse
from django.test import TestCase, Client

import base64

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access
from .cache import cache

class AuthTestCase(TestCase):
    client = Client()
    home_url = reverse('home')
    auth_url = reverse('auth')
    username = 'testu'
    email = 'test.user@test.domain'
    password = 'testpass'
    test_usergroups = None
    test_usergroupauthorization = None
    test_userauthorization = None

    def setUp(self):
        self.test_user = User.objects.create(username=self.username, email=self.email)

    def basic_auth(self, username, password):
        return 'Basic {}'.format(base64.b64encode('{}:{}'.format(username, password).encode('utf-8')).decode('utf-8'))

#    @mock.patch('adal.AuthenticationContext.acquire_token_with_username_password')
#    def test_home_redirects(self, mock_api_call):
#        mock_api_call.return_value = {
#            'userId': self.email
#        }

#        response = self.client.get(self.home_url)
#        self.assertRedirects

    def populate_testdata(self):
        #popuate UserGroup objects
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

        cache.refresh(True)

    def test_auth(self):
        self.test_usergroups = [
            ("all_user",["*@*"],None,None)
        ]
        self.test_usergroupauthorization = [
            ("all_user","*","*",None)
        ]
        self.populate_testdata()

        #test sso_auth without authentication   
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,401,msg="Should return 401 response for unauthenticated request")
        
        #test sso_auth after authentication   
        self.client.force_login(self.test_user)
        res = self.client.get(self.auth_url)
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.has_header('X-auth-cache-hit'),False,msg="Should authenticate the user without hit the cache")

        res = self.client.get(self.auth_url,HTTP_X_UPSTREAM_SERVER_NAME="gunfire.com",HTTP_X_UPSTREAM_REQUEST_URI="/about")
        self.assertEqual(res.status_code,200,msg="Should return 200 response for authenticated request")
        self.assertEqual(res.get('X-auth-cache-hit'),'success',msg="Already authenticated, should hit the cache")

