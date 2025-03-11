# -*- coding: utf-8 -*-
from collections import OrderedDict
from datetime import timedelta
from importlib import import_module

from django.urls import reverse
from django.test import TestCase, Client
from django.conf import settings

import base64

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access,UserToken,User,CustomizableUserflow
from .cache import cache,get_usercache
from authome import patch
groupid = 0

class Auth2Client(Client):
    def get(self,path, authorization=None,domain=None,url=None):
        headers={"HOST":settings.AUTH2_DOMAIN,"SERVER_NAME":settings.AUTH2_DOMAIN}
        if authorization:
            headers["AUTHORIZATION"] = authorization
        if domain:
            headers["X_UPSTREAM_SERVER_NAME"] = domain
        elif path in ("/sso/auth","/sso/auth_basic","/sso/auth_optional","/sso/auth_basic_optional"):
            headers["X_UPSTREAM_SERVER_NAME"] = settings.AUTH2_DOMAIN

        if url:
            headers["X_UPSTREAM_REQUEST_URI"] = url

        if settings.AUTH2_CLUSTER_ENABLED:
            headers["X_LB_HASH_KEY"] = "test_lb_hashkey"
        return super().get(path,headers=headers)

    @property
    def session(self):
        """Return the current session variables."""
        engine = import_module(settings.SESSION_ENGINE)
        cookie = self.cookies.get(settings.SESSION_COOKIE_NAME)
        if cookie:
            return engine.SessionStore("test_lb_hashkey",settings.AUTH2_CLUSTERID,cookie.value)
        if settings.AUTH2_CLUSTER_ENABLED:
            session = engine.SessionStore("test_lb_hashkey",settings.AUTH2_CLUSTERID,None)
        else:
            session = engine.SessionStore()
        session.save()
        self.cookies[settings.SESSION_COOKIE_NAME] = session.session_key
        return session

    
class BaseTestCase(TestCase):
    test_usergroupauthorization = None
    test_userauthorization = None
    test_users = None
    test_usergroups = None
    @classmethod
    def setUpClass(cls):
        super(BaseTestCase,cls).setUpClass()
        print("*********************************************************")
        if settings.RELEASE:
            print("Running unitest({}) in release mode".format(cls.__name__))
        else:
            print("Running unitest({}) in dev mode".format(cls.__name__))

    def delete_testdata(self):
        #delete user group authorization
        if self.test_usergroupauthorization:
            for groupname,domain,paths,excluded_paths in self.test_usergroupauthorization :
                UserGroupAuthorization.objects.filter(usergroup=UserGroup.objects.get(name=groupname),domain=domain,paths=paths,excluded_paths=excluded_paths).delete()
    
        #delete user authorization
        if self.test_userauthorization: 
            for user,domain,paths,excluded_paths in self.test_userauthorization:
                UserAuthorization.objects.filter(user=user,domain=domain,paths=paths,excluded_paths=excluded_paths).delete()

        #delete users
        if self.test_users:
            for user in self.test_users.values():
                user.delete()


        #delete UserGroup objects
        if self.test_usergroups:
            del_usergroups = []
            created_usergroups = [(UserGroup.public_group(),self.test_usergroups)]
            while created_usergroups:
                parent_obj,subgroup_datas = created_usergroups.pop()
                for subgroup in subgroup_datas:
                    if len(subgroup) == 4:
                        name,users,excluded_users,subgroups = subgroup
                        session_timeout = None
                    else:
                        name,users,excluded_users,session_timeout,subgroups = subgroup

                    obj = UserGroup.objects.filter(name=name,parent_group=parent_obj).first()
                    if obj:
                        del_usergroups.insert(0,obj)
                    if subgroups:
                        created_usergroups.append((obj,subgroups))

            for usergroup in del_usergroups:
                usergroup.delete()

    def populate_testdata(self):
        #popuate UserGroup objects
        if self.test_usergroups:
            uncreated_usergroups = [(UserGroup.public_group(),self.test_usergroups)]
            while uncreated_usergroups:
                parent_obj,subgroup_datas = uncreated_usergroups.pop()
                for subgroup in subgroup_datas:
                    if len(subgroup) == 4:
                        name,users,excluded_users,subgroups = subgroup
                        session_timeout = None
                    else:
                        name,users,excluded_users,session_timeout,subgroups = subgroup

                    if users and isinstance(users,str):
                        users = [users]
                    if excluded_users and isinstance(excluded_users,str):
                        excluded_users = [excluded_users]
                     
                    obj = UserGroup.objects.filter(name=name).first()
                    if obj:
                        obj.groupid=name
                        obj.users=users
                        obj.excluded_users=excluded_users
                        obj.parent_group=parent_obj
                        obj.session_timeout=session_timeout
                    else:
                        obj = UserGroup(name=name,groupid=name,users=users,excluded_users=excluded_users,parent_group=parent_obj,session_timeout=session_timeout)
                    obj.clean()
                    print("save usergroup={}".format(obj))
                    obj.save()
                    if subgroups:
                        uncreated_usergroups.append((obj,subgroups))

        users = OrderedDict()
        if self.test_users:
            for test_user in self.test_users:
                obj = User.objects.filter(username=test_user[0]).first()
                if obj:
                    obj.email = test_user[1]
                else:
                    obj = User(username=test_user[0],email=test_user[1])
                obj.clean()
                obj.save()
                users[test_user[0]] = obj
                if len(test_user) >= 3 and test_user[2]:
                    token = UserToken(user=obj,enabled=True)
                    token.generate_token()
                    token.save()
                    usercache = get_usercache(token.user_id)
                    if usercache and usercache.get(settings.GET_USERTOKEN_KEY(token.user_id)):
                        #Only cache the user token only if it is already cached
                        usercache.set(settings.GET_USERTOKEN_KEY(token.user_id),token,settings.STAFF_CACHE_TIMEOUT if token.user.is_staff else settings.USER_CACHE_TIMEOUT)
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

class BaseAuthTestCase(BaseTestCase):
    client_class = Auth2Client
    home_url = reverse('home')
    auth_url = reverse('auth')
    auth_optional_url = reverse('auth_optional')
    auth_basic_url = reverse('auth_basic')
    auth_basic_optional_url = reverse('auth_basic_optional')


    def create_client(self):
        return Auth2Client()

    def setUp(self):
        settings.AUTH_CACHE_SIZE=2000
        settings.BASIC_AUTH_CACHE_SIZE=1000
        settings.AUTH_BASIC_CACHE_EXPIRETIME=timedelta(seconds=3600)
        settings.AUTH_CACHE_EXPIRETIME=timedelta(seconds=3600)
        settings.STAFF_AUTH_CACHE_EXPIRETIME=settings.AUTH_CACHE_EXPIRETIME
        settings.AUTH_CACHE_CLEAN_HOURS = [0]
        settings.AUTHORIZATION_CACHE_CHECK_HOURS = [0,12]

        settings.CHECK_AUTH_BASIC_PER_REQUEST = False

        if settings.AUTH2_CLUSTER_ENABLED:
            cache.current_auth2_cluster.register()
            cache._auth2_clusters.clear()
            cache.refresh_auth2_clusters(True)

        User.objects.filter(email__endswith="@gunfire.com").delete()
        User.objects.filter(email__endswith="@gunfire.com.au").delete()
        User.objects.filter(email__endswith="@hacker.com").delete()
        UserToken.objects.all().delete()
        UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()
        UserAuthorization.objects.all().delete()

        cache.refresh_authorization_cache(True)
        public_group = UserGroup.objects.filter(users=["*"], excluded_users__isnull=True).first()
        if public_group:
            public_group.session_timeout = 900
            public_group.save()
        else:
            public_group = UserGroup(name="Public User",groupid="PUBLIC",users=["*"],session_timeout=900)
            public_group.clean()
            public_group.save()
        if not CustomizableUserflow.objects.filter(domain="*").exists():
            default_flow = CustomizableUserflow(
                domain='*',
                default='default',
                mfa_set="default_mfa_set",
                mfa_reset="default_mfa_reset",
                password_reset="default_password_reset",
                verifyemail_from="oim@dbca.wa.gov.au",
                verifyemail_subject="test"
            )
            default_flow.clean()
            default_flow.save()

        cache.clean_auth_cache(True)
        cache.refresh_authorization_cache(True)


    def basic_auth(self, username, password):
        return 'Basic {}'.format(base64.b64encode('{}:{}'.format(username, password).encode('utf-8')).decode('utf-8'))

class BaseAuthCacheTestCase(BaseAuthTestCase):
    def setUp(self):
        super().setUp()
        settings.AUTH_CACHE_SIZE=3
        settings.BASIC_AUTH_CACHE_SIZE=3
        settings.AUTH_BASIC_CACHE_EXPIRETIME=timedelta(seconds=5)
        settings.AUTH_CACHE_EXPIRETIME=timedelta(seconds=5)
        settings.STAFF_AUTH_CACHE_EXPIRETIME=settings.AUTH_CACHE_EXPIRETIME
        settings.AUTH_CACHE_CLEAN_HOURS = [i for i in range(0,24)]
        settings.AUTHORIZATION_CACHE_CHECK_HOURS = [i for i in range(0,24)]

