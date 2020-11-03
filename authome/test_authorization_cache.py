# -*- coding: utf-8 -*-
from django.test import TestCase, Client

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access
from .cache import get_cache

class AuthorizationCacheTestCase(TestCase):
    def setUp(self):
        #clear the unittest data
        UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()
        UserAuthorization.objects.all().delete()

    def test_authorize(self):
        cache = get_cache()
        test_usergroups = [
            ("all_user",["*@*"],None,[
                ("gunfire",["@gunfire.com"],None,[
                    ("dev",["dev_*@gunfire.com"],None,[])
                ])
            ])
        ]
        test_usergroupauthorization = [
            ("all_user","*",None,"*"),
            ("all_user","game.gunfire.com",None,None),
            ("all_user","gunfire.com",None,["/register"]),

            ("gunfire","gunfire.com",None,["/register","/unregister","/start","shutdown"]),

            ("dev","gunfire.com",None,["/unregister","/shutdown"]),
        ]

        test_userauthorization = [
            ("dev_1@gunfire.com","gunfire.com",None,None),
            ("hacker1@hacker.com","gunfire.com",None,None)
        ]
        testcases = [
            ("hacker1@hacker.com","gunfire.com","/register",True),
            ("hacker1@hacker.com","map.gunfire.com","/register",False),

            ("staff_1@gunfire.com.au","gunfire.com","/about",True),
            ("staff_1@gunfire.com.au","gunfire.com","/register",False),
            ("staff_1@gunfire.com.au","gunfire.com","/unregister",True),

            ("staff_1@gunfire.com","gunfire.com","/about",True),
            ("staff_1@gunfire.com","gunfire.com","/register",False),
            ("staff_1@gunfire.com","gunfire.com","/unregister",False),

            ("dev_1@gunfire.com","gunfire.com","/about",True),
            ("dev_1@gunfire.com","gunfire.com","/register",True),
            ("dev_1@gunfire.com","gunfire.com","/unregister",True),
            ("dev_1@gunfire.com","gunfire.com","/start",True),
            ("dev_1@gunfire.com","gunfire.com","/shutdown",True),

            ("dev_2@gunfire.com","gunfire.com","/about",True),
            ("dev_2@gunfire.com","gunfire.com","/register",True),
            ("dev_2@gunfire.com","gunfire.com","/unregister",False),
            ("dev_2@gunfire.com","gunfire.com","/start",True),
            ("dev_2@gunfire.com","gunfire.com","/shutdown",False),
        ]
        #popuate UserGroup objects
        uncreated_usergroups = [(UserGroup.public_group(),test_usergroups)]
        while uncreated_usergroups:
            parent_obj,subgroup_datas = uncreated_usergroups.pop()
            for name,users,excluded_users,subgroups in subgroup_datas:
                obj = UserGroup(name=name,users=users,excluded_users=excluded_users,parent_group=parent_obj)
                obj.clean()
                obj.save()
                if subgroups:
                    uncreated_usergroups.append((obj,subgroups))

        for groupname,domain,paths,excluded_paths in test_usergroupauthorization:
            obj = UserGroupAuthorization(usergroup=UserGroup.objects.get(name=groupname),domain=domain,paths=paths,excluded_paths=excluded_paths)
            obj.clean()
            obj.save()
    
        for user,domain,paths,excluded_paths in test_userauthorization:
            obj = UserAuthorization(user=user,domain=domain,paths=paths,excluded_paths=excluded_paths)
            obj.clean()
            obj.save()

        cache.refresh_authorization_cache(True)
        for email,domain,path,result in testcases:
            if domain == "map.dev.gunfire.com" and email=="staff1@gunfire.com":
                #import ipdb;ipdb.set_trace()
                pass
            self.assertEqual(can_access(email,domain,path),result,msg="{} should {} the permission to access https://{}{}".format(email,"have" if result else "not have",domain,path))
            

