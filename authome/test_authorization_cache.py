# -*- coding: utf-8 -*-
from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from django.test import TestCase, Client

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access
from .cache import cache,HourListTaskRunable
from .basetest import BaseAuthCacheTestCase

class AuthorizationCacheTestCase(BaseAuthCacheTestCase):

    def test_authorize(self):
        test_datas = [
            #0
            ( 
                [
                    ("usergroup","add",["all_user",None,["*@*.*"],None]),
                    ("usergroupauthorization","add",["all_user","*",None,["*"]]),
                ],
                [
                    ("hacker1@hacker.com","gunfire.com","/register",False),
                    ("hacker1@hacker.com","map.gunfire.com","/register",False),
        
                    ("staff_1@gunfire.com.au","gunfire.com","/about",False),
                    ("staff_1@gunfire.com.au","gunfire.com","/register",False),
                    ("staff_1@gunfire.com.au","gunfire.com","/unregister",False),
        
                    ("staff_1@gunfire.com","gunfire.com","/about",False),
                    ("staff_1@gunfire.com","gunfire.com","/register",False),
                    ("staff_1@gunfire.com","gunfire.com","/unregister",False),
        
                    ("dev_1@gunfire.com","gunfire.com","/about",False),
                    ("dev_1@gunfire.com","gunfire.com","/register",False),
                    ("dev_1@gunfire.com","gunfire.com","/unregister",False),
                    ("dev_1@gunfire.com","gunfire.com","/start",False),
                    ("dev_1@gunfire.com","gunfire.com","/shutdown",False),
        
                    ("dev_2@gunfire.com","gunfire.com","/about",False),
                    ("dev_2@gunfire.com","gunfire.com","/register",False),
                    ("dev_2@gunfire.com","gunfire.com","/unregister",False),
                    ("dev_2@gunfire.com","gunfire.com","/start",False),
                    ("dev_2@gunfire.com","gunfire.com","/shutdown",False)
                ]
            ),
            #1
            (
                [
                    ("usergroupauthorization","add",["all_user","game.gunfire.com",None,None]),
                    ("usergroupauthorization","add",["all_user","gunfire.com",None,["/register","/start","/shutdown"]])
                ],
                [
                    ("hacker1@hacker.com","gunfire.com","/register",False),
                    ("hacker1@hacker.com","map.gunfire.com","/register",False),
        
                    ("staff_1@gunfire.com.au","gunfire.com","/about",True),
                    ("staff_1@gunfire.com.au","gunfire.com","/register",False),
                    ("staff_1@gunfire.com.au","gunfire.com","/unregister",True),
        
                    ("staff_1@gunfire.com","gunfire.com","/about",True),
                    ("staff_1@gunfire.com","gunfire.com","/register",False),
                    ("staff_1@gunfire.com","gunfire.com","/unregister",True),
        
                    ("dev_1@gunfire.com","gunfire.com","/about",True),
                    ("dev_1@gunfire.com","gunfire.com","/register",False),
                    ("dev_1@gunfire.com","gunfire.com","/unregister",True),
                    ("dev_1@gunfire.com","gunfire.com","/start",False),
                    ("dev_1@gunfire.com","gunfire.com","/shutdown",False),
        
                    ("dev_2@gunfire.com","gunfire.com","/about",True),
                    ("dev_2@gunfire.com","gunfire.com","/register",False),
                    ("dev_2@gunfire.com","gunfire.com","/unregister",True),
                    ("dev_2@gunfire.com","gunfire.com","/start",False),
                    ("dev_2@gunfire.com","gunfire.com","/shutdown",False)
                ]
            ),
            #2
            (
                [
                    ("usergroup","add",["gunfire","all_user",["@gunfire.com"],None]),
                    ("usergroup","add",["dev","gunfire",["dev_*@gunfire.com"],None]),
                    ("usergroupauthorization","add",["gunfire","gunfire.com",None,["/register","/unregister","/start","/shutdown"]]),
                    ("usergroupauthorization","add",["dev","gunfire.com",None,["/unregister","/shutdown"]])
                ],
                [
                    ("hacker1@hacker.com","gunfire.com","/register",False),
                    ("hacker1@hacker.com","map.gunfire.com","/register",False),
        
                    ("staff_1@gunfire.com.au","gunfire.com","/about",True),
                    ("staff_1@gunfire.com.au","gunfire.com","/register",False),
                    ("staff_1@gunfire.com.au","gunfire.com","/unregister",True),
        
                    ("staff_1@gunfire.com","gunfire.com","/about",True),
                    ("staff_1@gunfire.com","gunfire.com","/register",False),
                    ("staff_1@gunfire.com","gunfire.com","/unregister",False),
        
                    ("dev_1@gunfire.com","gunfire.com","/about",True),
                    ("dev_1@gunfire.com","gunfire.com","/register",True),
                    ("dev_1@gunfire.com","gunfire.com","/unregister",False),
                    ("dev_1@gunfire.com","gunfire.com","/start",True),
                    ("dev_1@gunfire.com","gunfire.com","/shutdown",False),
        
                    ("dev_2@gunfire.com","gunfire.com","/about",True),
                    ("dev_2@gunfire.com","gunfire.com","/register",True),
                    ("dev_2@gunfire.com","gunfire.com","/unregister",False),
                    ("dev_2@gunfire.com","gunfire.com","/start",True),
                    ("dev_2@gunfire.com","gunfire.com","/shutdown",False)
                ]
            ),
            #3
            (
                [
                    ("userauthorization","add",["dev_1@gunfire.com","gunfire.com",None,None]),
                    ("userauthorization","add",["hacker1@hacker.com","gunfire.com",None,None])
                ],
                [
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
                    ("dev_2@gunfire.com","gunfire.com","/shutdown",False)
                ]
            ),
            #4
            (
                [
                    ("usergroup","update",["gunfire","all_user",["@gunfire.com","@gunfire.com.au"],None]),
                    ("userauthorization","update",["dev_1@gunfire.com","gunfire.com",None,["/shutdown"]]),
                    ("userauthorization","update",["hacker1@hacker.com","gunfire.com",None,["/register"]]),
                    ("usergroupauthorization","update",["dev","gunfire.com",None,["/unregister"]])
                ],
                [
                    ("hacker1@hacker.com","gunfire.com","/register",False),
                    ("hacker1@hacker.com","map.gunfire.com","/register",False),
        
                    ("staff_1@gunfire.com.au","gunfire.com","/about",True),
                    ("staff_1@gunfire.com.au","gunfire.com","/register",False),
                    ("staff_1@gunfire.com.au","gunfire.com","/unregister",False),
        
                    ("staff_1@gunfire.com","gunfire.com","/about",True),
                    ("staff_1@gunfire.com","gunfire.com","/register",False),
                    ("staff_1@gunfire.com","gunfire.com","/unregister",False),
        
                    ("dev_1@gunfire.com","gunfire.com","/about",True),
                    ("dev_1@gunfire.com","gunfire.com","/register",True),
                    ("dev_1@gunfire.com","gunfire.com","/unregister",True),
                    ("dev_1@gunfire.com","gunfire.com","/start",True),
                    ("dev_1@gunfire.com","gunfire.com","/shutdown",False),
        
                    ("dev_2@gunfire.com","gunfire.com","/about",True),
                    ("dev_2@gunfire.com","gunfire.com","/register",True),
                    ("dev_2@gunfire.com","gunfire.com","/unregister",False),
                    ("dev_2@gunfire.com","gunfire.com","/start",True),
                    ("dev_2@gunfire.com","gunfire.com","/shutdown",True)
                ]
            ),
            #5
            (
                [
                    ("usergroup","update",["gunfire","all_user",["@gunfire.com"],None]),
                    ("userauthorization","delete",["dev_1@gunfire.com","gunfire.com",None,None]),
                    ("userauthorization","delete",["hacker1@hacker.com","gunfire.com",None,None])
                ],
                [
                    ("hacker1@hacker.com","gunfire.com","/register",False),
                    ("hacker1@hacker.com","map.gunfire.com","/register",False),
        
                    ("staff_1@gunfire.com.au","gunfire.com","/about",True),
                    ("staff_1@gunfire.com.au","gunfire.com","/register",False),
                    ("staff_1@gunfire.com.au","gunfire.com","/unregister",True),
        
                    ("staff_1@gunfire.com","gunfire.com","/about",True),
                    ("staff_1@gunfire.com","gunfire.com","/register",False),
                    ("staff_1@gunfire.com","gunfire.com","/unregister",False),
        
                    ("dev_1@gunfire.com","gunfire.com","/about",True),
                    ("dev_1@gunfire.com","gunfire.com","/register",True),
                    ("dev_1@gunfire.com","gunfire.com","/unregister",False),
                    ("dev_1@gunfire.com","gunfire.com","/start",True),
                    ("dev_1@gunfire.com","gunfire.com","/shutdown",True),
        
                    ("dev_2@gunfire.com","gunfire.com","/about",True),
                    ("dev_2@gunfire.com","gunfire.com","/register",True),
                    ("dev_2@gunfire.com","gunfire.com","/unregister",False),
                    ("dev_2@gunfire.com","gunfire.com","/start",True),
                    ("dev_2@gunfire.com","gunfire.com","/shutdown",True)
                ]
            ),
            #6
            (
                [
                    ("usergroup","delete",["dev"]),
                    ("usergroup","delete",["gunfire"]),
                ],
                [
                    ("hacker1@hacker.com","gunfire.com","/register",False),
                    ("hacker1@hacker.com","map.gunfire.com","/register",False),
        
                    ("staff_1@gunfire.com.au","gunfire.com","/about",True),
                    ("staff_1@gunfire.com.au","gunfire.com","/register",False),
                    ("staff_1@gunfire.com.au","gunfire.com","/unregister",True),
        
                    ("staff_1@gunfire.com","gunfire.com","/about",True),
                    ("staff_1@gunfire.com","gunfire.com","/register",False),
                    ("staff_1@gunfire.com","gunfire.com","/unregister",True),
        
                    ("dev_1@gunfire.com","gunfire.com","/about",True),
                    ("dev_1@gunfire.com","gunfire.com","/register",False),
                    ("dev_1@gunfire.com","gunfire.com","/unregister",True),
                    ("dev_1@gunfire.com","gunfire.com","/start",False),
                    ("dev_1@gunfire.com","gunfire.com","/shutdown",False),
        
                    ("dev_2@gunfire.com","gunfire.com","/about",True),
                    ("dev_2@gunfire.com","gunfire.com","/register",False),
                    ("dev_2@gunfire.com","gunfire.com","/unregister",True),
                    ("dev_2@gunfire.com","gunfire.com","/start",False),
                    ("dev_2@gunfire.com","gunfire.com","/shutdown",False)
                ]
            ),
        ]
        index = -1
        for testconfigs,testcases in test_datas:
            index += 1
            for table,action,configdata in testconfigs:
                if table == "usergroup":
                    if action == "add":
                        obj = UserGroup(
                            name=configdata[0],
                            parent_group=UserGroup.objects.get(name=configdata[1]) if configdata[1] else None,
                            users=configdata[2],
                            excluded_users=configdata[3]
                        )
                        obj.clean()
                        obj.save()
                    elif action == "update":
                        obj = UserGroup.objects.get(name=configdata[0])
                        obj.parent_group=UserGroup.objects.get(name=configdata[1]) if configdata[1] else None
                        obj.users = configdata[2]
                        obj.excluded_users = configdata[3]
                        obj.clean()
                        obj.save()
                    elif action == "delete":
                        UserGroup.objects.filter(name=configdata[0]).delete()
                    else:
                        raise Exception("Unknown action '{1}' for table '{0}'".format(table,action))

                elif table == "usergroupauthorization":
                    usergroup = UserGroup.objects.get(name=configdata[0])
                    if action == "add":
                        obj = UserGroupAuthorization(
                            usergroup=usergroup,
                            domain=configdata[1],
                            paths=configdata[2],
                            excluded_paths=configdata[3]
                        )
                        obj.clean()
                        obj.save()
                    elif action == "update":
                        obj = UserGroupAuthorization.objects.get(usergroup=usergroup,domain=configdata[1])
                        obj.paths = configdata[2]
                        obj.excluded_paths = configdata[3]
                        obj.clean()
                        obj.save()
                    elif action == "delete":
                        UserGroupAuthorization.objects.filter(usergroup=usergroup,domain=configdata[1]).delete()
                    else:
                        raise Exception("Unknown action '{1}' for table '{0}'".format(table,action))

                elif table == "userauthorization":
                    if action == "add":
                        obj = UserAuthorization(
                            user=configdata[0],
                            domain=configdata[1],
                            paths=configdata[2],
                            excluded_paths=configdata[3]
                        )
                        obj.clean()
                        obj.save()
                    elif action == "update":
                        obj = UserAuthorization.objects.get(user=configdata[0],domain=configdata[1])
                        obj.paths = configdata[2]
                        obj.excluded_paths = configdata[3]
                        obj.clean()
                        obj.save()
                    elif action == "delete":
                        UserAuthorization.objects.filter(user=configdata[0],domain=configdata[1]).delete()
                    else:
                        raise Exception("Unknown action '{1}' for table '{0}'".format(table,action))

                else:
                    raise Exception("Unknown table '{}'".format(table))


            cache._authorization_cache_check_time = HourListTaskRunable("authorization cache",settings.AUTHORIZATION_CACHE_CHECK_HOURS)
            cache._authorization_cache_check_time.can_run(timezone.localtime() - timedelta(hours=1))
            
            for email,domain,path,result in testcases:
                if index == 1 and path == "/about":
                    #import ipdb;ipdb.set_trace()
                    pass
                if domain == "map.dev.gunfire.com" and email=="staff1@gunfire.com":
                    #import ipdb;ipdb.set_trace()
                    pass
                self.assertEqual(can_access(email,domain,path),result,
                    msg="Test scenario({}): {} should {} the permission to access https://{}{}".format(index,email,"have" if result else "not have",domain,path)
                )
            

