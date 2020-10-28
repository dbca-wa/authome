# -*- coding: utf-8 -*-
from django.test import TestCase, Client

from .models import UserGroup,UserGroupRequests,UserRequests,can_access
from .cache import cache


#class UserGroupTestCase(TestCase):
class UserGroupTestCase(object):
    def setUp(self):
        #clear the unittest data
        UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()


    def test_delete_public_group(self):
        with self.assertRaises(Exception,msg="Delete public user group should throw exception."):
            UserGroup.public_group().delete()

    def test_duplicate_public_group(self):
        public_group = UserGroup.public_group()
        #create another public group
        public_group.id = None
        with self.assertRaises(Exception,msg="Save the second public user group should throw exception"):
            public_group.save()

    def test_save(self):
        index = 0
        for test_data,expected_data in [
            ((None,["*"]),(["*"],["*"])),
            ((["test2@test1.com","",None,"test1@test1.com","*1@*.com","@test3.com"],None),(["@test3.com","test1@test1.com","test2@test1.com","*1@*.com"],None)),
        ]:
            index += 1
            obj = UserGroup(name="test_{}".format(index),users=test_data[0],excluded_users=test_data[1])
            obj.clean()
            obj.save()
            users,excluded_users = expected_data
            self.assertEqual(obj.users,users,msg="The UserGroup(users={},excluded_users={}) is not matched with the expected user '{}'".format(obj.users,obj.excluded_users,users))
            self.assertEqual(obj.excluded_users,excluded_users,msg="The UserGroup(users={},excluded_users={}) is not matched with the expected excluded user '{}'".format(obj.users,obj.excluded_users,excluded_users))

    def test_contain(self):
        index = 0
        for test_data,testcases in [
            ((["*"],["*"]),[("test1@test1.com",False),("test2@test2.com",False)]),
            ((["@test1.com"],None),[("test1@test1.com",True),("test12@test1.com",True),("test2@test2.com",False),("test3@test3.com",False)]),
            ((["test1@test1.com"],None),[("test1@test1.com",True),("test12@test1.com",False),("test2@test2.com",False),("test3@test3.com",False)]),
            ((["*1@*.com"],None),[("test1@test1.com",True),("test12@test1.com",False),("test1@test2.com",True),("test1@test3.org",False)]),
            ((["*"],["@test1.com"]),[("test1@test1.com",False),("test2@test2.com",True),("test3@test3.com",True)]),
            ((["*"],["test1@test1.com"]),[("test1@test1.com",False),("test11@test1.com",True),("test2@test2.com",True)]),
            ((["*"],["*1@*.com"]),[("test1@test1.com",False),("test1@test2.com",False),("test1@test1.org",True),("test@test.com",True)]),
            ((["@test1.com","@test2.com","test3@test3.com","*1@*.org"],["test1@test1.com","test1@test.org"]),[("test1@test1.com",False),("test11@test1.com",True),("test2@test2.com",True),("test3@test3.com",True),("test31@test3.com",False),("test1@test.org",False),("test11@test.org",True),("test1@test.com",False)]),
            ((["@test1.com"],["@test1.com"]),[("test1@test1.com",False),("test2@test2.com",False)]),
        ]:
            index += 1
            obj = UserGroup(name="test_{}".format(index),users=test_data[0],excluded_users=test_data[1])
            obj.clean()
            obj.save()
            for email,result in testcases:
               self.assertEqual(obj.contain(email),result,msg="The UserGroup(users={},excluded_users={}) should {} the user({})".format(obj.users,obj.excluded_users,"contain" if result else "not contain",email,))


    def test_find(self):
        test_datas = [
            ("testcompany",["@test1.com"],None,[
                ("developers",["dev_*@test1.com"],None,[
                    ("app_developers",["dev_app_*@test1.com"],["dev_app_test*@test1.com"],[
                        ("app_dev_leaders",["dev_app_leader1@test1.com","dev_app_leader2@test1.com"],None,[
                            ("app_dev_manager",["dev_app_leader1@test1.com"],None,None)
                        ])
                    ])
                ]),
                ("supporters",["support_*@test1.com"],None,[])
            ])
        ]
        testcases = [
            ("test@test2.com",UserGroup.public_group().name),
            ("sales@test1.com","testcompany"),
            ("support_1@test1.com","supporters"),
            ("dev_1@test1.com","developers"),
            ("dev_app_1@test1.com","app_developers"),
            ("dev_app_leader2@test1.com","app_dev_leaders"),
            ("dev_app_leader1@test1.com","app_dev_manager")
        ]
        #popuate UserGroup objects
        pending_datas = [(UserGroup.public_group(),test_datas)]
        while pending_datas:
            parent_obj,subgroup_datas = pending_datas.pop()
            for name,users,excluded_users,subgroups in subgroup_datas:
                obj = UserGroup(name=name,users=users,excluded_users=excluded_users,parent_group=parent_obj)
                obj.clean()
                obj.save()
                if subgroups:
                    pending_datas.append((obj,subgroups))

        cache.refresh(True)
  
        for email,group_name in testcases:
            group = UserGroup.find(email)
            self.assertEqual(group.name,group_name,msg="{}: matched group({}) is not the expected group({})".format(email,group.name,group_name))
            
class UserRequestsTestCase(object):
    def setUp(self):
        #clear the unittest data
        UserRequests.objects.all().delete()

    def get_role(self,index):
        return "test{:0>3}".format(index)

    def get_role_requests(self,role,domain,paths,excluded_paths):
        return UserRequests(user=role,domain=domain,paths=paths,excluded_paths=excluded_paths)

    def test_save(self):
        index = 0
        for test_data,expected_data in [
            (("gunfire.com",None,None),("gunfire.com",None,None,True,False)),
            (("gunfire.com",["*"],None),("gunfire.com",["*"],None,True,False)),
            (("gunfire.com",["*","","**"],None),("gunfire.com",["*"],None,True,False)),
            (("gunfire.com",["/"],None),("gunfire.com",["/"],None,True,False)),
            (("gunfire.com",["/","*"],None),("gunfire.com",["*"],None,True,False)),
            (("gunfire.com",["/","*","=/info"],None),("gunfire.com",["*"],None,True,False)),

            (("gunfire.com",None,["*"]),("gunfire.com",None,["*"],False,True)),
            (("gunfire.com",None,["*","","**"]),("gunfire.com",None,["*"],False,True)),
            (("gunfire.com",None,["/"]),("gunfire.com",None,["/"],False,True)),
            (("gunfire.com",None,["/","*"]),("gunfire.com",None,["*"],False,True)),
            (("gunfire.com",None,["/","*","=/info"]),("gunfire.com",None,["*"],False,True)),

            (("gunfire.com",["*"],["/","*"]),("gunfire.com",["*"],["*"],False,True)),

            (("gunfire.com",["^.*$"],None),("gunfire.com",["^.*$"],None,True,False)),
            (("gunfire.com",["^.*$","/info"],None),("gunfire.com",["^.*$"],None,True,False)),

            (("gunfire.com",["=/about","^/api/.*/get$","/web"],None),("gunfire.com",["/web","^/api/.*/get$","=/about"],None,False,False))
        ]:
            index += 1
            domain,paths,excluded_paths = test_data
            user = self.get_role(index)
            expected_domain,expected_paths,expected_excluded_paths,expected_allow_all,expected_deny_all = expected_data
            obj = self.get_role_requests(user,domain,paths,excluded_paths)
            obj.clean()
            obj.save()
            self.assertEqual(obj.domain,expected_domain,msg="The UserRequests({},domain={}) is not matched with the expected domain '{}'".format(user,obj.domain,expected_domain))
            self.assertEqual(obj.paths,expected_paths,msg="The UserRequests({},paths={}) is not matched with the expected paths '{}'".format(user,obj.paths,expected_paths))
            self.assertEqual(obj.excluded_paths,expected_excluded_paths,msg="The UserRequests({},excluded_paths={}) is not matched with the expected excluded_paths '{}'".format(user,obj.excluded_paths,expected_excluded_paths))
            self.assertEqual(obj.allow_all,expected_allow_all,msg="The UserRequests({},allow_all={}) is not matched with the expected allow_all '{}'".format(user,obj.allow_all,expected_allow_all))
            self.assertEqual(obj.deny_all,expected_deny_all,msg="The UserRequests({},deny_all={}) is not matched with the expected deny_all '{}'".format(user,obj.deny_all,expected_deny_all))

    def test_allow(self):
        index = 0
        for test_data,testcases in [
            (("gunfire.com",None,None),[("/info",True),("/update",True)]),
            (("gunfire.com",["*"],None),[("/info",True),("/update",True)]),
            (("gunfire.com",["/"],None),[("/info",True),("/update",True)]),
            (("gunfire.com",["^.*$"],None),[("/info",True),("/update",True)]),

            (("gunfire.com",None,["*"]),[("/info",False),("/update",False)]),
            (("gunfire.com",None,["/"]),[("/info",False),("/update",False)]),
            (("gunfire.com",None,["^.*$"]),[("/info",False),("/update",False)]),

            (("gunfire.com",["*"],["*"]),[("/info",False),("/update",False)]),
            (("gunfire.com",["*"],["/"]),[("/info",False),("/update",False)]),
            (("gunfire.com",["*"],["^.*$"]),[("/info",False),("/update",False)]),

            (("gunfire.com",["/info"],None),[("/info",True),("/info/list",True),("/data",False),("/information",True),("/",False)]),
            (("gunfire.com",["=/about"],None),[("/info",False),("/about",True),("/about1",False),("/about/contact",False)]),
            (("gunfire.com",["^.*/get$"],None),[("/get",True),("/usr/get",True),("/list",False),("/user/info",False)]),

            (("gunfire.com",None,["/info"]),[("/info",False),("/info/list",False),("/data",True),("/information",False),("/",True)]),
            (("gunfire.com",None,["=/about"]),[("/info",True),("/about",False),("/about1",True),("/about/contact",True)]),
            (("gunfire.com",None,["^.*/get$"]),[("/get",False),("/usr/get",False),("/list",True),("/user/info",True)])
        ]:
            index += 1
            domain,paths,excluded_paths = test_data
            user = self.get_role(index)
            obj = self.get_role_requests(user,domain,paths,excluded_paths)
            obj.clean()
            obj.save()
            for path,result in testcases:
                self.assertEqual(obj.allow(path),result,msg="The UserRequests({},paths={},excluded_paths={}) can {} the path '{}'".format(user,obj.paths,obj.excluded_paths,"access" if result else "not access",path))


class UserGroupRequestsTestCase(UserRequestsTestCase):
    def setUp(self):
        #clear the unittest data
        UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()

    def get_role(self,index):
        group = UserGroup(name="test{:0>3}".format(index),users=["@test.com"])
        group.clean()
        group.save()
        return group

    def get_role_requests(self,role,domain,paths,excluded_paths):
        return UserGroupRequests(usergroup=role,domain=domain,paths=paths,excluded_paths=excluded_paths)


class AuthorizatioinTestCase(TestCase):
    def setUp(self):
        #clear the unittest data
        UserGroup.objects.all().exclude(users=["*"],excluded_users__isnull=True).delete()
        UserRequests.objects.all().delete()

    def test_authorize(self):
        test_usergroups = [
            ("all_user",["*@*"],None,[
                ("gunfire",["@gunfire.com"],None,[
                    ("dev",["dev_*@gunfire.com"],None,[
                        ("dev_map",["dev_map_*@gunfire.com"],["dev_map_external_*@gunfire.com"],[
                            ("dev_map_leader",["dev_map_leader1@gunfire.com","dev_map_leader2@gunfire.com","dev_map_leader3@gunfire.com","dev_map_leader4@gunfire.com"],None,[
                                ("dev_map_manager",["dev_map_leader1@gunfire.com","dev_map_leader2@gunfire.com"],None,None)
                            ])
                        ]),
                        ("dev_role",["dev_role_*@gunfire.com"],["dev_role_external_*@gunfire.com"],[
                            ("dev_role_leader",["dev_role_leader1@gunfire.com","dev_role_leader2@gunfire.com","dev_role_leader3@gunfire.com","dev_role_leader4@gunfire.com"],None,[
                                ("dev_role_manager",["dev_role_leader1@gunfire.com","dev_role_leader2@gunfire.com"],None,None)
                            ])
                        ]),
                    ]),
                    ("support",["support_*@gunfire.com"],None,[])
                ])
            ])
        ]
        test_usergrouprequests = [
            ("all_user","*",None,"*"),
            ("all_user","game.gunfire.com",None,None),
            ("all_user","gunfire.com",None,["/register"]),

            ("gunfire",".gunfire.com",None,None),
            ("gunfire","gunfire.com",None,["/register","/unregister"]),
            ("gunfire","*dev.gunfire.com",None,["*"]),
            ("gunfire","*support.gunfire.com",None,["*"]),

            ("support","gunfire.com",None,["/unregister"]),

            ("dev","dev.gunfire.com",None,None),

            ("dev_map","map.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/approve$","^.*/deploy$","^.*/remove$"]),

            ("dev_map_leader","map.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/remove$"]),

            ("dev_map_manager","map.dev.gunfire.com",None,["=/start","=/shutdown"]),

            ("dev_role","map.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/approve$","^.*/deploy$","^.*/remove$"]),

            ("dev_role_leader","map.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/remove$"]),

            ("dev_role_manager","map.dev.gunfire.com",None,["=/start","=/shutdown"])
        ]

        test_userrequests = [
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com",None,None),

            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com",None,["=/shutdown"]),

            ("hacker1@hacker.com",".gunfire.com",None,None),
            ("hacker1@hacker.com","map.dev.gunfire.com",None,["=/start"]),
            ("hacker1@hacker.com","role.dev.gunfire.com",None,["^.*/remove$"])
        ]
        testcases = [
            ("test@gmail.com","test.com","/play",False),
            ("test@gmail.com","dev.gunfire.com","/",False),
            ("test@gmail.com","dev.gunfire.com","/info",False),
            ("test@gmail.com","gunfire.com","/about",True),
            ("test@gmail.com","gunfire.com","/",True),
            ("test@gmail.com","gunfire.com","/games",True),
            ("test@gmail.com","gunfire.com","/register",False),
            ("test@gmail.com","game.gunfire.com","/play",True),

            ("hacker1@hacker.com","test.com","/play",False),
            ("hacker1@hacker.com","gunfire.com","/register",False),
            ("hacker1@hacker.com","map.dev.gunfire.com","/start",False),
            ("hacker1@hacker.com","map.dev.gunfire.com","/shutdown",True),
            ("hacker1@hacker.com","map.dev.gunfire.com","/tasks",True),
            ("hacker1@hacker.com","map.dev.gunfire.com","/tasks/self",True),
            ("hacker1@hacker.com","map.dev.gunfire.com","/test/deploy",True),
            ("hacker1@hacker.com","role.dev.gunfire.com","/start",True),
            ("hacker1@hacker.com","role.dev.gunfire.com","/test/remove",False),
            ("hacker1@hacker.com","role.dev.gunfire.com","/remove",False),

            ("staff1@gunfire.com","test.com","/test/remove",False),
            ("staff1@gunfire.com","gunfire.com","/about",True),
            ("staff1@gunfire.com","gunfire.com","/register",False),
            ("staff1@gunfire.com","gunfire.com","/unregister",False),
            ("staff1@gunfire.com","gunfire.com","/",True),
            ("staff1@gunfire.com","dev.gunfire.com","/",False),
            ("staff1@gunfire.com","map.dev.gunfire.com","/",False),
            ("staff1@gunfire.com","support.gunfire.com","/",False),
            ("staff1@gunfire.com","shop.gunfire.com","/",True),
            ("staff1@gunfire.com","shop.gunfire.com","/register",True),

            ("support_1@gunfire.com","test.com","/test/remove",False),
            ("support_1@gunfire.com","gunfire.com","/about",True),
            ("support_1@gunfire.com","gunfire.com","/register",True),
            ("support_1@gunfire.com","gunfire.com","/unregister",False),
            ("support_1@gunfire.com","gunfire.com","/",True),
            ("support_1@gunfire.com","dev.gunfire.com","/",False),
            ("support_1@gunfire.com","map.dev.gunfire.com","/",False),
            ("support_1@gunfire.com","support.gunfire.com","/",False),
            ("support_1@gunfire.com","shop.gunfire.com","/",True),
            ("support_1@gunfire.com","shop.gunfire.com","/register",True),

            ("dev_1@gunfire.com","test.com","/test/remove",False),
            ("dev_1@gunfire.com","gunfire.com","/about",True),
            ("dev_1@gunfire.com","gunfire.com","/register",False),
            ("dev_1@gunfire.com","gunfire.com","/unregister",False),
            ("dev_1@gunfire.com","gunfire.com","/",True),
            ("dev_1@gunfire.com","dev.gunfire.com","/",True),
            ("dev_1@gunfire.com","map.dev.gunfire.com","/",False),
            ("dev_1@gunfire.com","support.gunfire.com","/",False),
            ("dev_1@gunfire.com","shop.gunfire.com","/",True),
            ("dev_1@gunfire.com","shop.gunfire.com","/register",True),
            
            ("dev_map_1@gunfire.com","test.com","/test/remove",False),
            ("dev_map_1@gunfire.com","gunfire.com","/about",True),
            ("dev_map_1@gunfire.com","gunfire.com","/register",False),
            ("dev_map_1@gunfire.com","gunfire.com","/unregister",False),
            ("dev_map_1@gunfire.com","gunfire.com","/",True),
            ("dev_map_1@gunfire.com","dev.gunfire.com","/",True),
            ("dev_map_1@gunfire.com","support.gunfire.com","/",False),
            ("dev_map_1@gunfire.com","shop.gunfire.com","/",True),
            ("dev_map_1@gunfire.com","shop.gunfire.com","/register",True),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/",True),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/start",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/tasks",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/tasks/today",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/approve",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/task1/approve",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/deploy",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/task1/deploy",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/remove",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/task1/remove",False),
            ("dev_map_1@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),

            ("dev_map_leader3@gunfire.com","test.com","/test/remove",False),
            ("dev_map_leader3@gunfire.com","gunfire.com","/about",True),
            ("dev_map_leader3@gunfire.com","gunfire.com","/register",False),
            ("dev_map_leader3@gunfire.com","gunfire.com","/unregister",False),
            ("dev_map_leader3@gunfire.com","gunfire.com","/",True),
            ("dev_map_leader3@gunfire.com","dev.gunfire.com","/",True),
            ("dev_map_leader3@gunfire.com","support.gunfire.com","/",False),
            ("dev_map_leader3@gunfire.com","shop.gunfire.com","/",True),
            ("dev_map_leader3@gunfire.com","shop.gunfire.com","/register",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/start",False),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/tasks",False),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/tasks/today",False),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/remove",False),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/task1/remove",False),
            ("dev_map_leader3@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),

            ("dev_map_leader4@gunfire.com","test.com","/test/remove",False),
            ("dev_map_leader4@gunfire.com","gunfire.com","/about",True),
            ("dev_map_leader4@gunfire.com","gunfire.com","/register",False),
            ("dev_map_leader4@gunfire.com","gunfire.com","/unregister",False),
            ("dev_map_leader4@gunfire.com","gunfire.com","/",True),
            ("dev_map_leader4@gunfire.com","dev.gunfire.com","/",True),
            ("dev_map_leader4@gunfire.com","support.gunfire.com","/",False),
            ("dev_map_leader4@gunfire.com","shop.gunfire.com","/",True),
            ("dev_map_leader4@gunfire.com","shop.gunfire.com","/register",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/start",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/tasks",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/tasks/today",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/remove",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/task1/remove",True),
            ("dev_map_leader4@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),

            ("dev_map_leader1@gunfire.com","test.com","/test/remove",False),
            ("dev_map_leader1@gunfire.com","gunfire.com","/about",True),
            ("dev_map_leader1@gunfire.com","gunfire.com","/register",False),
            ("dev_map_leader1@gunfire.com","gunfire.com","/unregister",False),
            ("dev_map_leader1@gunfire.com","gunfire.com","/",True),
            ("dev_map_leader1@gunfire.com","dev.gunfire.com","/",True),
            ("dev_map_leader1@gunfire.com","support.gunfire.com","/",False),
            ("dev_map_leader1@gunfire.com","shop.gunfire.com","/",True),
            ("dev_map_leader1@gunfire.com","shop.gunfire.com","/register",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/start",False),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/tasks",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/tasks/today",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/remove",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/remove",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),

            ("dev_map_leader2@gunfire.com","test.com","/test/remove",False),
            ("dev_map_leader2@gunfire.com","gunfire.com","/about",True),
            ("dev_map_leader2@gunfire.com","gunfire.com","/register",False),
            ("dev_map_leader2@gunfire.com","gunfire.com","/unregister",False),
            ("dev_map_leader2@gunfire.com","gunfire.com","/",True),
            ("dev_map_leader2@gunfire.com","dev.gunfire.com","/",True),
            ("dev_map_leader2@gunfire.com","support.gunfire.com","/",False),
            ("dev_map_leader2@gunfire.com","shop.gunfire.com","/",True),
            ("dev_map_leader2@gunfire.com","shop.gunfire.com","/register",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/start",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/shutdown",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/tasks",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/tasks/today",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/remove",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/task1/remove",True),
            ("dev_map_leader2@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True)

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

        for groupname,domain,paths,excluded_paths in test_usergrouprequests:
            obj = UserGroupRequests(usergroup=UserGroup.objects.get(name=groupname),domain=domain,paths=paths,excluded_paths=excluded_paths)
            obj.clean()
            obj.save()
    
        for user,domain,paths,excluded_paths in test_userrequests:
            obj = UserRequests(user=user,domain=domain,paths=paths,excluded_paths=excluded_paths)
            obj.clean()
            obj.save()

        cache.refresh(True)
        for email,domain,path,result in testcases:
            if domain == "map.dev.gunfire.com" and email=="staff1@gunfire.com":
                #import ipdb;ipdb.set_trace()
                pass
            self.assertEqual(can_access(email,domain,path),result,msg="{} should {} the permission to access https://{}{}".format(email,"have" if result else "not have",domain,path))
            

