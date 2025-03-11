# -*- coding: utf-8 -*-
from django.test import TestCase, Client
from django.core.exceptions import ValidationError

from .models import UserGroup,UserGroupAuthorization,UserAuthorization,can_access
from .cache import cache
from .basetest import BaseAuthCacheTestCase


class UserGroupTestCase(BaseAuthCacheTestCase):

    def test_delete_public_group(self):
        with self.assertRaises(Exception,msg="Delete public user group should throw exception."):
            UserGroup.public_group().delete()

    def test_duplicate_public_group(self):
        public_group = UserGroup.public_group()
        #create another public group
        public_group.id = None
        with self.assertRaises(Exception,msg="Save the second public user group should throw exception"):
            public_group.save()

    def test_validation(self):
        index = 0
        for test_data,expected_result in [
            (("test1",None,["@test1.com"],["blocked1@test1.com","blocked2@test1.com"],True),None),
            (("test2","test1",["developer_*@test1.com"],None,True),None),
            (("test2","test1",["developer*@test1.com","blocked1@test1.com"],None,False),ValidationError("The excluded email pattern({}) in the parent group({}) is contained by the current group({})".format("blocked1@test1.com","test1","test2"))),
            (("test2","test1",["developer_*@test1.com"],["blocked1@test1.com"],False),ValidationError("The excluded email pattern({}) is not contained by email patterns configured in current group({})".format("blocked1@test1.com","test2"))),
            (("test2","test1",["@test1.com"],["blocked1@test1.com"],False),ValidationError("The excluded email pattern({}) in the parent group({}) is contained by the current group({})".format("blocked2@test1.com","test1","test2"))),
            (("test2","test1",["developer_*@test1.com","test2@test2.com"],None,False),ValidationError("The email pattern({}) in the current group({}) is not contained by the parent group({})".format("test2@test2.com","test2","test1"))),

            (("test3","test1",["developer_*@test1.com","blocked1@test1.com"],None,True),ValidationError("The excluded email pattern({}) in the parent group({}) is contained by the current group({})".format("blocked1@test1.com","test1","test3"))),

            (("test4","test1",["developer_*@test1.com"],["blocked1@test1.com"],True),ValidationError("The excluded email pattern({}) is not contained by email patterns configured in current group({})".format("blocked1@test1.com","test4"))),

            (("test5","test1",["@test1.com"],["blocked1@test1.com"],True),ValidationError("The excluded email pattern({}) in the parent group({}) is contained by the current group({})".format("blocked2@test1.com","test1","test5"))),

            (("test6","test1",["developer_*@test1.com","test2@test2.com"],None,True),ValidationError("The email pattern({}) in the current group({}) is not contained by the parent group({})".format("test2@test2.com","test6","test1"))),

            (("test10","test2",["developer_*@test1.com"],None,True),None),
            (("test11","test10",["developer_*@test1.com"],None,True),None),
            (("test12","test11",["developer_*@test1.com"],None,True),None),
            (("test10","test10",["developer_*@test1.com"],None,False),ValidationError("The parent group of the group ({0}) can't be itself".format("test10"))),
            (("test10","test12",["developer_*@test1.com"],None,False),ValidationError("The parent group({1}) of the group ({0}) can't be descendant of the group({0})".format("test10","test12"))),
            (("test10","test11",["developer_*@test1.com"],None,False),ValidationError("The parent group({1}) of the group ({0}) can't be descendant of the group({0})".format("test10","test11"))),
            #test regex user email
            (("test20","test1",["a@test1.com","b@test1.com"],["^[c-z][^@]*@test1.com$"],True),None),
            (("test30","test1",["@test1.com"],["^[c-z][^@]*@test1.com$"],True),None),
            (("test40","test1",["a*@test1.com"],["^[c-z][^@]*@test1.com$"],True),None),
            (("test50","test1",["^a.*@test1.com$"],["^[c-z][^@]*@test1.com$"],True),None),
            (("test60","test1",["^a.*@test1.com$"],["c@test1.com"],True),None),
            (("test70","test1",["^a.*@test1.com$"],["c*@test1.com"],True),None)
        ]:
            index += 1
            if test_data[1]:
                pgroup = UserGroup.objects.get(name=test_data[1])
            else:
                pgroup = None
            if test_data[-1]:
                obj = UserGroup(name=test_data[0],groupid=test_data[0].upper(),users=test_data[2],excluded_users=test_data[3],parent_group=pgroup)
            else:
                obj = UserGroup.objects.get(name=test_data[0])
                obj.groupid = test_data[0].upper()
                obj.users = test_data[2]
                obj.excluded_users = test_data[3]
                obj.parent_group = pgroup

            try:
                if index == 14:
                    #import ipdb;ipdb.set_trace()
                    pass
                obj.clean()
                obj.save()
                if expected_result:
                    raise Exception("Test case({}) failed.user group saved successfully but should raise a exception,{}".format(index,expected_result))
            except Exception as ex:
                if expected_result:
                    self.assertEqual((ex.__class__,str(ex)),(expected_result.__class__,str(expected_result)),msg="Test case({}) failed. msg={}, expected msg={}".format(index,ex,expected_result))
                else:
                    raise Exception("Test case({}) failed.{}".format(index,str(ex)))
                    


    def test_save(self):
        index = 0
        for test_data,expected_data in [
            ((None,["*"]),(["*"],["*"])),
            ((["test2@test1.com","",None,"test1@test1.com","*1@*.com","@test3.com","^[a-b].*@test4.com$"],None),(["@test3.com","^[a-b].*@test4.com$","*1@*.com","test1@test1.com","test2@test1.com"],None)),
        ]:
            index += 1
            obj = UserGroup(name="test_{}".format(index),groupid="test_{}".format(index),users=test_data[0],excluded_users=test_data[1])
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
            #test regex user email
            ((["*"],["^[c-z][^@]*@test1.com$"]),[("test1@test1.com",False),("test2@test2.com",True),("c@test1.com",False),("dz@test1.com",False),("a@test1.com",True)]),
            ((["^[a-d][^@]*@test1.com$","^[c-z][^@]*@test2.com$"],["^[c-z][^@]*@test1.com$"]),[("test1@test1.com",False),("test2@test2.com",True),("c@test1.com",False),("dz@test1.com",False),("a@test1.com",True),("cd@test2.com",True),("a@test2.com",False),("a@test3.com",False)]),
        ]:
            index += 1
            obj = UserGroup(name="test_{}".format(index),groupid="test_{}".format(index),users=test_data[0],excluded_users=test_data[1])
            obj.clean()
            obj.save()
            for email,result in testcases:
               self.assertEqual(obj.contain(email),result,msg="The UserGroup(users={},excluded_users={}) should {} the user({})".format(obj.users,obj.excluded_users,"contain" if result else "not contain",email,))


    def test_find(self):
        self.test_usergroups = [
            ("testcompany",["@test1.com"],None,[
                ("developers",["dev_*@test1.com"],None,[
                    ("app_developers",["dev_app_*@test1.com"],["dev_app_test*@test1.com"],[
                        ("app_dev_leaders",["dev_app_leader*@test1.com"],None,[
                            ("app_dev_manager",["dev_app_leader_manager*@test1.com"],None,None)
                        ])
                    ])
                ]),
                ("supporters",["support_*@test1.com"],None,[])
            ]),
            ("reportgroup",["report1@test1.com","dev_report1@test1.com","dev_app_report1@test1.com","dev_app_leader_report1@test1.com","dev_app_leader_manager_report1@test1.com","support_report1@test1.com"],None,None),
            #test regex
            ("testcompany2",["^[^@]+@test2.com$"],None,[
                ("developers2",["dev_*@test2.com"],["^dev_.*fake.*@test2.com$"],[
                    ("app_developers2",["dev_app_*@test2.com"],["^dev_app_.*fake.*@test2.com$"],[
                        ("app_dev_leaders2",["^dev_app_leader.*@test2.com$"],None,[
                            ("app_dev_manager2",["^dev_app_leader_manager.*@test2.com$"],None,None)
                        ])
                    ])
                ])
            ]),

        ]
        testcases = [
            ("test@test.com",[UserGroup.public_group().name],[UserGroup.public_group().groupid]),
            ("sales@test1.com",["testcompany"],[UserGroup.public_group().groupid,"testcompany"]),
            ("support_1@test1.com",["supporters"],[UserGroup.public_group().groupid,"testcompany","supporters"]),
            ("dev_1@test1.com",["developers"],[UserGroup.public_group().groupid,"testcompany","developers"]),
            ("dev_app_1@test1.com",["app_developers"],[UserGroup.public_group().groupid,"testcompany","developers","app_developers"]),
            ("dev_app_leader1@test1.com",["app_dev_leaders"],[UserGroup.public_group().groupid,"testcompany","developers","app_developers","app_dev_leaders"]),
            ("dev_app_leader_manager1@test1.com",["app_dev_manager"],[UserGroup.public_group().groupid,"testcompany","developers","app_developers","app_dev_leaders","app_dev_manager"]),

            ("report1@test1.com",["testcompany","reportgroup"],[UserGroup.public_group().groupid,"testcompany","reportgroup"]),
            ("support_report1@test1.com",["supporters","reportgroup"],[UserGroup.public_group().groupid,"testcompany","supporters","reportgroup"]),
            ("dev_report1@test1.com",["developers","reportgroup"],[UserGroup.public_group().groupid,"testcompany","developers","reportgroup"]),
            ("dev_app_report1@test1.com",["app_developers","reportgroup"],[UserGroup.public_group().groupid,"testcompany","developers","app_developers","reportgroup"]),
            ("dev_app_leader_report1@test1.com",["app_dev_leaders","reportgroup"],[UserGroup.public_group().groupid,"testcompany","developers","app_developers","app_dev_leaders","reportgroup"]),
            ("dev_app_leader_manager_report1@test1.com",["app_dev_manager","reportgroup"],[UserGroup.public_group().groupid,"testcompany","developers","app_developers","app_dev_leaders","app_dev_manager","reportgroup"]),
            #regex test

            ("dev_1@test2.com",["developers2"],[UserGroup.public_group().groupid,"testcompany2","developers2"]),
            ("dev_1_fake@test2.com",["testcompany2"],[UserGroup.public_group().groupid,"testcompany2"]),
            ("dev_app_fake@test2.com",["testcompany2"],[UserGroup.public_group().groupid,"testcompany2"]),
            ("dev_app_leader_fake@test2.com",["testcompany2"],[UserGroup.public_group().groupid,"testcompany2"]),
            ("dev_app_leader_manager_fake@test2.com",["testcompany2"],[UserGroup.public_group().groupid,"testcompany2"]),
            ("dev_app_1@test2.com",["app_developers2"],[UserGroup.public_group().groupid,"testcompany2","developers2","app_developers2"]),
            ("dev_app_leader1@test2.com",["app_dev_leaders2"],[UserGroup.public_group().groupid,"testcompany2","developers2","app_developers2","app_dev_leaders2"]),
            ("dev_app_leader_manager1@test2.com",["app_dev_manager2"],[UserGroup.public_group().groupid,"testcompany2","developers2","app_developers2","app_dev_leaders2","app_dev_manager2"]),


        ]
        #popuate UserGroup objects
        self.populate_testdata()

        cache.refresh_authorization_cache(True)
  
        for email,expected_groups,expected_groupnames in testcases:
            groups,groupnames,grouppks = UserGroup.find_groups(email)
            groups = [g.name for g in groups]
            groups.sort()
            groupnames = groupnames.split(",")
            groupnames.sort()
            expected_groups.sort()
            expected_groupnames.sort()
            self.assertEqual(groups,expected_groups,msg="{}: matched group({}) is not the expected group({})".format(email,groups,expected_groups))
            self.assertEqual(groupnames,expected_groupnames,msg="{}: matched group names({}) is not the expected group names({})".format(email,groupnames,expected_groupnames))
            
class UserAuthorizationTestCase(object):#BaseAuthCacheTestCase):

    def get_role(self,index):
        return "test{:0>3}".format(index)

    def get_role_requests(self,role,domain,paths,excluded_paths):
        return UserAuthorization(user=role,domain=domain,paths=paths,excluded_paths=excluded_paths)

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
            self.assertEqual(obj.domain,expected_domain,msg="The UserAuthorization({},domain={}) is not matched with the expected domain '{}'".format(user,obj.domain,expected_domain))
            self.assertEqual(obj.paths,expected_paths,msg="The UserAuthorization({},paths={}) is not matched with the expected paths '{}'".format(user,obj.paths,expected_paths))
            self.assertEqual(obj.excluded_paths,expected_excluded_paths,msg="The UserAuthorization({},excluded_paths={}) is not matched with the expected excluded_paths '{}'".format(user,obj.excluded_paths,expected_excluded_paths))
            self.assertEqual(obj.allow_all,expected_allow_all,msg="The UserAuthorization({},allow_all={}) is not matched with the expected allow_all '{}'".format(user,obj.allow_all,expected_allow_all))
            self.assertEqual(obj.deny_all,expected_deny_all,msg="The UserAuthorization({},deny_all={}) is not matched with the expected deny_all '{}'".format(user,obj.deny_all,expected_deny_all))

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
                self.assertEqual(obj.allow(path),result,msg="The UserAuthorization({},paths={},excluded_paths={}) can {} the path '{}'".format(user,obj.paths,obj.excluded_paths,"access" if result else "not access",path))


class UserGroupAuthorizationTestCase(UserAuthorizationTestCase):

    def get_role(self,index):
        group = UserGroup(name="test{:0>3}".format(index),groupid="test{:0>3}".format(index).format(index),users=["@test.com"])
        group.clean()
        group.save()
        return group

    def get_role_requests(self,role,domain,paths,excluded_paths):
        return UserGroupAuthorization(usergroup=role,domain=domain,paths=paths,excluded_paths=excluded_paths)


class AuthorizationTestCase(BaseAuthCacheTestCase):

    def test_authorize(self):
        self.test_usergroups = [
            ("all_user",["*@*.*"],None,[
                ("gunfire",["@gunfire.com","audit*@gunfire.com"],None,[
                    ("dev",["dev_*@gunfire.com","audit_dev*@gunfire.com"],None,[
                        ("dev_map",["dev_map_*@gunfire.com","audit_dev_map*@gunfire.com"],["dev_map_external_*@gunfire.com"],[
                            ("dev_map_leader",["dev_map_leader*@gunfire.com","audit_dev_map_leader*@gunfire.com"],None,[
                                ("dev_map_manager",["dev_map_leader_manager*@gunfire.com","audit_dev_map_leader_manager*@gunfire.com"],None,None)
                            ])
                        ]),
                        ("dev_role",["dev_role_*@gunfire.com","audit_dev_role*@gunfire.com"],["dev_role_external_*@gunfire.com"],[
                            ("dev_role_leader",["dev_role_leader*@gunfire.com","audit_dev_role_leader*@gunfire.com"],None,[
                                ("dev_role_manager",["dev_role_leader_manager*@gunfire.com","audit_dev_role_leader_manager*@gunfire.com"],None,None)
                            ])
                        ]),
                        ("dev_manager",["dev_manager*@gunfire.com"],None,None)
                    ]),
                    ("support",["support_*@gunfire.com","audit_support*@gunfire.com"],None,None),
                ]),
                ("audit",["audit*@gunfire.com","dev_manager*@gunfire.com"],None,[]),

            ])
        ]
        self.test_usergroupauthorization = [
            ("all_user","*",None,"*"),
            ("all_user","game.gunfire.com",None,None),
            ("all_user","gunfire.com",None,["/register"]),

            ("gunfire",".gunfire.com",None,["/audit"]),
            ("gunfire","gunfire.com",None,["/register","/unregister","/audit"]),
            ("gunfire","*dev.gunfire.com",None,["*"]),
            ("gunfire","*support.gunfire.com",None,["*"]),

            ("support","gunfire.com",None,["/unregister","/audit"]),

            ("audit","gunfire.com",["/audit"],None),
            ("audit",".gunfire.com",["/audit"],None),

            ("dev","dev.gunfire.com",None,["/audit"]),

            ("dev_map","map.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/approve$","^.*/deploy$","^.*/remove$","/audit"]),

            ("dev_map_leader","map.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/remove$","/audit"]),

            ("dev_map_manager","map.dev.gunfire.com",None,["=/start","=/shutdown","/audit"]),

            ("dev_role","role.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/approve$","^.*/deploy$","^.*/remove$","/audit"]),

            ("dev_role_leader","role.dev.gunfire.com",None,["=/start","=/shutdown","/tasks","^.*/remove$","/audit"]),

            ("dev_role_manager","role.dev.gunfire.com",None,["=/start","=/shutdown","/audit"]),

            ("dev_manager","^(role|map).dev.gunfire.com",None,["=/start","=/shutdown","/audit"]),
        ]

        self.test_userauthorization = [
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
            ("staff1@gunfire.com","support.gunfire.com","/audit/",False),
            ("staff1@gunfire.com","gunfire.com","/audit/",False),

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
            ("support_1@gunfire.com","support.gunfire.com","/audit/",False),
            ("support_1@gunfire.com","gunfire.com","/audit/",False),

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
            ("dev_1@gunfire.com","support.gunfire.com","/audit/",False),
            ("dev_1@gunfire.com","gunfire.com","/audit/",False),
            
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
            ("dev_map_1@gunfire.com","support.gunfire.com","/audit/",False),
            ("dev_map_1@gunfire.com","gunfire.com","/audit/",False),

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
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/tasks",False),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/tasks/today",False),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/remove",False),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/remove",False),
            ("dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),
            ("dev_map_leader1@gunfire.com","support.gunfire.com","/audit/",False),
            ("dev_map_leader1@gunfire.com","gunfire.com","/audit/",False),

            ("dev_map_leader_manager1@gunfire.com","test.com","/test/remove",False),
            ("dev_map_leader_manager1@gunfire.com","gunfire.com","/about",True),
            ("dev_map_leader_manager1@gunfire.com","gunfire.com","/register",False),
            ("dev_map_leader_manager1@gunfire.com","gunfire.com","/unregister",False),
            ("dev_map_leader_manager1@gunfire.com","gunfire.com","/",True),
            ("dev_map_leader_manager1@gunfire.com","dev.gunfire.com","/",True),
            ("dev_map_leader_manager1@gunfire.com","support.gunfire.com","/",False),
            ("dev_map_leader_manager1@gunfire.com","shop.gunfire.com","/",True),
            ("dev_map_leader_manager1@gunfire.com","shop.gunfire.com","/register",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/start",False),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/tasks",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/tasks/today",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/remove",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/remove",True),
            ("dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),
            ("dev_map_leader_manager1@gunfire.com","support.gunfire.com","/audit/",False),
            ("dev_map_leader-manager1@gunfire.com","gunfire.com","/audit/",False),

            ("audit_staff1@gunfire.com","test.com","/test/remove",False),
            ("audit_staff1@gunfire.com","gunfire.com","/about",True),
            ("audit_staff1@gunfire.com","gunfire.com","/register",False),
            ("audit_staff1@gunfire.com","gunfire.com","/unregister",False),
            ("audit_staff1@gunfire.com","gunfire.com","/",True),
            ("audit_staff1@gunfire.com","dev.gunfire.com","/",False),
            ("audit_staff1@gunfire.com","map.dev.gunfire.com","/",False),
            ("audit_staff1@gunfire.com","support.gunfire.com","/",False),
            ("audit_staff1@gunfire.com","shop.gunfire.com","/",True),
            ("audit_staff1@gunfire.com","shop.gunfire.com","/register",True),
            ("audit_staff1@gunfire.com","support.gunfire.com","/audit/",True),
            ("audit_staff1@gunfire.com","gunfire.com","/audit/",True),

            ("audit_dev_1@gunfire.com","test.com","/test/remove",False),
            ("audit_dev_1@gunfire.com","gunfire.com","/about",True),
            ("audit_dev_1@gunfire.com","gunfire.com","/register",False),
            ("audit_dev_1@gunfire.com","gunfire.com","/unregister",False),
            ("audit_dev_1@gunfire.com","gunfire.com","/",True),
            ("audit_dev_1@gunfire.com","dev.gunfire.com","/",True),
            ("audit_dev_1@gunfire.com","map.dev.gunfire.com","/",False),
            ("audit_dev_1@gunfire.com","support.gunfire.com","/",False),
            ("audit_dev_1@gunfire.com","shop.gunfire.com","/",True),
            ("audit_dev_1@gunfire.com","shop.gunfire.com","/register",True),
            ("audit_dev_1@gunfire.com","support.gunfire.com","/audit/",True),
            ("audit_dev_1@gunfire.com","gunfire.com","/audit/",True),

            ("audit_dev_map_leader1@gunfire.com","test.com","/test/remove",False),
            ("audit_dev_map_leader1@gunfire.com","gunfire.com","/about",True),
            ("audit_dev_map_leader1@gunfire.com","gunfire.com","/register",False),
            ("audit_dev_map_leader1@gunfire.com","gunfire.com","/unregister",False),
            ("audit_dev_map_leader1@gunfire.com","gunfire.com","/",True),
            ("audit_dev_map_leader1@gunfire.com","dev.gunfire.com","/",True),
            ("audit_dev_map_leader1@gunfire.com","support.gunfire.com","/",False),
            ("audit_dev_map_leader1@gunfire.com","shop.gunfire.com","/",True),
            ("audit_dev_map_leader1@gunfire.com","shop.gunfire.com","/register",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/start",False),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/tasks",False),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/tasks/today",False),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/remove",False),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/remove",False),
            ("audit_dev_map_leader1@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),
            ("audit_dev_map_leader1@gunfire.com","support.gunfire.com","/audit/",True),
            ("audit_dev_map_leader1@gunfire.com","gunfire.com","/audit/",True),

            ("audit_dev_map_leader_manager1@gunfire.com","test.com","/test/remove",False),
            ("audit_dev_map_leader_manager1@gunfire.com","gunfire.com","/about",True),
            ("audit_dev_map_leader_manager1@gunfire.com","gunfire.com","/register",False),
            ("audit_dev_map_leader_manager1@gunfire.com","gunfire.com","/unregister",False),
            ("audit_dev_map_leader_manager1@gunfire.com","gunfire.com","/",True),
            ("audit_dev_map_leader_manager1@gunfire.com","dev.gunfire.com","/",True),
            ("audit_dev_map_leader_manager1@gunfire.com","support.gunfire.com","/",False),
            ("audit_dev_map_leader_manager1@gunfire.com","shop.gunfire.com","/",True),
            ("audit_dev_map_leader_manager1@gunfire.com","shop.gunfire.com","/register",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/start",False),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/tasks",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/tasks/today",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/remove",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/remove",True),
            ("audit_dev_map_leader_manager1@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),
            ("audit_dev_map_leader_manager1@gunfire.com","support.gunfire.com","/audit/",True),
            ("audit_dev_map_leader_manager1@gunfire.com","gunfire.com","/audit/",True),

            ("dev_manager1@gunfire.com","test.com","/test/remove",False),
            ("dev_manager1@gunfire.com","gunfire.com","/about",True),
            ("dev_manager1@gunfire.com","gunfire.com","/register",False),
            ("dev_manager1@gunfire.com","gunfire.com","/unregister",False),
            ("dev_manager1@gunfire.com","gunfire.com","/",True),
            ("dev_manager1@gunfire.com","dev.gunfire.com","/",True),
            ("dev_manager1@gunfire.com","support.gunfire.com","/",False),
            ("dev_manager1@gunfire.com","shop.gunfire.com","/",True),
            ("dev_manager1@gunfire.com","shop.gunfire.com","/register",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/start",False),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/start/map1",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/shutdown",False),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/shutdown/map1",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/tasks",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/tasks/today",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/approve",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/task1/approve",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/task1/approve/now",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/deploy",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/task1/deploy",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/remove",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/task1/remove",True),
            ("dev_manager1@gunfire.com","map.dev.gunfire.com","/task1/remove/now",True),

            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/start",False),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/start/map1",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/shutdown",False),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/shutdown/map1",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/tasks",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/tasks/today",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/approve",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/task1/approve",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/task1/approve/now",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/deploy",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/task1/deploy",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/task1/deploy/now",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/remove",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/task1/remove",True),
            ("dev_manager1@gunfire.com","role.dev.gunfire.com","/task1/remove/now",True),

            ("dev_manager1@gunfire.com","support.gunfire.com","/audit/",True),
            ("dev_manager1@gunfire.com","gunfire.com","/audit/",True),

        ]

        self.populate_testdata()
        for email,domain,path,result in testcases:
            if domain == "dev.gunfire.com" and email=="audit_dev_1@gunfire.com" and path=="/":
                #import ipdb;ipdb.set_trace()
                pass
            self.assertEqual(can_access(email,domain,path),result,msg="{} should {} the permission to access https://{}{}".format(email,"have" if result else "not have",domain,path))
            

