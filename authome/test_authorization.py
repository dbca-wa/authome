# -*- coding: utf-8 -*-
from django.test import TestCase, Client

from .models import UserGroup,UserGroupRequests,UserRequests


#class UserGroupTestCase(TestCase):
class UserGroupTestCase(object):
    def setUp(self):
        #clear the unittest data
        UserGroup.objects.filter(name__startswith="unittest_").exclude(users=["*"],excluded_users__isnull=True).delete()

    def tearDown(self):
        #clear the unittest data
        #UserGroup.objects.filter(name__startswith="unittest_").exclude(users=["*"],excluded_users__isnull=True).delete()
        pass

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
            obj = UserGroup(name="unittest_test_{}".format(index),users=test_data[0],excluded_users=test_data[1])
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
            obj = UserGroup(name="unittest_test_{}".format(index),users=test_data[0],excluded_users=test_data[1])
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
                obj = UserGroup(name="unittest_{}".format(name),users=users,excluded_users=excluded_users,parent_group=parent_obj)
                obj.clean()
                obj.save()
                if subgroups:
                    pending_datas.append((obj,subgroups))
  
        for email,group_name in testcases:
            group = UserGroup.find(email)
            if group_name != UserGroup.public_group().name:
                group_name = "unittest_{}".format(group_name)
            self.assertEqual(group.name,group_name,msg="{}: matched group({}) is not the expected group({})".format(email,group.name,group_name))
            
class UserRequestTestCase(TestCase):
    def setUp(self):
        #clear the unittest data
        UserRequests.objects.filter(user__startswith="unittest_").delete()

    def test_save(self):
        index = 0
        for test_data,expected_data in [
            (("test01@test.com","app.com",None,None),("app.com",None,None,True,False)),
            (("test02@test.com","app.com",["*"],None),("app.com",["*"],None,True,False)),
            (("test03@test.com","app.com",["*","","**"],None),("app.com",["*"],None,True,False)),
            (("test04@test.com","app.com",["/"],None),("app.com",["/"],None,True,False)),
            (("test05@test.com","app.com",["/","*"],None),("app.com",["*"],None,True,False)),
            (("test06@test.com","app.com",["/","*","=/info"],None),("app.com",["*"],None,True,False)),

            (("test12@test.com","app.com",None,["*"]),("app.com",None,["*"],False,True)),
            (("test13@test.com","app.com",None,["*","","**"]),("app.com",None,["*"],False,True)),
            (("test14@test.com","app.com",None,["/"]),("app.com",None,["/"],False,True)),
            (("test15@test.com","app.com",None,["/","*"]),("app.com",None,["*"],False,True)),
            (("test16@test.com","app.com",None,["/","*","=/info"]),("app.com",None,["*"],False,True)),

            (("test21@test.com","app.com",["*"],["/","*"]),("app.com",["*"],["*"],False,True)),

            (("test31@test.com","app.com",["^.*$"],None),("app.com",["^.*$"],None,True,False)),
            (("test32@test.com","app.com",["^.*$","/info"],None),("app.com",["^.*$"],None,True,False)),

            (("test41@test.com","app.com",["=/about","^/api/.*/get$","/web"],None),("app.com",["/web","^/api/.*/get$","=/about"],None,False,False))
        ]:
            index += 1
            user,domain,paths,excluded_paths = test_data
            expected_domain,expected_paths,expected_excluded_paths,expected_allow_all,expected_deny_all = expected_data
            obj = UserRequests(user="unittest_{}".format(user),domain=domain,paths=paths,excluded_paths=excluded_paths)
            obj.clean()
            obj.save()
            self.assertEqual(obj.domain,expected_domain,msg="The UserRequests({},domain={}) is not matched with the expected domain '{}'".format(user,obj.domain,expected_domain))
            self.assertEqual(obj.paths,expected_paths,msg="The UserRequests({},paths={}) is not matched with the expected paths '{}'".format(user,obj.paths,expected_paths))
            self.assertEqual(obj.excluded_paths,expected_excluded_paths,msg="The UserRequests({},excluded_paths={}) is not matched with the expected excluded_paths '{}'".format(user,obj.excluded_paths,expected_excluded_paths))
            self.assertEqual(obj.allow_all,expected_allow_all,msg="The UserRequests({},allow_all={}) is not matched with the expected allow_all '{}'".format(user,obj.allow_all,expected_allow_all))
            self.assertEqual(obj.deny_all,expected_deny_all,msg="The UserRequests({},deny_all={}) is not matched with the expected deny_all '{}'".format(user,obj.deny_all,expected_deny_all))

class UserGroupRequestTestCase(object):
    def setUp(self):
        #clear the unittest data
        UserGroup.objects.filter(name__startswith="unittest_").exclude(users=["*"],excluded_users__isnull=True).delete()

    def aatest_find(self):
        test_datas = [
            ("all_user",["*@*"],None,[
                ("testcompany",["@test1.com"],None,[
                    ("developers",["dev_*@test1.com"],None,[
                        ("app_developers",["dev_app_*@test1.com"],["dev_app_test*@test1.com"],[
                            ("app_dev_leaders",["dev_app_leader1@test1.com","dev_app_leader2@test1.com","dev_app_leader3@test1.com","dev_app_leader4@test1.com"],None,[
                                ("app_dev_managers",["dev_app_leader1@test1.com","dev_app_leader2@test1.com"],None,None)
                            ])
                        ])
                    ]),
                    ("supporters",["support_*@test1.com"],None,[])
                ])
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
                obj = UserGroup(name="unittest_{}".format(name),users=users,excluded_users=excluded_users,parent_group=parent_obj)
                obj.clean()
                obj.save()
                if subgroups:
                    pending_datas.append((obj,subgroups))

        test_group_requests_datas = [
            ("all_user","*",None,"*"),
            ("testcompany","test.com",["/get","/list","=/login","^.*/info$"],None),
            ("testcompany","test-*.au",["*"],None),
            ("testcompany","test-dev.au",["*"],["/api"]),
            ("testcompany","company.com",["*"],["/update","=/login","^.*/delete$"]),
            ("supporters","sale.com",["*"],None),
            ("developers",".dev.com",["*"],None),
            ("developers","dev.com",["*"],["/admin","/register","^.*/create$"]),
            ("app_developers","dev.com",["*"],["/admin","/register"]),
            ("app_developers","app.dev.com",["*"],["/admin"]),
            ("app_dev_leaders","dev.com",["*"],["/register"]),
            ("app_dev_leaders","app.dev.com",["*"],None),
            ("app_dev_managers",".dev.com",["*"],None),
            ("app_dev_managers","admin.dev.com",["/register"],None),
        ]
        for groupname,domain,paths,excluded_paths in test_group_requests_datas:
            if groupname != UserGroup.public_group().name:
                groupname = "unittest_{}".format(groupname)
            obj = UserGroupRequests(usergroup=UserGroup.objects.get(name=groupname),domain=domain,paths=paths,excluded_paths=excluded_paths)
            obj.clean()
            obj.save()
    
        test_user_requests_datas = [
            ("dev_app_leader1@test1.com","admin.dev.com",None,None),
            ("dev_app_leader3@test1.com","admin.dev.com",["/test"],["^.*/delete$"]),
            ("dev_app_1@test1.com","app.dev.com",None,None),
            ("dev_1@test1.com","test.dev.com",None,["/admin"]),
            ("test1@test1.com","company.com",None,["^.*/delete$"]),
            ("super@user.com","company.com",None,None),
        ]
        for email,domain,paths,excluded_paths in test_group_requests_datas:
            obj = UserRequests(user=email,domain=domain,paths=paths,excluded_paths=excluded_paths)
            obj.clean()
            obj.save()
  
        testcases = [
            ("public_1@public.com",[("test.com","/info",False),("edu.com","/",False)]),
        ]

            
        for email,cases in testcases:
            for domain,path,result in cases:
                self.assertEqual(RequestsMixin.can_access(email,domain,path),result,msg="{} can {} https://{}{}".format(email,"access" if result else "not access",domain,path))
            

