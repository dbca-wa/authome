
from django import forms
from django.contrib.postgres.forms import SimpleArrayField

from  .models import UserGroup,UserGroupAuthorization,UserAuthorization
from .widgets import (ReadonlyWidget,text_readonly_widget)


class UserGroupForm(forms.ModelForm):
    users = SimpleArrayField(forms.CharField(required=False),delimiter="\n",widget=forms.Textarea(attrs={"style":"width:80%","rows":10}))
    excluded_users = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=forms.Textarea(attrs={"style":"width:80%","rows":10}))
    class Meta:
        model = UserGroup
        fields = "__all__"
        

class UserGroupAuthorizationForm(forms.ModelForm):
    paths = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=forms.Textarea(attrs={"style":"width:80%","rows":10}))
    excluded_paths = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=forms.Textarea(attrs={"style":"width:80%","rows":10}))

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        if self.instance :
            if self.instance.created:
                if "usergroup" in self.fields :
                    self.fields["usergroup"].widget = ReadonlyWidget(lambda d:UserGroup.objects.get(id = int(d)) if d else "")

    class Meta:
        model = UserGroupAuthorization
        fields = "__all__"

class UserGroupAuthorizationForm(forms.ModelForm):
    paths = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=forms.Textarea(attrs={"style":"width:80%","rows":10}))
    excluded_paths = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=forms.Textarea(attrs={"style":"width:80%","rows":10}))

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        if self.instance :
            if self.instance.created:
                if "user" in self.fields :
                    self.fields["user"].widget = text_readonly_widget

    class Meta:
        model = UserAuthorization
        fields = "__all__"
        



