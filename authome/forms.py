
from django import forms
from django.contrib.postgres.forms import SimpleArrayField
from django.utils.safestring import mark_safe

from  .models import UserGroup,UserGroupAuthorization,UserAuthorization,ExactRequestDomain,User,IdentityProvider,CustomizableUserflow
from .widgets import (ReadonlyWidget,text_readonly_widget)

def get_help_text(model_class,field):
    return mark_safe("<pre>{}</pre>".format(model_class._meta.get_field(field).help_text))

class UserCreateForm(forms.ModelForm):
    class Meta:
        model = User
        fields = ("username","email","first_name","last_name","is_active","is_staff","is_superuser")

class SystemUserCreateForm(forms.ModelForm):

    def _post_clean(self):
        super()._post_clean()
        self.instance.systemuser = True
    class Meta:
        model = User
        fields = ("username","email")

class UserGroupForm(forms.ModelForm):
    users = SimpleArrayField(forms.CharField(required=False),delimiter="\n",widget=forms.Textarea(attrs={"style":"width:80%","rows":10}),help_text=get_help_text(UserGroup,"users"))
    excluded_users = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=forms.Textarea(attrs={"style":"width:80%","rows":10}),help_text=get_help_text(UserGroup,"excluded_users"))
    class Meta:
        model = UserGroup
        fields = "__all__"

class AuthorizationForm(forms.ModelForm):
    check_domain_js = """
value = this.value.trim()
if (value == "" || value[0] == "." || value.indexOf('*') >= 0) {
    document.getElementById("id_paths").disabled=true
    document.getElementById("id_excluded_paths").disabled=true
} else {
    document.getElementById("id_paths").disabled=false
    document.getElementById("id_excluded_paths").disabled=false
}
    """
    path_widget = forms.Textarea(attrs={"style":"width:80%","rows":10})
    disabled_path_widget = forms.Textarea(attrs={"style":"width:80%","rows":10,"disabled":True})
    #domain = forms.CharField(required=True,widget=forms.TextInput(attrs={"style":"width:80%","onchange":check_domain_js}),help_text=get_help_text(UserGroupAuthorization,"domain"))
    domain = forms.CharField(required=True,widget=forms.TextInput(attrs={"style":"width:80%"}),help_text=get_help_text(UserGroupAuthorization,"domain"))
    paths = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=path_widget,help_text=get_help_text(UserGroupAuthorization,"paths"))
    excluded_paths = SimpleArrayField(forms.CharField(required=False),delimiter="\n",required=False,widget=path_widget,help_text=get_help_text(UserGroupAuthorization,"excluded_paths"))

    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        """
        if self.instance :
            if not isinstance(self.instance.request_domain,ExactRequestDomain):
                self.fields["paths"].widget = self.disabled_path_widget
                self.fields["excluded_paths"].widget = self.disabled_path_widget
        """


class UserGroupAuthorizationForm(AuthorizationForm):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        if self.instance :
            if self.instance.created:
                if "usergroup" in self.fields :
                    self.fields["usergroup"].widget = ReadonlyWidget(lambda d:UserGroup.objects.get(id = int(d)) if d else "")

    class Meta:
        model = UserGroupAuthorization
        fields = "__all__"

class UserAuthorizationForm(AuthorizationForm):
    def __init__(self,*args,**kwargs):
        super().__init__(*args,**kwargs)
        if self.instance :
            if self.instance.created:
                if "user" in self.fields :
                    self.fields["user"].widget = text_readonly_widget

    class Meta:
        model = UserAuthorization
        fields = "__all__"


class IdentityProviderForm(forms.ModelForm):
    logout_url = forms.CharField(required=False,widget=forms.TextInput(attrs={"style":"width:80%"}))
    class Meta:
        model = IdentityProvider
        fields = "__all__"

class CustomizableUserflowForm(forms.ModelForm):
    domain = forms.CharField(required=True,widget=forms.TextInput(),help_text=get_help_text(CustomizableUserflow,"domain"))
    sortkey = forms.CharField(required=False,widget=forms.TextInput(),help_text=get_help_text(CustomizableUserflow,"sortkey"))
    class Meta:
        model = CustomizableUserflow
        fields = "__all__"
        widgets = {
            'extracss': forms.Textarea(attrs={'style':'width:80%;height:100px'}),
            'page_layout': forms.Textarea(attrs={'style':'width:80%;height:500px'}),
            'verifyemail_body': forms.Textarea(attrs={'style':'width:80%;height:500px'}),
            'verifyemail_subject': forms.TextInput(attrs={'style':'width:80%;'})
        }

