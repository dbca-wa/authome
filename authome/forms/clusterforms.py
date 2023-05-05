from . import forms
from .. import exceptions
from ..cache import cache

class UserEditForm(forms.UserEditForm):
    def save(self,*args,**kwargs):
        userid = self.instance.id
        result = super().save(*args,**kwargs)
        if userid:
            #update existing user
            changed_clusters,not_changed_clusters,failed_clusters = cache.user_changed(userid)
            if failed_clusters:
                raise exceptions.Auth2ClusterException("Failed to send change event of the user({1}<{0}>) to some cluseters.{2} ".format(self.instance.id,self.instance.email,["{}:{}".format(c,str(e)) for c,e in failed_clusters]))
        return result
