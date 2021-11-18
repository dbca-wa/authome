
from django import forms

class ReadonlyWidget(forms.HiddenInput):

    def __init__(self,f_display=None,*args,**kwargs):
        super().__init__(*args,**kwargs)
        self._f_display = f_display if f_display else lambda value:str(value) if value is not None else ""

    @property
    def is_hidden(self):
        return False

    def render(self, name, value, attrs=None, renderer=None):
        return "{}{}".format(super().render(name,value,attrs=attrs,renderer=renderer),self._f_display(value))

text_readonly_widget = ReadonlyWidget()
boolean_readonly_widget = ReadonlyWidget(lambda value: '<img src="/static/admin/img/icon-yes.svg" alt="True">' if value else '<img src="/static/admin/img/icon-no.svg" alt="True">')
