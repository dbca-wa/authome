import logging

from django.contrib.admin import ChoicesFieldListFilter
from django.utils.translation import gettext_lazy as _

logger = logging.getLogger(__name__)

class FilteredChoicesFieldListFilter(ChoicesFieldListFilter):
    def __init__(self, field, request, params, model, model_admin, field_path,choicefilter):
        super().__init__(field, request, params, model, model_admin, field_path)
        self._choicefilter=choicefilter

    def choices(self, changelist):
        yield {
            'selected': self.lookup_val is None,
            'query_string': changelist.get_query_string(remove=[self.lookup_kwarg, self.lookup_kwarg_isnull]),
            'display': _('All')
        }
        none_title = ''
        for lookup, title in self.field.flatchoices:
            if lookup is None:
                none_title = title
                continue
            if not self._choicefilter(lookup,title):
                continue
            yield {
                'selected': str(lookup) == self.lookup_val,
                'query_string': changelist.get_query_string({self.lookup_kwarg: lookup}, [self.lookup_kwarg_isnull]),
                'display': title,
            }
        if none_title:
            yield {
                'selected': bool(self.lookup_val_isnull),
                'query_string': changelist.get_query_string({self.lookup_kwarg_isnull: 'True'}, [self.lookup_kwarg]),
                'display': none_title,
            }


