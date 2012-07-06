import deform
from pyramid.i18n import TranslationStringFactory

_ = TranslationStringFactory('horus')

class SubmitForm(deform.Form):
    def __init__(self, *args, **kwargs):

        if not kwargs.get('buttons'):
            kwargs['buttons'] = (_(u"Submit"), )

        super(SubmitForm, self).__init__(*args, **kwargs)

class ProviderForm(deform.Form):
    pass
