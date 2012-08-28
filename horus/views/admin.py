from horus.views            import BaseController
from horus.views            import translate
from horus.schemas          import AdminUserSchema
from horus.forms            import HorusForm
from pyramid.view           import view_config
from pyramid.httpexceptions import HTTPFound
from pyramid.i18n           import TranslationStringFactory

import deform

class AdminController(BaseController):
    @view_config(
            route_name='horus_admin_users_create',
            renderer='horus:templates/admin/create_user.mako',
            permission='admin'
    )
    def create_user(self):
        schema = AdminUserSchema()
        schema = schema.bind(request=self.request)
        form = HorusForm(schema)

        if self.request.method == 'GET':
            return dict(form=form)
        else:
            try:
                controls = self.request.POST.items()
                captured = form.validate(controls)
            except deform.ValidationFailure, e:
                return dict(form=e, errors=e.error.children)

            user = self.User()
            user_account = self.UserAccount(
                    username=captured['Username'],
                    email=captured['Email'],
                    password=captured['Password']
            )
            user.accounts.append(user_account)

            self.db.add(user)

            self.request.session.flash(translate(u'The user account was created'), 'success')

            return HTTPFound(
                location=self.request.route_url('horus_admin_users_list')
            )

    @view_config(
            route_name='horus_admin_users_list',
            renderer='horus:templates/admin/users_list.mako',
            permission='admin'
    )
    def list(self):
        return dict(users=self.UserAccount.get_all(self.request))
