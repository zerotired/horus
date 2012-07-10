from horus.resources import UserAccountFactory

def includeme(config):
    """ Add routes to the config """
    config.add_route('horus_login', '/login')
    config.add_route('horus_logout', '/logout')
    config.add_route('horus_register', '/register')
    config.add_route('horus_activate', '/activate/{user_id}/{code}', factory=UserAccountFactory)
    config.add_route('horus_forgot_password', '/forgot_password')
    config.add_route('horus_reset_password', '/reset_password/{code}')
    config.add_route('horus_profile', '/profile/{user_id}', factory=UserAccountFactory,
            traverse="/{user_id}")
    config.add_route('horus_edit_profile', '/profile/{user_id}/edit',
            factory=UserAccountFactory, traverse="/{user_id}")

    config.add_route('horus_admin_users_list', '/admin/users')
    config.add_route('horus_admin_users_create', '/admin/users/create')
    config.add_route('horus_admin_users_edit', '/admin/users/{user_id}')

    config.add_route('velruse_callback', '/velruse_callback')
