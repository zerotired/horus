from horus.resources import UserAccountFactory

def build_routes(config):
    """ Add routes to the config """
    config.add_route('login', '/login')
    config.add_route('logout', '/logout')
    config.add_route('register', '/register')
    config.add_route('activate', '/activate/{user_account_id}/{code}', factory=UserAccountFactory)
    config.add_route('forgot_password', '/forgot_password')
    config.add_route('reset_password', '/reset_password/{code}')
    config.add_route('profile', '/profile/{user_account_id}', factory=UserAccountFactory,
            traverse="/{user_account_id}")
    config.add_route('edit_profile', '/profile/{user_account_id}/edit', factory=UserAccountFactory,
            traverse="/{user_account_id}")

    config.add_route('velruse_callback', '/velruse_callback')
