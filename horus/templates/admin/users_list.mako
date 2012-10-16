<html>
<head></head>
<body>
<table>
    <tr>
        <th>Username</th>
        <th>Email</th>
        <th>Login provider</th>
        <th>OpenID</th>
        <th>Last login</th>
        <th>Is Active</th>
        <th>Pending (Email)Activation</th>
    </tr>
% for user_account in user_accounts:
    <tr>
        <td>${user_account.username}</td>
        <td>${user_account.email}</td>
        <td>${user_account.provider}</td>
        <td>${user_account.openid}</td>
        <td>${user_account.last_login_date}</td>
        <td>${user_account.user.active}</td>
        <td>${user_account.activation_id is not None}</td>
    </tr>
%endfor
</table>
</body>
</html>
