insert into customers (email, pwd) values
   ('account@gmail.com', '$2a$10$fbn6kkAm/Up5titTiozr2uN3MLL39otuKAUBHdaqzcmVVuSjTQHeK'),
   ('cards@gmail.com', '$2a$10$fbn6kkAm/Up5titTiozr2uN3MLL39otuKAUBHdaqzcmVVuSjTQHeK'),
   ('loans@gmail.com', '$2a$10$fbn6kkAm/Up5titTiozr2uN3MLL39otuKAUBHdaqzcmVVuSjTQHeK'),
   ('balance@gmail.com', '$2a$10$fbn6kkAm/Up5titTiozr2uN3MLL39otuKAUBHdaqzcmVVuSjTQHeK');

insert into roles(role_name, description, id_customer) values
   ('ROLE_ADMIN', 'cant view account endpoint', 1),
   ('ROLE_ADMIN', 'cant view cards endpoint', 2),
   ('ROLE_USER', 'cant view loans endpoint', 3),
   ('ROLE_USER', 'cant view balance endpoint', 4);

insert into partners(
    client_id,
    client_name,
    client_secret,
    scopes,
    grant_types,
    authentication_methods,
    redirect_uri,
    redirect_uri_logout
)
values ('angelfgdeveloper',
        'angel ideas',
        '$2a$10$NSWrnJdEyTR7r/4oR.chg.QxpOl/dtS4qzVIY7K348qg2TvgIh.qu',
        'read,write',
        'authorization_code,refresh_token',
        'client_secret_basic,client_secret_jwt',
        'https://oauthdebugger.com/debug',
        'https://springone.io/authorized'
);
