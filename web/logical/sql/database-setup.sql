USE users;

CREATE TABLE users (
    username TEXT(50),
    password TEXT(50)
);

INSERT INTO users (username, password) VALUES (
    'admin',
    'gigem{bl1nd-1nj3ct10n}'
);

REVOKE ALL ON *.* FROM 'ro_user'@'*';
GRANT SELECT ON *.* TO 'ro_user'@'%';
FLUSH PRIVILEGES;

