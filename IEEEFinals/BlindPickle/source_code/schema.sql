DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'member',
    last_login TEXT
);

-- Seed admin (id will be 1)
INSERT INTO users (username, email, password, role, last_login)
VALUES ('admin', 'admin129836193618726@example.com', 'admin1231o82y3198371239719kjgahsdkg', 'admin', NULL);

-- A lot of realistic users
INSERT INTO users (username, email, password, role, last_login) VALUES
('alice', 'alice@example.com', 'alicepass', 'member', NULL),
('bob', 'bob@example.com', 'bobpass', 'member', NULL),
('carol', 'carol@example.com', 'carolpass', 'member', NULL),
('dave', 'dave@example.com', 'davepass', 'member', NULL),
('erin', 'erin@example.com', 'erinpass', 'member', NULL),
('frank', 'frank@example.com', 'frankpass', 'member', NULL),
('grace', 'grace@example.com', 'gracepass', 'member', NULL),
('heidi', 'heidi@example.com', 'heidipass', 'member', NULL),
('ivan', 'ivan@example.com', 'ivanpass', 'member', NULL),
('judy', 'judy@example.com', 'judypass', 'member', NULL),
('mallory', 'mallory@example.com', 'mallorypass', 'member', NULL),
('oscar', 'oscar@example.com', 'oscarpass', 'member', NULL),
('peggy', 'peggy@example.com', 'peggypass', 'member', NULL),
('trent', 'trent@example.com', 'trentpass', 'member', NULL),
('victor', 'victor@example.com', 'victorpass', 'member', NULL),
('walter', 'walter@example.com', 'walterpass', 'member', NULL),
('yolanda', 'yolanda@example.com', 'yolandapass', 'member', NULL),
('zara', 'zara@example.com', 'zarapass', 'member', NULL),
('sam', 'sam@example.com', 'sampass', 'member', NULL),
('tom', 'tom@example.com', 'tompass', 'member', NULL),
('uma', 'uma@example.com', 'umapass', 'member', NULL),
('vera', 'vera@example.com', 'verapass', 'member', NULL),
('will', 'will@example.com', 'willpass', 'member', NULL),
('xena', 'xena@example.com', 'xenapass', 'member', NULL),
('yuri', 'yuri@example.com', 'yuripass', 'member', NULL),
('zoe', 'zoe@example.com', 'zoepass', 'member', NULL),
('noah', 'noah@example.com', 'noahpass', 'member', NULL),
('liam', 'liam@example.com', 'liampass', 'member', NULL),
('emma', 'emma@example.com', 'emmapass', 'member', NULL),
('olivia', 'olivia@example.com', 'oliviapass', 'member', NULL),
('ava', 'ava@example.com', 'avapass', 'member', NULL),
('isabella', 'isabella@example.com', 'isabellapass', 'member', NULL),
('sophia', 'sophia@example.com', 'sophiapass', 'member', NULL),
('mia', 'mia@example.com', 'miapass', 'member', NULL),
('charlotte', 'charlotte@example.com', 'charlottepass', 'member', NULL),
('amelia', 'amelia@example.com', 'ameliapass', 'member', NULL);

-- A couple of staff/moderators
INSERT INTO users (username, email, password, role, last_login) VALUES
('mod_jane', 'jane@example.com', 'modjane', 'member', NULL),
('mod_john', 'john@example.com', 'modjohn', 'member', NULL);