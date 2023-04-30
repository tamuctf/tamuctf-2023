USE writeups;

CREATE TABLE articles (
    title TEXT(50),
    postdate TEXT(20),
    descr TEXT(700),
    imgloc TEXT(50),
    artloc TEXT(50),
    access_code TEXT(50)
);

INSERT INTO articles (title, postdate, descr, imgloc, artloc, access_code) VALUES (
    'TAMUctf 2023 Writeups',
    'April 10, 2023',
    'Collection of writeups for TAMUctf 2023. This post will be password protected until the end of the competition.',
    '/img/tamuctf.png',
    '/writeups/tamuctf23/',
    'ba65ba9416d8e53c5d02006b2962d27e'
);

INSERT INTO articles (title, postdate, descr, imgloc, artloc, access_code) VALUES (
    'HackTheBox: Paper',
    'Jun 18, 2022',
    'Before I get started, I just want to say that, at the time of writing (03/02/22), this is my favorite box on the platform. The box is based on The Office and has several references to the show. The user is compromised by exploiting an outdated version of WordPress as well as leaking credentials on a custom chatbot. The privilege escalation vector was using PwnKit, with the intended exploit being created by the box author.',
    '/img/paper.png',
    '/writeups/paper/',
    ''
);

INSERT INTO articles (title, postdate, descr, imgloc, artloc, access_code) VALUES (
    'HackTheBox: Meta',
    'Jun 11, 2022',
    'Meta was a fun medium box about vulnerabilities in common image editors. The initial foothold started with getting a reverse shell by exploiting an RCE vulnerability in ExifTool. From there, a cron job running ImageMagick is exploited to access the user. Finally, abusing neofetch with environment variables allows for root access.',
    '/img/meta.png',
    '/writeups/meta/',
    ''
);

INSERT INTO articles (title, postdate, descr, imgloc, artloc, access_code) VALUES (
    'HackTheBox: Pandora',
    'May 21, 2022',
    'Pandora is an easy box on Hack The Box. I found that, despite the classification, this box is quite difficult for an "easy" box. In this box, there are a lot of steps and a lot of exploits that will not work. I believe I tried over 10 different exploits in the user phase before finding something that works.',
    '/img/pandora.png',
    '/writeups/pandora/',
    ''
);

INSERT INTO articles (title, postdate, descr, imgloc, artloc, access_code) VALUES (
    'MetaCTF 2021 Writeups',
    'December 30, 2021',
    'Collection of writeups for MetaCTF 2021. I had a lot of fun with this competition. The writeups here are for the challenges I solved and found interesting.',
    '/img/metactf.png',
    'https://tx.ag/pwnsimps',
    ''
);

REVOKE ALL ON *.* FROM 'ro_user'@'%';
GRANT SELECT ON *.* TO 'ro_user'@'%';
FLUSH PRIVILEGES;
