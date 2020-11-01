CREATE USER yara_owner WITH PASSWORD 'password';
CREATE DATABASE yara OWNER yara_owner;
CREATE DATABASE yara_shadow OWNER yara_owner;

create role yara_user;
grant yara_user to yara_owner;
