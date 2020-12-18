CREATE USER yara_owner WITH PASSWORD 'password';
CREATE DATABASE yara OWNER yara_owner;
CREATE DATABASE yara_shadow OWNER yara_owner;

CREATE ROLE yara_user;
GRANT yara_user TO yara_owner;

\connect yara

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;
