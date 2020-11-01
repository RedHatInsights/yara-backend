--! Previous: -
--! Hash: sha1:492983a3fbb3bab426e9289e8dbbd554ce8546c5

DROP FUNCTION IF EXISTS rule_system_count(rule);
DROP FUNCTION IF EXISTS rule_has_match(rule);
DROP FUNCTION IF EXISTS rule_is_disabled(rule);
DROP FUNCTION IF EXISTS disable_rule(int);
DROP FUNCTION IF EXISTS enable_rule(int);
DROP FUNCTION IF EXISTS rule_stats();
DROP FUNCTION IF EXISTS scan_stats();
DROP FUNCTION IF EXISTS host_stats();
DROP FUNCTION IF EXISTS time_series_stats();
DROP FUNCTION IF EXISTS search_rules(text);
DROP TABLE IF EXISTS string_match;
DROP TYPE IF EXISTS rule_stats;
DROP TYPE IF EXISTS scan_stats;
DROP TYPE IF EXISTS host_stats;
DROP TYPE IF EXISTS day_stats;
DROP TABLE IF EXISTS rule_scan;
DROP TABLE IF EXISTS rule_disable;
DROP TABLE IF EXISTS scan_rule;
DROP TABLE IF EXISTS scan;
DROP TABLE IF EXISTS rule;
DROP TABLE IF EXISTS host;
DROP VIEW IF EXISTS current_account;
DROP VIEW IF EXISTS stats;

CREATE TABLE rule
(
    id       integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    name     text NOT NULL CHECK (char_length(name) < 80),
    tags     text[],/*check array length, element length, uniqueness*/
    metadata jsonb,
    raw_rule text
);
CREATE TABLE rule_disable
(
    account text CHECK (char_length(account) < 10),
    rule_id integer NOT NULL REFERENCES rule (id),
    PRIMARY KEY (account, rule_id)
);
CREATE TABLE host
(
    id           integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    account      text CHECK (char_length(account) < 10),
    hostname     text,
    tags         jsonb,
    inventory_id uuid
);
CREATE TABLE scan
(
    id         integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    created_at timestamp DEFAULT now(),
    host_id    integer NOT NULL REFERENCES host (id)
);

CREATE TABLE rule_scan
(
    id      integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    scan_id integer NOT NULL REFERENCES scan (id),
    rule_id integer NOT NULL REFERENCES rule (id)
);

CREATE TABLE string_match
(
    id                integer PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
    rule_scan_id      integer NOT NULL REFERENCES rule_scan (id),
    source            text,/*file or pid*/
    string_offset     bigint,
    string_identifier text,
    string_data       text
);


GRANT SELECT ON TABLE host TO yara_user;
GRANT SELECT ON TABLE scan TO yara_user;
GRANT SELECT ON TABLE rule TO yara_user;
GRANT SELECT ON TABLE rule_scan TO yara_user;
GRANT SELECT ON TABLE string_match TO yara_user;
GRANT SELECT ON TABLE rule_disable TO yara_user;
GRANT INSERT ON TABLE rule_disable TO yara_user;
GRANT DELETE ON TABLE rule_disable TO yara_user;

ALTER TABLE rule_disable
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE host
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE scan
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE rule_scan
    ENABLE ROW LEVEL SECURITY;
ALTER TABLE string_match
    ENABLE ROW LEVEL SECURITY;

CREATE POLICY select_rule_disable ON rule_disable FOR SELECT USING (account = current_setting('insights.account'));
CREATE POLICY delete_rule_disable ON rule_disable FOR DELETE USING (account = current_setting('insights.account'));
CREATE POLICY insert_rule_disable ON rule_disable FOR INSERT WITH CHECK (account = current_setting('insights.account'));
CREATE POLICY select_host ON host FOR SELECT USING (account = current_setting('insights.account'));
CREATE POLICY select_scan ON scan FOR SELECT USING (exists(SELECT 1
                                                           FROM host
                                                           WHERE id = host_id));
CREATE POLICY select_rule_scan ON rule_scan FOR SELECT USING (exists(SELECT 1
                                                                     FROM scan
                                                                     WHERE scan_id = id));


CREATE POLICY select_string_match ON string_match FOR SELECT USING (exists(SELECT 1
                                                                           FROM rule_scan
                                                                           WHERE rule_scan_id = id));


CREATE INDEX scan_host_id_index ON scan (host_id);
CREATE INDEX ON rule_scan (scan_id);
CREATE INDEX ON rule_scan (rule_id);
CREATE INDEX ON string_match (rule_scan_id);
CREATE INDEX ON rule_disable (rule_id);


CREATE TYPE rule_stats AS
(
    enabled_count  bigint,
    disabled_count bigint,
    matched_count  bigint
);
CREATE TYPE scan_stats AS
(
    rule_scan_hit_count bigint,
    rule_scan_count     bigint
);
CREATE TYPE host_stats AS
(
    host_count bigint
);
CREATE TYPE day_stats AS
(
    day             date,
    rule_scan_count bigint,
    host_scan_count bigint
);


CREATE FUNCTION rule_stats() RETURNS rule_stats AS
$$
SELECT count(*) FILTER ( WHERE rd.rule_id IS NULL )                       AS enabled_count,
       count(*) FILTER ( WHERE rd.rule_id IS NOT NULL )                   AS disabled_count,
       count(*) FILTER ( WHERE exists(SELECT 1
                                      FROM string_match
                                               JOIN rule_scan ON string_match.rule_scan_id = rule_scan.id
                                      WHERE rule.id = rule_scan.rule_id)) AS match_count
FROM rule
         LEFT JOIN rule_disable rd ON rule.id = rd.rule_id;
$$ LANGUAGE sql STABLE;


CREATE FUNCTION scan_stats() RETURNS scan_stats AS
$$
SELECT (SELECT count(*)
        FROM rule_scan
        WHERE exists(SELECT 1
                     FROM string_match
                     WHERE string_match.rule_scan_id = rule_scan.id)) AS rule_scan_hit_count,
       (SELECT count(*) FROM rule_scan)                               AS rule_scan_count

$$ LANGUAGE sql STABLE;


CREATE FUNCTION host_stats() RETURNS host_stats AS
$$
SELECT count(*)
FROM host;

$$ LANGUAGE sql STABLE;


CREATE FUNCTION time_series_stats() RETURNS setof day_stats AS
$$
SELECT dates.day, count(rule_id), count(DISTINCT host_id)
FROM (SELECT generate_series(now() - INTERVAL '7 days', now(), '1 day')::date AS day) dates
         LEFT JOIN scan ON date_trunc('day', created_at) = dates.day
         LEFT JOIN rule_scan ON scan.id = rule_scan.scan_id
GROUP BY dates.day;

$$ LANGUAGE sql STABLE;

CREATE FUNCTION search_rules(rule_name text) RETURNS setof rule AS
$$
SELECT *
FROM rule
WHERE rule_name IS NULL
   OR rule.name ILIKE ('%' || rule_name || '%');

$$ LANGUAGE sql STABLE;


CREATE FUNCTION rule_system_count(r rule) RETURNS bigint AS
$$

SELECT count(DISTINCT host_id)
FROM scan
         JOIN rule_scan ON scan.id = scan_id
WHERE rule_scan.rule_id = r.id;

$$ LANGUAGE sql STABLE;


CREATE FUNCTION rule_has_match(r rule) RETURNS boolean AS
$$

SELECT exists(SELECT 1
              FROM string_match
                       JOIN rule_scan ON string_match.rule_scan_id = rule_scan.id
              WHERE rule_id = r.id);

$$ LANGUAGE sql STABLE;


CREATE FUNCTION rule_is_disabled(r rule) RETURNS boolean AS
$$

SELECT exists(SELECT 1 FROM rule_disable WHERE rule_id = r.id);

$$ LANGUAGE sql STABLE;

CREATE FUNCTION disable_rule(id int) RETURNS void AS
$$

INSERT INTO rule_disable (account, rule_id)
VALUES (current_setting('insights.account'), id);

$$ LANGUAGE sql VOLATILE;

CREATE FUNCTION enable_rule(id int) RETURNS void AS
$$
DELETE
FROM rule_disable
WHERE rule_id = id;

$$ LANGUAGE sql VOLATILE;



COMMENT ON TABLE rule_disable IS E'@omit';
COMMENT ON TABLE rule_scan IS E'@omit create,update,delete';
COMMENT ON TABLE string_match IS E'@omit create,update,delete';
COMMENT ON TABLE scan IS E'@omit create,update,delete';
COMMENT ON TABLE host IS E'@omit create,update,delete';
COMMENT ON TABLE rule IS E'@omit create,update,delete,all';
COMMENT ON FUNCTION search_rules(text) IS E'@sortable\n@filterable\n@name rules';
COMMENT ON FUNCTION rule_system_count(rule) IS E'@sortable';
COMMENT ON FUNCTION rule_has_match(rule) IS E'@sortable\n@filterable';
COMMENT ON FUNCTION rule_is_disabled(rule) IS E'@sortable\n@filterable';


/*INSERT INTO rule (name, tags, metadata)
VALUES ('cve_1', ARRAY ['meeting'], '{
  "severity": "catastrophic"
}');
INSERT INTO rule (name, tags, metadata)
VALUES ('cve_2', ARRAY ['lolz'], '{
  "severity": "okay"
}');

INSERT INTO host (account, hostname)
VALUES ('540155', 'a.com');



INSERT INTO scan (host_id)
VALUES (1);
INSERT INTO rule_scan (rule_id, scan_id)
VALUES (2, 1),
       (1, 1);


INSERT INTO scan (host_id, created_at)
VALUES (1, now() - INTERVAL '1 day'),
       (1, now() - INTERVAL '3 day');
INSERT INTO rule_scan (rule_id, scan_id)
VALUES (1, 2),
       (2, 2),
       (2, 3);

INSERT INTO string_match (rule_scan_id, string_identifier, string_offset, string_data)
VALUES (2, '$string2', 123456, 'virus-string2'),
       (1, '$string1', 123456, 'virus-string1'),
       (1, '$string1', 123456, 'virus-string1'),
       (2, '$string2', 123456, 'virus-string2');

INSERT INTO rule_disable(account, rule_id)
VALUES ('729650', 1),
       ('540155', 2);*/


/*
Todo: upload rule function
      upload results function
*/
