CREATE TABLE employees (id integer PRIMARY KEY, name text, department text, salary integer, medical_information text);
INSERT INTO employees VALUES (1,'Alice','Engineering',120000,'restricted'),(2,'Bob','Sales',90000,'restricted');
CREATE ROLE nontrusted_user LOGIN PASSWORD 'nontrusted_pw';
REVOKE ALL ON employees FROM PUBLIC;
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO nontrusted_user;
GRANT SELECT (id,name,department) ON employees TO nontrusted_user;
-- No SELECT(salary,medical_information), INSERT, UPDATE, DELETE, or metadata grants.
