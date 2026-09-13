CREATE TABLE employees (id integer PRIMARY KEY, name text, department text, salary integer, medical_information text);
INSERT INTO employees VALUES (1,'Alice','Engineering',120000,'restricted'),(2,'Bob','Sales',90000,'restricted');
CREATE ROLE semi_user LOGIN PASSWORD 'semi_pw';
REVOKE ALL ON employees FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO semi_user;
GRANT SELECT (id,name,department) ON employees TO semi_user;
