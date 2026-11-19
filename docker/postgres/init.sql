-- Only the database owner is used by the API. The cluster administrator is local to this container.
\getenv app_password SHIFR_DB_PASSWORD
CREATE ROLE shifr LOGIN PASSWORD :'app_password';
ALTER DATABASE shifr OWNER TO shifr;
