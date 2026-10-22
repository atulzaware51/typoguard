# Import the Path class from pathlib to work with file paths in an object-oriented way
from pathlib import Path

# Import create_engine to manage the connection to the database
from sqlalchemy import create_engine, inspect, text

# Import declarative_base to create a base class for database models,
# and sessionmaker to generate database session instances
from sqlalchemy.orm import declarative_base, sessionmaker


# BASE_DIR: Represents the root directory path of the project.
# __file__: A built-in Python variable that holds the path of the current script file.
# resolve(): Resolves symbolic links and turns relative paths into absolute paths.
# parents[2]: Navigates up 2 directory levels in the folder structure.
BASE_DIR = Path(__file__).resolve().parents[2]

# DATABASE_PATH: Combines the base directory with the SQLite database filename "typoguard.db".
DATABASE_PATH = BASE_DIR / "typoguard.db"

# DATABASE_URL: Formats the path into a standard database connection string (connection URI).
# as_posix(): Converts Windows backslashes (\) into forward slashes (/) required for database URIs.
DATABASE_URL = f"sqlite:///{DATABASE_PATH.as_posix()}"

# engine: The core entry point that handles communication with the SQLite database.
# create_engine: Creates a new engine instance using the database URL.
# connect_args={"check_same_thread": False}: Needed only for SQLite so multiple HTTP requests can share the same database connection.
engine = create_engine(
    DATABASE_URL,
    connect_args={"check_same_thread": False},
)

# SessionLocal: A factory function that creates new database session objects.
# sessionmaker: Configures how new database sessions will behave.
# bind=engine: Binds the created sessions directly to our database engine.
# autoflush=False: Prevents automatic flushing of pending changes to the DB before running queries.
# autocommit=False: Requires explicit commits (db.commit()) to save changes permanently.
SessionLocal = sessionmaker(
    bind=engine,
    autoflush=False,
    autocommit=False,
)

# Base: A base class that all database ORM models (tables) will inherit from.
# declarative_base(): Constructs the base class for declarative class definitions.
Base = declarative_base()


def migrate_domain_fingerprints(target_engine=engine):
    """Add fingerprint fields to existing SQLite databases and backfill them."""
    if "domain_fingerprints" not in inspect(target_engine).get_table_names():
        return

    from app.services.fingerprint import create_fingerprint

    with target_engine.begin() as connection:
        columns = {
            column["name"]
            for column in inspect(target_engine).get_columns("domain_fingerprints")
        }
        schema_changed = False
        if "subdomain_count" not in columns:
            connection.execute(text(
                "ALTER TABLE domain_fingerprints "
                "ADD COLUMN subdomain_count INTEGER NOT NULL DEFAULT 0"
            ))
            schema_changed = True
        if "is_punycode" not in columns:
            connection.execute(text(
                "ALTER TABLE domain_fingerprints "
                "ADD COLUMN is_punycode BOOLEAN NOT NULL DEFAULT 0"
            ))
            schema_changed = True
        if not schema_changed:
            return

        records = connection.execute(text(
            "SELECT id, normalized_domain FROM domain_fingerprints"
        )).all()
        for fingerprint_id, domain in records:
            features = create_fingerprint(domain)
            connection.execute(
                text(
                    "UPDATE domain_fingerprints "
                    "SET subdomain_count = :subdomain_count, "
                    "is_punycode = :is_punycode "
                    "WHERE id = :fingerprint_id"
                ),
                {
                    "subdomain_count": features["subdomain_count"],
                    "is_punycode": features["is_punycode"],
                    "fingerprint_id": fingerprint_id,
                },
            )


# get_db(): A dependency generator function used in web frameworks (like FastAPI) to manage session lifecycles.
def get_db():
    """Provide one database session per request."""
    # Instantiates a fresh database session instance from the SessionLocal factory.
    db = SessionLocal()

    # try block ensures the session is provided and clean teardown occurs even if errors happen.
    try:
        # yield: Converts this function into a Python generator.
        # It pauses execution, hands the active database session `db` to the API request handler,
        # and waits until the request finishes before resuming.
        yield db
    # finally block guarantees execution regardless of whether the request succeeds or throws an exception.
    finally:
        # close(): Closes the database session to release the connection back to the pool and prevent memory leaks.
        db.close()