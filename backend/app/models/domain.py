# Import datetime utilities to handle timestamps and timezone specifications
from datetime import datetime, timezone

# Import Column data types and relationship tools from SQLAlchemy
from sqlalchemy import (
    Boolean,    # Represents SQL BOOLEAN (True/False)
    Column,     # Represents a database table column definition
    DateTime,   # Represents SQL DATETIME / TIMESTAMP fields
    ForeignKey, # Represents a database foreign key constraint linking tables
    Integer,    # Represents SQL INTEGER (whole numbers)
    String,     # Represents SQL VARCHAR / string fields
)

# Import relationship to define Object-Relational Mapping (ORM) links between models
from sqlalchemy.orm import relationship

# Import the base declarative class defined in your database module
from app.core.database import Base


# Helper function to generate current UTC timestamp with timezone metadata
def utc_now():
    # datetime.now(timezone.utc): Returns aware UTC time rather than naive local time
    return datetime.now(timezone.utc)


# TrustedDomain ORM Model: Maps to the 'trusted_domains' table in the database
class TrustedDomain(Base):
    # __tablename__: Specifies the exact SQL table name in the database
    __tablename__ = "trusted_domains"

    # id: Unique integer primary key for each domain record
    # primary_key=True: Uniquely identifies each row
    # index=True: Creates a database index for faster lookups by ID
    id = Column(
        Integer, primary_key=True, index=True
    )
    
    # domain: The domain name string (e.g., "google.com")
    # String(253): Max length set to 253 characters (standard max FQDN domain length)
    # unique=True: Ensures duplicate domain entries are blocked by the database
    # nullable=False: Requires a non-empty value (NOT NULL constraint)
    domain = Column(
        String(253), unique=True, index=True, nullable=False
    )
    
    # organization: Name of the owner/company (e.g., "Google LLC")
    organization = Column(
        String(150), nullable=False
    )
    
    # category: Classification tag (e.g., "Search Engine", "Banking")
    category = Column(
        String(80), nullable=False
    )
    
    # created_at: Timestamp when the domain was created
    # DateTime(timezone=True): Stores timezone-aware timestamps
    # default=utc_now: Passes function reference so timestamp evaluates upon insertion
    created_at = Column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    # fingerprint: ORM relationship pointing to the DomainFingerprint model
    # relationship: Connects this Python object to the associated fingerprint object
    # back_populates="trusted_domain": Creates a bidirectional link between models
    # uselist=False: Enforces a 1-to-1 relationship instead of 1-to-Many
    # cascade="all, delete-orphan": Automatically deletes child fingerprint if parent domain is deleted
    fingerprint = relationship(
        "DomainFingerprint",
        back_populates="trusted_domain",
        uselist=False,
        cascade="all, delete-orphan",
    )


# DomainFingerprint ORM Model: Maps to the 'domain_fingerprints' table
class DomainFingerprint(Base):
    # __tablename__: Specifies the exact SQL table name
    __tablename__ = "domain_fingerprints"

    # id: Unique integer primary key
    id = Column(
        Integer, primary_key=True
    )
    
    # domain_id: Foreign Key connecting this fingerprint to a record in 'trusted_domains'
    # ForeignKey("trusted_domains.id"): Enforces relational link to table column
    # unique=True: Enforces 1-to-1 relationship at database constraint level
    domain_id = Column(
        Integer,
        ForeignKey("trusted_domains.id"),
        unique=True,
        nullable=False,
    )
    
    # Canonical hostname with lowercase labels, no trailing dot, and no www prefix.
    normalized_domain = Column(
        String(253), nullable=False, index=True
    )
    
    # length: Number of total characters in the domain
    length = Column(Integer, nullable=False)
    
    # alphabetic_count: Total letter count in the domain
    alphabetic_count = Column(
        Integer, nullable=False
    )
    
    # numeric_count: Total digit count in the domain
    numeric_count = Column(
        Integer, nullable=False
    )
    
    # hyphen_count: Total hyphen ('-') count in the domain
    hyphen_count = Column(
        Integer, nullable=False
    )
    
    # has_digit: Boolean flag checking if domain contains at least one number
    has_digit = Column(
        Boolean, nullable=False
    )
    
    # has_hyphen: Boolean flag checking if domain contains at least one hyphen
    has_hyphen = Column(
        Boolean, nullable=False
    )

    # These fields are added to existing SQLite databases by the startup migration.
    subdomain_count = Column(
        Integer, nullable=False, server_default="0"
    )

    is_punycode = Column(
        Boolean, nullable=False, server_default="0"
    )

    # trusted_domain: Bidirectional relationship pointing back to parent model
    # back_populates="fingerprint": Completes two-way link to TrustedDomain.fingerprint
    trusted_domain = relationship(
        "TrustedDomain",
        back_populates="fingerprint",
    )