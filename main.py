# main.py

import asyncio
import hashlib
import json
import logging
import os
import secrets
import zipfile
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from enum import Enum
from functools import wraps
from ipaddress import ip_address, ip_network
from itertools import cycle
from pathlib import Path
from typing import Any, AsyncGenerator, Dict, List, Optional, Tuple

import httpx
import ldap3
import pytz
import redis.asyncio as aioredis
from cryptography.fernet import Fernet, InvalidToken
from fastapi import (APIRouter, BackgroundTasks, Depends, FastAPI, File, Form,
                     Header, HTTPException, Path as FastApiPath, Query,
                     Request, Response, UploadFile)
from fastapi.openapi.utils import get_openapi
from fastapi.responses import (FileResponse, HTMLResponse, JSONResponse,
                               RedirectResponse)
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from ldap3.core.exceptions import LDAPBindError, LDAPException
from ldap3.utils.conv import escape_filter_chars
from passlib.hash import bcrypt
from pydantic import BaseModel, Field, HttpUrl
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import (BigInteger, Boolean, Column, DateTime, Float,
                        ForeignKey, Integer, String, Text, delete, func,
                        select, text, update)
from sqlalchemy.exc import DataError, IntegrityError
from sqlalchemy.ext.asyncio import (AsyncSession, async_sessionmaker,
                                    create_async_engine)
from sqlalchemy.orm import declarative_base, relationship, selectinload
from starlette.exceptions import HTTPException as StarletteHTTPException

# =====================================================================================
# 1. CONFIGURATION
# =====================================================================================

class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8", case_sensitive=False
    )

    LOGGING_LEVEL: str = "INFO"
    MOSCOW_TZ: pytz.BaseTzInfo = pytz.timezone("Europe/Moscow")
    HTTPS_ENABLED: bool = False

    SESSION_EXPIRE_HOURS: int = 5
    BAN_TTL_DAYS: int = 30
    CACHE_TTL_DAYS: int = 7
    BANLIST_UPDATE_INTERVAL_MINUTES: int = 15
    PROVIDERS: List[str] = ["abuseipdb", "virustotal", "otx"]
    AUDIT_LOG_TTL_DAYS: int = 45
    AD_CACHE_REFRESH_MINUTES: int = 60
    AD_GROUP_CLEANUP_INTERVAL_MINUTES: int = 15
    AD_MEMBERSHIP_SYNC_INTERVAL_SECONDS: int = 30
    AD_EXPIRED_MEMBERSHIP_CLEANUP_MINUTES: int = 5
    AD_MEMBERSHIP_MAX_RETRIES: int = 5

    AD_SECRET_KEY: str

    FILES_DIR: Path = Path("files")
    BANLIST_FILE_PATH: Path = FILES_DIR / "banlist.txt"
    BANLIST_ARCHIVE_PATH: Path = FILES_DIR / "list.zip"
    BANLIST_VERSION_PATH: Path = FILES_DIR / "version.txt"

    DATABASE_URL: str = "postgresql+asyncpg://user:password@db:5432/ipmanager"
    DB_POOL_SIZE: int = 20
    DB_MAX_OVERFLOW: int = 10
    REDIS_URL: str = "redis://redis:6379/0"

    ABUSEIPDB_KEYS: List[str] = Field(default_factory=list)
    VIRUSTOTAL_KEYS: List[str] = Field(default_factory=list)
    OTX_KEYS: List[str] = Field(default_factory=list)

    ADMIN_USER: str = "admin"
    ADMIN_PASS: str = "admin"


settings = Settings()

logging.basicConfig(
    level=settings.LOGGING_LEVEL, format="%(asctime)s - %(levelname)s - %(message)s"
)

abuseipdb_keys_cycle = (
    cycle(settings.ABUSEIPDB_KEYS) if settings.ABUSEIPDB_KEYS else cycle([None])
)
virustotal_keys_cycle = (
    cycle(settings.VIRUSTOTAL_KEYS) if settings.VIRUSTOTAL_KEYS else cycle([None])
)
otx_keys_cycle = cycle(settings.OTX_KEYS) if settings.OTX_KEYS else cycle([None])

# =====================================================================================
# 2. DATABASE & MODELS
# =====================================================================================

Base = declarative_base()
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=settings.DB_POOL_SIZE,
    max_overflow=settings.DB_MAX_OVERFLOW,
)
AsyncSessionLocal = async_sessionmaker(
    bind=engine, class_=AsyncSession, expire_on_commit=False
)

redis_pool = aioredis.from_url(settings.REDIS_URL, decode_responses=True)


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def get_redis() -> aioredis.Redis:
    return redis_pool


class UserRole(str, Enum):
    VIEWER = "viewer"
    EDITOR = "editor"
    ADMIN = "admin"


class ADMembershipStatus(str, Enum):
    PENDING_ADD = "pending_add"
    ACTIVE = "active"
    PENDING_REMOVE = "pending_remove"
    ERROR = "error"


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String, unique=True, nullable=False)
    password = Column(String, nullable=False)
    role = Column(String, default=UserRole.VIEWER, nullable=False)
    api_token = Column(String, unique=True, index=True)
    session_token = Column(String, unique=True, index=True)
    session_expiry = Column(DateTime(timezone=True))
    audit_settings = relationship("UserAuditSettings", back_populates="user", uselist=False, cascade="all, delete-orphan")
    notes = relationship("Note", back_populates="user", cascade="all, delete-orphan")

class UserAuditSettings(Base):
    __tablename__ = "user_audit_settings"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), unique=True, nullable=False)
    log_login_success = Column(Boolean, default=True, nullable=False)
    log_login_failure = Column(Boolean, default=True, nullable=False)
    log_logout = Column(Boolean, default=True, nullable=False)
    log_api_token_create = Column(Boolean, default=True, nullable=False)
    log_ban_create = Column(Boolean, default=True, nullable=False)
    log_ban_update = Column(Boolean, default=True, nullable=False)
    log_ban_delete = Column(Boolean, default=True, nullable=False)
    log_exception_create = Column(Boolean, default=True, nullable=False)
    log_exception_update = Column(Boolean, default=True, nullable=False)
    log_exception_delete = Column(Boolean, default=True, nullable=False)
    log_ad_domain_cud = Column(Boolean, default=True, nullable=False)
    log_ad_group_cud = Column(Boolean, default=True, nullable=False)
    log_ad_membership_cud = Column(Boolean, default=True, nullable=False)
    log_playbook_create = Column(Boolean, default=True, nullable=False)
    log_playbook_update = Column(Boolean, default=True, nullable=False)
    log_playbook_delete = Column(Boolean, default=True, nullable=False)
    log_user_create = Column(Boolean, default=True, nullable=False)
    log_user_update = Column(Boolean, default=True, nullable=False)
    log_user_delete = Column(Boolean, default=True, nullable=False)
    log_webhook_create = Column(Boolean, default=True, nullable=False)
    log_webhook_delete = Column(Boolean, default=True, nullable=False)
    user = relationship("User", back_populates="audit_settings")


class Ban(Base):
    __tablename__ = "bans"
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, nullable=False)
    ip_int = Column(BigInteger, index=True, nullable=False)
    reason = Column(String)
    banned_by = Column(String)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ExceptionIP(Base):
    __tablename__ = "exceptions"
    id = Column(Integer, primary_key=True)
    ip = Column(String, unique=True, nullable=False)
    ip_int = Column(BigInteger, index=True, nullable=False)
    reason = Column(String)
    added_by = Column(String)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Webhook(Base):
    __tablename__ = "webhooks"
    id = Column(Integer, primary_key=True)
    url = Column(String, unique=True, nullable=False)
    created_by = Column(String)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class AuditLog(Base):
    __tablename__ = "audit_logs"
    id = Column(Integer, primary_key=True)
    username = Column(String, index=True)
    action = Column(String)
    details = Column(Text)
    ip_address = Column(String)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Playbook(Base):
    __tablename__ = "playbooks"
    id = Column(Integer, primary_key=True)
    name = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    created_by = Column(String, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class Note(Base):
    __tablename__ = "notes"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    title = Column(String, nullable=False)
    content = Column(Text, nullable=False)
    is_pinned = Column(Boolean, default=False, nullable=False, index=True)
    timestamp = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    user = relationship("User", back_populates="notes")


class ADDomain(Base):
    __tablename__ = "ad_domains"
    id = Column(Integer, primary_key=True)
    name = Column(String, unique=True, nullable=False)
    host = Column(String, nullable=False)
    port = Column(Integer, default=389, nullable=False)
    use_ssl = Column(Boolean, default=False, nullable=False)
    base_dn = Column(String, nullable=False)
    bind_user = Column(String, nullable=False)
    bind_pass_encrypted = Column(String, nullable=False)


class ADManagedGroup(Base):
    __tablename__ = "ad_managed_groups"
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, nullable=False)
    group_dn = Column(String, unique=True, nullable=False)
    group_name = Column(String, nullable=False)
    cleanup_enabled = Column(Boolean, default=False, nullable=False)


class ADMembership(Base):
    __tablename__ = "ad_memberships"
    id = Column(Integer, primary_key=True)
    user_cache_id = Column(
        Integer, ForeignKey("ad_cached_users.id", ondelete="CASCADE"), nullable=False, index=True
    )
    group_dn = Column(String, nullable=False)
    domain_name = Column(String, nullable=False)
    granted_by = Column(String, nullable=False)
    approved_by = Column(String, nullable=True)
    granted_at = Column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc), nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    sync_status = Column(
        String, nullable=False, default=ADMembershipStatus.PENDING_ADD, index=True
    )
    last_sync_attempt = Column(DateTime(timezone=True), nullable=True)
    sync_message = Column(Text, nullable=True)
    retry_count = Column(Integer, default=0, nullable=False)
    user = relationship("ADCachedUser", back_populates="memberships")


class ADCachedUser(Base):
    __tablename__ = "ad_cached_users"
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, nullable=False, index=True)
    user_dn = Column(String, unique=True, nullable=False)
    display_name = Column(String, nullable=False)
    user_principal_name = Column(String, nullable=True)
    memberships = relationship(
        "ADMembership", back_populates="user", cascade="all, delete-orphan"
    )


class ADCachedGroup(Base):
    __tablename__ = "ad_cached_groups"
    id = Column(Integer, primary_key=True)
    domain_id = Column(Integer, nullable=False, index=True)
    group_dn = Column(String, unique=True, nullable=False)
    group_name = Column(String, nullable=False)


async def create_db_tables():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


# =====================================================================================
# 3. SCHEMAS (PYDANTIC MODELS)
# =====================================================================================

class BanCreate(BaseModel):
    ip: str
    reason: Optional[str] = None


class BanUpdate(BanCreate):
    ban_id: int


class BanDelete(BaseModel):
    ban_id: int


class BanRequest(BaseModel):
    ips: List[str]
    reason: Optional[str] = None


class ExceptionCreate(BaseModel):
    ip: str
    reason: Optional[str] = None


class ExceptionUpdate(ExceptionCreate):
    exc_id: int


class ExceptionDelete(BaseModel):
    exc_id: int


class UserCreate(BaseModel):
    username: str
    password: str
    role: UserRole = UserRole.VIEWER


class UserUpdate(BaseModel):
    user_id: int
    password: str


class UserRoleUpdate(BaseModel):
    user_id: int
    role: UserRole


class UserDelete(BaseModel):
    user_id: int


class AuditSettingsUpdate(BaseModel):
    log_login_success: bool
    log_login_failure: bool
    log_logout: bool
    log_api_token_create: bool
    log_ban_create: bool
    log_ban_update: bool
    log_ban_delete: bool
    log_exception_create: bool
    log_exception_update: bool
    log_exception_delete: bool
    log_ad_domain_cud: bool
    log_ad_group_cud: bool
    log_ad_membership_cud: bool
    log_playbook_create: bool
    log_playbook_update: bool
    log_playbook_delete: bool
    log_user_create: bool
    log_user_update: bool
    log_user_delete: bool
    log_webhook_create: bool
    log_webhook_delete: bool


class CheckRequestSingle(BaseModel):
    ips: List[str]
    provider: str
    threshold_percent: float = 50.0
    ban: bool = False
    reason: Optional[str] = None


class ConfirmRequest(BaseModel):
    ips: List[str]
    ban: bool = False
    reason: str = "Marked by operator"


class WebhookCreate(BaseModel):
    url: HttpUrl


class WebhookDelete(BaseModel):
    webhook_id: int


class PlaybookCreate(BaseModel):
    name: str
    content: str


class PlaybookUpdate(PlaybookCreate):
    playbook_id: int


class PlaybookDelete(BaseModel):
    playbook_id: int


class NoteCreate(BaseModel):
    title: str
    content: str


class NoteUpdate(NoteCreate):
    note_id: int


class NoteDelete(BaseModel):
    note_id: int


class NotePinToggle(BaseModel):
    note_id: int


class ADDomainCreate(BaseModel):
    name: str
    host: str
    port: int = 389
    use_ssl: bool = False
    base_dn: str
    bind_user: str
    bind_pass: str


class ADDomainUpdate(BaseModel):
    domain_id: int
    name: str
    host: str
    port: int = 389
    use_ssl: bool = False
    base_dn: str
    bind_user: str
    bind_pass: Optional[str] = None


class ADDomainDelete(BaseModel):
    domain_id: int


class ADDomainRefresh(BaseModel):
    domain_id: int


class ADManagedGroupDelete(BaseModel):
    group_id: int


class ADManagedGroupCleanupToggle(BaseModel):
    group_id: int
    enabled: bool


class ADMembershipDelete(BaseModel):
    grant_id: int


class ADMembershipRetry(BaseModel):
    grant_id: int


class ADGroupCreate(BaseModel):
    domain_id: int
    group_dn: str
    group_name: str


class ADMembershipCreate(BaseModel):
    domain_id: int
    group_dn: str
    user_cache_id: int
    approved_by: Optional[str] = None
    expires_at: Optional[datetime] = None


# =====================================================================================
# 4. GLOBAL OBJECTS & UTILS
# =====================================================================================

app = FastAPI(
    title="IP Management Service", docs_url=None, redoc_url=None, openapi_url=None
)


@app.middleware("http")
async def add_csp_header(request: Request, call_next):
    response = await call_next(request)
    csp_policy = (
        "default-src 'self'; "
        "script-src 'self' https://cdn.jsdelivr.net; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: https://cdn.redoc.ly; "
        "worker-src 'self' blob:; "
        "media-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self';"
    )
    response.headers["Content-Security-Policy"] = csp_policy
    return response


templates = Jinja2Templates(directory="templates")
templates.env.globals["UserRole"] = UserRole

check_semaphore = asyncio.Semaphore(20)
file_io_lock = asyncio.Lock()
banlist_modified = asyncio.Event()


def ip_to_int(ip: str) -> int:
    return int(ip_address(ip))


def to_msk(dt: datetime) -> datetime:
    if dt.tzinfo is None:
        dt = pytz.utc.localize(dt)
    return dt.astimezone(settings.MOSCOW_TZ)


def generate_api_token() -> str:
    return secrets.token_hex(32)


def get_abuseipdb_key():
    return next(abuseipdb_keys_cycle)


def get_virustotal_key():
    return next(virustotal_keys_cycle)


def get_otx_key():
    return next(otx_keys_cycle)


def apply_sorting_and_pagination(
    query, model, sort_by: str, sort_order: str, page: int, limit: int
):
    sort_columns = {
        "ip": getattr(model, "ip_int", None),
        "reason": getattr(model, "reason", None),
        "banned_by": getattr(model, "banned_by", None),
        "added_by": getattr(model, "added_by", None),
        "timestamp": getattr(model, "timestamp", None),
        "username": getattr(model, "username", None),
        "action": getattr(model, "action", None),
        "url": getattr(model, "url", None),
        "timestamp_msk": getattr(model, "timestamp", None),
        "details": getattr(model, "details", None),
        "ip_address": getattr(model, "ip_address", None),
        "name": getattr(model, "name", None),
        "title": getattr(model, "title", None),
        "created_by": getattr(model, "created_by", None),
        "user": ADCachedUser.display_name,
        "group": ADMembership.group_dn,
        "domain": ADMembership.domain_name,
        "granted_by": ADMembership.granted_by,
        "approved_by": ADMembership.approved_by,
        "granted_at": ADMembership.granted_at,
        "expires_at": ADMembership.expires_at,
        "sync_status": ADMembership.sync_status,
    }
    if model == Note:
        query = query.order_by(Note.is_pinned.desc())
        sort_column = sort_columns.get(sort_by)
        if sort_column is not None:
            query = (
                query.order_by(sort_column.asc())
                if sort_order.lower() == "asc"
                else query.order_by(sort_column.desc())
            )
        else:
             query = query.order_by(Note.timestamp.desc())

    elif sort_column := sort_columns.get(sort_by):
        query = (
            query.order_by(sort_column.asc())
            if sort_order.lower() == "asc"
            else query.order_by(sort_column.desc())
        )
    else:
        default_sort_col = getattr(model, "granted_at", getattr(model, "timestamp", getattr(model, "id")))
        query = query.order_by(default_sort_col.desc())

    paginated_query = query.offset((page - 1) * limit).limit(limit)
    return paginated_query



def get_client_ip(request: Request) -> str:
    if not request:
        return "N/A"

    if x_real_ip := request.headers.get("x-real-ip"):
        return x_real_ip

    if x_forwarded_for := request.headers.get("x-forwarded-for"):
        return x_forwarded_for.split(",")[0].strip()

    return request.client.host if request.client else "N/A"


class Encryptor:

    def __init__(self, key: str):
        self.fernet = Fernet(key.encode())

    def encrypt(self, data: str) -> str:
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, encrypted_data: str) -> Optional[str]:
        try:
            return self.fernet.decrypt(encrypted_data.encode()).decode()
        except (InvalidToken, TypeError):
            logging.error("Failed to decrypt data, token is invalid or malformed.")
            return None


encryptor = Encryptor(settings.AD_SECRET_KEY)


# =====================================================================================
# 5. SERVICES (External APIs, Business Logic)
# =====================================================================================

class ADManager:

    def __init__(self, domain: ADDomain):
        self.domain = domain
        self.password = encryptor.decrypt(domain.bind_pass_encrypted)
        self.server = ldap3.Server(
            self.domain.host,
            port=self.domain.port,
            use_ssl=self.domain.use_ssl,
            get_info=ldap3.ALL,
        )

    def _get_connection(self) -> Optional[ldap3.Connection]:
        if not self.password:
            logging.error(
                f"Decryption of bind password for domain '{self.domain.name}' failed. Cannot connect."
            )
            return None
        try:
            return ldap3.Connection(
                self.server,
                user=self.domain.bind_user,
                password=self.password,
                auto_bind=True,
            )
        except LDAPBindError as e:
            logging.error(
                f"LDAP Bind Error for user {self.domain.bind_user} on domain {self.domain.name}: {e}"
            )
        except LDAPException as e:
            logging.error(f"General LDAP Error connecting to {self.domain.host}: {e}")
        return None

    async def test_connection_async(self) -> Tuple[bool, str]:
        return await asyncio.to_thread(self.test_connection)

    async def get_group_members_dns_async(self, group_dn: str) -> List[str]:
        return await asyncio.to_thread(self.get_group_members_dns, group_dn)

    async def is_user_member_of_group_async(self, user_dn: str, group_dn: str) -> bool:
        return await asyncio.to_thread(self.is_user_member_of_group, user_dn, group_dn)

    async def get_all_groups_async(self) -> List[Dict[str, str]]:
        return await asyncio.to_thread(self.get_all_groups)

    async def get_all_users_async(self) -> List[Dict[str, str]]:
        return await asyncio.to_thread(self.get_all_users)

    async def add_user_to_group_async(
        self, user_dn: str, group_dn: str
    ) -> Tuple[bool, str]:
        return await asyncio.to_thread(self.add_user_to_group, user_dn, group_dn)

    async def remove_user_from_group_async(
        self, user_dn: str, group_dn: str
    ) -> Tuple[bool, str]:
        return await asyncio.to_thread(self.remove_user_from_group, user_dn, group_dn)

    def test_connection(self) -> Tuple[bool, str]:
        if not self.password:
            return False, "Connection failed: Could not decrypt stored password."
        try:
            with ldap3.Connection(
                self.server,
                user=self.domain.bind_user,
                password=self.password,
                auto_bind=True,
            ):
                return True, "Connection successful!"
        except LDAPBindError:
            logging.error(
                f"LDAP Bind Error for user {self.domain.bind_user} on domain {self.domain.name}"
            )
            return False, "Connection failed: Invalid credentials or connection problem."
        except LDAPException as e:
            logging.error(f"General LDAP Error for {self.domain.host}: {e}")
            return False, f"Connection failed: Cannot connect to host. Details: {e}"

    def get_group_members_dns(self, group_dn: str) -> List[str]:
        conn = self._get_connection()
        if not conn:
            return []

        try:
            conn.search(
                search_base=group_dn,
                search_filter="(objectClass=*)",
                search_scope=ldap3.BASE,
                attributes=["member"],
            )
            if conn.response and "attributes" in conn.response[0]:
                members = conn.response[0]["attributes"].get("member", [])
                return members if isinstance(members, list) else [members]
        except LDAPException as e:
            logging.error(f"LDAP error fetching members for group {group_dn}: {e}")
        finally:
            conn.unbind()
        return []

    def is_user_member_of_group(self, user_dn: str, group_dn: str) -> bool:
        conn = self._get_connection()
        if not conn:
            return False
        try:
            escaped_group_dn = escape_filter_chars(group_dn)
            search_filter = f"(memberOf:1.2.840.113556.1.4.1941:={escaped_group_dn})"

            conn.search(
                search_base=user_dn,
                search_filter=search_filter,
                search_scope=ldap3.BASE,
                attributes=["dn"],
            )
            return len(conn.response) > 0
        except LDAPException as e:
            logging.error(
                f"LDAP error checking group membership for user '{user_dn}' in group '{group_dn}': {e}"
            )
            return False
        finally:
            if conn:
                conn.unbind()

    def get_all_groups(self) -> List[Dict[str, str]]:
        conn = self._get_connection()
        if not conn:
            return []
        results = []
        try:
            conn.search(
                search_base=self.domain.base_dn,
                search_filter="(objectClass=group)",
                search_scope=ldap3.SUBTREE,
                attributes=["cn"],
            )
            for entry in conn.response:
                if "attributes" in entry and "dn" in entry:
                    cn_value = entry["attributes"].get("cn")
                    group_name = (
                        cn_value[0]
                        if isinstance(cn_value, list) and cn_value
                        else cn_value or entry["dn"]
                    )
                    results.append({"name": group_name, "dn": entry["dn"]})
        finally:
            conn.unbind()
        return results

    def get_all_users(self) -> List[Dict[str, str]]:
        conn = self._get_connection()
        if not conn:
            return []
        results = []
        try:
            search_filter = "(&(objectClass=user)(objectCategory=person)(!(userAccountControl:1.2.840.113556.1.4.803:=2)))"
            conn.search(
                search_base=self.domain.base_dn,
                search_filter=search_filter,
                search_scope=ldap3.SUBTREE,
                attributes=["displayName", "userPrincipalName"],
            )
            for entry in conn.response:
                if "attributes" in entry and "dn" in entry:
                    display_name_val = entry["attributes"].get("displayName")
                    upn_val = entry["attributes"].get("userPrincipalName")

                    user_name = (
                        display_name_val[0]
                        if isinstance(display_name_val, list) and display_name_val
                        else display_name_val or entry["dn"]
                    )
                    upn = (
                        upn_val[0]
                        if isinstance(upn_val, list) and upn_val
                        else upn_val if not isinstance(upn_val, list) else None
                    )

                    if user_name:
                        results.append(
                            {"displayName": user_name, "dn": entry["dn"], "upn": upn}
                        )
        finally:
            if conn:
                conn.unbind()
        return results

    def add_user_to_group(self, user_dn: str, group_dn: str) -> Tuple[bool, str]:
        conn = self._get_connection()
        if not conn:
            return False, "Failed to get LDAP connection"

        try:
            conn.modify(group_dn, {"member": [(ldap3.MODIFY_ADD, [user_dn])]})
            if conn.result["result"] == 0:
                logging.info(f"Successfully added {user_dn} to {group_dn}")
                return True, "Success"
            description = conn.result.get("description", "")
            if "entryAlreadyExists" in str(description):
                logging.warning(f"User {user_dn} is already a member of {group_dn}.")
                return True, "User already a member"

            error_msg = f"Failed to add user to group: {conn.result}"
            logging.error(error_msg)
            return False, str(conn.result)
        except LDAPException as e:
            error_msg = f"LDAP exception adding user to group: {e}"
            logging.error(error_msg)
            return False, str(e)
        finally:
            conn.unbind()

    def remove_user_from_group(self, user_dn: str, group_dn: str) -> Tuple[bool, str]:
        conn = self._get_connection()
        if not conn:
            return False, "Failed to get LDAP connection"

        try:
            conn.modify(group_dn, {"member": [(ldap3.MODIFY_DELETE, [user_dn])]})
            if conn.result["result"] == 0:
                logging.info(f"Successfully removed {user_dn} from {group_dn}")
                return True, "Success"
            description = conn.result.get("description", "")
            if "noSuchAttribute" in str(description):
                logging.warning(
                    f"Attempted to remove non-existent member {user_dn} from {group_dn}."
                )
                return True, "User was not a member"

            error_msg = f"Failed to remove user from group: {conn.result}"
            logging.warning(error_msg)
            return False, str(conn.result)
        except LDAPException as e:
            error_msg = f"LDAP exception removing user from group: {e}"
            logging.error(error_msg)
            return False, str(e)
        finally:
            conn.unbind()

async def log_audit_event(
    db: AsyncSession,
    request: Optional[Request],
    username: Optional[str],
    action: str,
    details: str = "",
):
    if not username or username == "system":
        pass
    else:
        user_res = await db.execute(
            select(User).where(User.username == username).options(selectinload(User.audit_settings))
        )
        user = user_res.scalar_one_or_none()

        if user and user.audit_settings:
            settings = user.audit_settings
            category_map = {
                "LOGIN_SUCCESS": settings.log_login_success,
                "LOGIN_FAILURE": settings.log_login_failure,
                "LOGOUT": settings.log_logout,
                "CREATE_API_TOKEN": settings.log_api_token_create,
                "ADD_BAN": settings.log_ban_create,
                "BULK_ADD_BANS": settings.log_ban_create,
                "UPDATE_BAN": settings.log_ban_update,
                "DELETE_BAN": settings.log_ban_delete,
                "AUTO_BAN_ADD": settings.log_ban_create,
                "AUTO_BAN_UPDATE": settings.log_ban_update,
                "ADD_EXCEPTION": settings.log_exception_create,
                "BULK_ADD_EXCEPTIONS": settings.log_exception_create,
                "UPDATE_EXCEPTION": settings.log_exception_update,
                "DELETE_EXCEPTION": settings.log_exception_delete,
                "CREATE_USER": settings.log_user_create,
                "UPDATE_USER_PASSWORD": settings.log_user_update,
                "UPDATE_USER_ROLE": settings.log_user_update,
                "UPDATE_AUDIT_SETTINGS": settings.log_user_update,
                "DELETE_USER": settings.log_user_delete,
                "CREATE_PLAYBOOK": settings.log_playbook_create,
                "UPDATE_PLAYBOOK": settings.log_playbook_update,
                "DELETE_PLAYBOOK": settings.log_playbook_delete,
                "CREATE_WEBHOOK": settings.log_webhook_create,
                "DELETE_WEBHOOK": settings.log_webhook_delete,
                "AD_DOMAIN_CREATE": settings.log_ad_domain_cud,
                "AD_DOMAIN_UPDATE": settings.log_ad_domain_cud,
                "AD_DOMAIN_DELETE": settings.log_ad_domain_cud,
                "AD_GROUP_ADD_MANAGED": settings.log_ad_group_cud,
                "AD_GROUP_REMOVE_MANAGED": settings.log_ad_group_cud,
                "AD_GROUP_CLEANUP_TOGGLE": settings.log_ad_group_cud,
                "AD_MEMBERSHIP_GRANT_QUEUED": settings.log_ad_membership_cud,
                "AD_MEMBERSHIP_REVOKE_QUEUED": settings.log_ad_membership_cud,
                "AD_MEMBERSHIP_RETRY": settings.log_ad_membership_cud,
            }
            if action in category_map and not category_map[action]:
                return

    log_entry = AuditLog(
        username=username or "system",
        action=action,
        details=details,
        ip_address=get_client_ip(request) if request else "N/A",
    )
    db.add(log_entry)


async def trigger_webhooks(event: str, payload: dict):
    async with AsyncSessionLocal() as db:
        hooks_result = await db.execute(select(Webhook))
        hooks = hooks_result.scalars().all()
        if not hooks:
            return

    async with httpx.AsyncClient() as client:
        tasks = []
        for hook in hooks:
            data = {
                "event": event,
                "payload": payload,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            tasks.append(client.post(hook.url, json=data, timeout=10))

        results = await asyncio.gather(*tasks, return_exceptions=True)
        for url, res in zip([h.url for h in hooks], results):
            if isinstance(res, Exception):
                logging.warning(f"Webhook to {url} failed: {res}")
            elif res.status_code >= 400:
                logging.warning(f"Webhook to {url} returned status {res.status_code}")


# =====================================================================================
# 6. CRUD OPERATIONS
# =====================================================================================

async def _archive_banlist():
    if not settings.BANLIST_FILE_PATH.exists():
        logging.warning("banlist.txt does not exist, skipping archival.")
        return

    version = 1
    if settings.BANLIST_VERSION_PATH.exists():
        try:
            version = (
                int(settings.BANLIST_VERSION_PATH.read_text(encoding="utf-8").strip())
                + 1
            )
        except (ValueError, FileNotFoundError):
            pass
    settings.BANLIST_VERSION_PATH.write_text(str(version), encoding="utf-8")

    try:
        with zipfile.ZipFile(
            settings.BANLIST_ARCHIVE_PATH, "w", zipfile.ZIP_DEFLATED
        ) as zf:
            zf.write(settings.BANLIST_FILE_PATH, arcname="list.txt")
        logging.info(f"Successfully archived banlist to version {version}.")

        md5_hash = hashlib.md5()
        with open(settings.BANLIST_ARCHIVE_PATH, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                md5_hash.update(chunk)
        checksum = md5_hash.hexdigest()
        md5_file_path = settings.BANLIST_ARCHIVE_PATH.with_suffix(".zip.md5")
        md5_file_path.write_text(
            f"{checksum}  {settings.BANLIST_ARCHIVE_PATH.name}\n", encoding="utf-8"
        )
        logging.info(f"Successfully created checksum file: {md5_file_path.name}")
    except OSError as e:
        logging.error(f"Failed to archive banlist or create checksum: {e}")


async def update_and_archive_banlist_file():
    async with file_io_lock:
        try:
            async with AsyncSessionLocal() as db:
                result = await db.execute(select(Ban.ip))
                banned_ips = [ip for (ip,) in result.all()]

            temp_file_path = settings.BANLIST_FILE_PATH.with_suffix(".tmp")
            with open(temp_file_path, "w", encoding="utf-8") as f:
                f.write("\n".join(banned_ips))
            os.replace(temp_file_path, settings.BANLIST_FILE_PATH)

            logging.info(f"Banlist file updated with {len(banned_ips)} IPs.")
            await _archive_banlist()
        except Exception as e:
            logging.error(f"Error during banlist file update and archival: {e}")


async def get_exception_networks(redis: aioredis.Redis) -> List[ip_network]:
    cache_key = "exception_networks"
    if cached_json := await redis.get(cache_key):
        try:
            return [ip_network(s, strict=False) for s in json.loads(cached_json)]
        except (json.JSONDecodeError, ValueError) as e:
            logging.warning(f"Could not parse cached exception networks: {e}")

    logging.info("Updating exception networks cache from DB...")
    networks, strings_to_cache = [], []
    async with AsyncSessionLocal() as db:
        result = await db.execute(select(ExceptionIP.ip))
        for (exc_ip,) in result.all():
            try:
                networks.append(ip_network(exc_ip, strict=False))
                strings_to_cache.append(exc_ip)
            except (ValueError, IndexError):
                continue
    await redis.set(cache_key, json.dumps(strings_to_cache), ex=3600)
    return networks


async def is_ip_in_exceptions(ip_str: str, redis: aioredis.Redis) -> bool:
    try:
        addr = ip_address(ip_str)
        networks = await get_exception_networks(redis)
        return any(addr in net for net in networks)
    except ValueError:
        return False


async def upsert_ban(
    db: AsyncSession, ip: str, reason: str, username: str
) -> Tuple[str, Ban]:
    result = await db.execute(select(Ban).where(Ban.ip == ip))
    if existing_ban := result.scalar_one_or_none():
        existing_ban.reason = reason
        existing_ban.banned_by = username
        existing_ban.timestamp = datetime.now(timezone.utc)
        return "updated", existing_ban

    new_ban = Ban(
        ip=ip,
        ip_int=ip_to_int(ip),
        reason=reason,
        banned_by=username,
        timestamp=datetime.now(timezone.utc),
    )
    db.add(new_ban)
    return "added", new_ban


async def delete_ban(db: AsyncSession, ban_id: int) -> Optional[Ban]:
    result = await db.execute(select(Ban).where(Ban.id == ban_id))
    if ban := result.scalar_one_or_none():
        await db.delete(ban)
        return ban
    return None


async def upsert_exception(
    db: AsyncSession, network_str: str, reason: str, username: str, redis: aioredis.Redis
) -> int:
    network = ip_network(network_str, strict=False)
    canonical_net_str = str(network)

    result = await db.execute(
        select(ExceptionIP).where(ExceptionIP.ip == canonical_net_str)
    )
    if existing_exc := result.scalar_one_or_none():
        existing_exc.reason = reason
        existing_exc.added_by = username
        existing_exc.timestamp = datetime.now(timezone.utc)
    else:
        new_exc = ExceptionIP(
            ip=canonical_net_str,
            ip_int=int(network.network_address),
            reason=reason,
            added_by=username,
        )
        db.add(new_exc)

    stmt = delete(Ban).where(
        Ban.ip_int >= int(network.network_address),
        Ban.ip_int <= int(network.broadcast_address),
    )
    delete_result = await db.execute(stmt)
    await redis.delete("exception_networks")
    return delete_result.rowcount


async def delete_exception(db: AsyncSession, exc_id: int, redis: aioredis.Redis) -> bool:
    result = await db.execute(select(ExceptionIP).where(ExceptionIP.id == exc_id))
    if exc := result.scalar_one_or_none():
        await db.delete(exc)
        await redis.delete("exception_networks")
        return True
    return False


# =====================================================================================
# 7. AUTHENTICATION
# =====================================================================================

async def get_current_user(
    request: Request, db: AsyncSession = Depends(get_db)
) -> User:
    token = request.cookies.get("user")
    if not token:
        raise HTTPException(status_code=401, detail="Not logged in")

    result = await db.execute(select(User).where(User.session_token == token))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(status_code=401, detail="Session invalid")

    session_expired = False
    if user.session_expiry:
        session_expiry_aware = user.session_expiry
        if session_expiry_aware.tzinfo is None:
            session_expiry_aware = session_expiry_aware.replace(tzinfo=timezone.utc)
        
        if session_expiry_aware < datetime.now(timezone.utc):
            session_expired = True

    if session_expired:
        headers = {
            "Set-Cookie": "user=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT; samesite=lax; httponly"
        }
        raise HTTPException(
            status_code=401, detail="Session expired", headers=headers
        )
    return user


async def get_current_user_optional(
    request: Request, db: AsyncSession = Depends(get_db)
) -> Optional[User]:
    try:
        return await get_current_user(request, db)
    except HTTPException:
        return None


def require_role(allowed_roles: List[UserRole]):

    async def dependency(current_user: User = Depends(get_current_user)) -> User:
        if current_user.role not in allowed_roles:
            raise HTTPException(status_code=403, detail="Insufficient permissions")
        return current_user

    return dependency


require_viewer = require_role([UserRole.VIEWER, UserRole.EDITOR, UserRole.ADMIN])
require_editor = require_role([UserRole.EDITOR, UserRole.ADMIN])
require_admin = require_role([UserRole.ADMIN])


async def get_user_by_token(
    authorization: str = Header(...), db: AsyncSession = Depends(get_db)
) -> User:
    if not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Invalid token header format")
    token = authorization.split(" ")[1]
    result = await db.execute(select(User).where(User.api_token == token))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=401, detail="Invalid API token")
    return user


async def create_default_admin():
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(User.id).where(User.username == settings.ADMIN_USER)
        )
        if not result.scalar_one_or_none():
            hashed_password = bcrypt.hash(settings.ADMIN_PASS)
            admin_user = User(
                username=settings.ADMIN_USER,
                password=hashed_password,
                role=UserRole.ADMIN,
                audit_settings=UserAuditSettings()
            )
            db.add(admin_user)
            await db.commit()
            logging.info(f"Default admin user '{settings.ADMIN_USER}' created.")


# =====================================================================================
# 8. BACKGROUND TASKS
# =====================================================================================

async def cleanup_task():
    while True:
        await asyncio.sleep(24 * 3600)
        async with AsyncSessionLocal() as db:
            try:
                expiration_date = datetime.now(timezone.utc) - timedelta(
                    days=settings.BAN_TTL_DAYS
                )
                stmt = delete(Ban).where(Ban.timestamp < expiration_date)
                result = await db.execute(stmt)
                if deleted_count := result.rowcount:
                    await db.commit()
                    banlist_modified.set()
                    logging.info(f"Cleaned up {deleted_count} expired bans.")
            except Exception as e:
                logging.error(f"Error in cleanup task: {e}")


async def audit_cleanup_task():
    while True:
        await asyncio.sleep(24 * 3600)
        logging.info("Running daily audit log cleanup task...")
        async with AsyncSessionLocal() as db:
            try:
                expiration_date = datetime.now(timezone.utc) - timedelta(
                    days=settings.AUDIT_LOG_TTL_DAYS
                )
                stmt = delete(AuditLog).where(AuditLog.timestamp < expiration_date)
                result = await db.execute(stmt)
                if deleted_count := result.rowcount:
                    await db.commit()
                    logging.info(f"Cleaned up {deleted_count} old audit log entries.")
            except Exception as e:
                logging.error(f"Error in audit cleanup task: {e}")


async def expired_membership_cleanup_task():
    while True:
        await asyncio.sleep(settings.AD_EXPIRED_MEMBERSHIP_CLEANUP_MINUTES * 60)
        logging.info("Checking for expired AD memberships...")
        async with AsyncSessionLocal() as db:
            try:
                now = datetime.now(timezone.utc)
                stmt = (
                    update(ADMembership)
                    .where(
                        ADMembership.expires_at != None,
                        ADMembership.expires_at <= now,
                        ADMembership.sync_status == ADMembershipStatus.ACTIVE,
                    )
                    .values(
                        sync_status=ADMembershipStatus.PENDING_REMOVE,
                        retry_count=0
                    )
                )
                result = await db.execute(stmt)
                if result.rowcount > 0:
                    logging.info(
                        f"Flagged {result.rowcount} expired memberships for removal."
                    )
                    await db.commit()
            except Exception as e:
                await db.rollback()
                logging.error(f"Error in expired membership cleanup task: {e}")


async def membership_sync_task():
    while True:
        await asyncio.sleep(settings.AD_MEMBERSHIP_SYNC_INTERVAL_SECONDS)
        async with AsyncSessionLocal() as db:
            try:
                domains_res = await db.execute(select(ADDomain))
                domains_map = {d.name: d for d in domains_res.scalars().all()}
                managers = {
                    name: ADManager(domain) for name, domain in domains_map.items()
                }

                add_stmt = (
                    select(ADMembership)
                    .where(ADMembership.sync_status == ADMembershipStatus.PENDING_ADD)
                    .options(selectinload(ADMembership.user))
                )
                for grant in (await db.execute(add_stmt)).scalars().all():
                    if not grant.user:
                        grant.sync_status = ADMembershipStatus.ERROR
                        grant.sync_message = f"User with cache ID {grant.user_cache_id} not found."
                        continue

                    user_dn, group_dn = grant.user.user_dn, grant.group_dn
                    if not (manager := managers.get(grant.domain_name)):
                        grant.sync_status = ADMembershipStatus.ERROR
                        grant.sync_message = f"Domain '{grant.domain_name}' not found."
                        continue

                    grant.last_sync_attempt = datetime.now(timezone.utc)
                    success, message = await manager.add_user_to_group_async(user_dn, group_dn)
                    
                    if success:
                        grant.sync_status = ADMembershipStatus.ACTIVE
                        grant.sync_message = "Successfully added or already a member."
                        grant.retry_count = 0
                    else:
                        grant.retry_count += 1
                        grant.sync_message = f"Attempt {grant.retry_count}: {message}"
                        if grant.retry_count >= settings.AD_MEMBERSHIP_MAX_RETRIES:
                            grant.sync_status = ADMembershipStatus.ERROR
                            logging.error(f"Grant add for {user_dn} failed after {grant.retry_count} retries.")


                remove_stmt = (
                    select(ADMembership)
                    .where(ADMembership.sync_status == ADMembershipStatus.PENDING_REMOVE)
                    .options(selectinload(ADMembership.user))
                )
                grants_to_delete_ids = []
                for grant in (await db.execute(remove_stmt)).scalars().all():
                    if not grant.user or not (manager := managers.get(grant.domain_name)):
                        logging.warning(f"Orphaned or invalid grant ID {grant.id} found during removal. Deleting record.")
                        grants_to_delete_ids.append(grant.id)
                        continue

                    user_dn, group_dn = grant.user.user_dn, grant.group_dn
                    grant.last_sync_attempt = datetime.now(timezone.utc)
                    success, message = await manager.remove_user_from_group_async(user_dn, group_dn)
                    
                    if success:
                        grants_to_delete_ids.append(grant.id)
                    else:
                        grant.retry_count += 1
                        grant.sync_message = f"Attempt {grant.retry_count}: {message}"
                        if grant.retry_count >= settings.AD_MEMBERSHIP_MAX_RETRIES:
                            grant.sync_status = ADMembershipStatus.ERROR
                            logging.error(f"Grant removal for {user_dn} failed after {grant.retry_count} retries.")


                if grants_to_delete_ids:
                    await db.execute(delete(ADMembership).where(ADMembership.id.in_(grants_to_delete_ids)))
                
                await db.commit()

            except Exception as e:
                await db.rollback()
                logging.error(f"Critical error in membership sync task: {e}", exc_info=True)


async def group_cleanup_task():
    while True:
        await asyncio.sleep(settings.AD_GROUP_CLEANUP_INTERVAL_MINUTES * 60)
        logging.info("Starting periodic AD group cleanup and reconciliation task...")
        async with AsyncSessionLocal() as db:
            try:
                domains_res = await db.execute(select(ADDomain))
                domains_map = {d.id: d for d in domains_res.scalars().all()}

                cleanup_groups_res = await db.execute(
                    select(ADManagedGroup).where(ADManagedGroup.cleanup_enabled == True)
                )
                for group in cleanup_groups_res.scalars().all():
                    if not (domain := domains_map.get(group.domain_id)):
                        logging.warning(f"Skipping reconciliation for group '{group.group_name}' due to missing domain ID {group.domain_id}")
                        continue

                    logging.info(f"Reconciling group: {group.group_name} ({domain.name})")
                    manager = ADManager(domain)
                    
                    actual_dns = set(
                        await manager.get_group_members_dns_async(group.group_dn)
                    )

                    expected_res = await db.execute(
                        select(ADCachedUser.user_dn)
                        .join(ADMembership)
                        .where(
                            ADMembership.group_dn == group.group_dn,
                            ADMembership.sync_status.in_(
                                [ADMembershipStatus.ACTIVE, ADMembershipStatus.PENDING_ADD]
                            ),
                        )
                    )
                    expected_dns = {row[0] for row in expected_res.all()}

                    to_remove = actual_dns - expected_dns
                    if to_remove:
                        logging.warning(
                            f"Found {len(to_remove)} unexpected member(s) in AD group '{group.group_name}'. Removing..."
                        )
                        for user_dn in to_remove:
                            success, msg = await manager.remove_user_from_group_async(
                                user_dn, group.group_dn
                            )
                            if success:
                                await log_audit_event(
                                    db, None, "system", "AD_GROUP_CLEANUP_REMOVED",
                                    f"Removed unexpected user: {user_dn} from group: {group.group_name}"
                                )
                            else:
                                 logging.error(f"Cleanup failed to remove {user_dn} from {group.group_name}: {msg}")

                    to_add = expected_dns - actual_dns
                    if to_add:
                        logging.warning(
                            f"Found {len(to_add)} missing member(s) in AD group '{group.group_name}'. Re-adding..."
                        )
                        for user_dn in to_add:
                            success, msg = await manager.add_user_to_group_async(
                                user_dn, group.group_dn
                            )
                            if success:
                                await log_audit_event(
                                    db, None, "system", "AD_GROUP_CLEANUP_ADDED",
                                    f"Re-added missing user: {user_dn} to group: {group.group_name}"
                                )
                            else:
                                logging.error(f"Cleanup failed to re-add {user_dn} to {group.group_name}: {msg}")

                await db.commit()
            except Exception as e:
                await db.rollback()
                logging.error(f"Critical error in AD group cleanup task: {e}", exc_info=True)


async def update_single_domain_cache(domain_id: int):
    logging.info(f"Starting smart cache sync for domain ID: {domain_id}")
    async with AsyncSessionLocal() as db:
        try:
            domain = await db.get(ADDomain, domain_id)
            if not domain:
                logging.error(f"Cannot sync cache: Domain with ID {domain_id} not found.")
                return

            manager = ADManager(domain)
            is_ok, msg = await manager.test_connection_async()
            if not is_ok:
                logging.error(f"Cannot connect to domain {domain.name} for cache sync: {msg}")
                return

            fresh_users_list, fresh_groups_list, cached_users_res, cached_groups_res = await asyncio.gather(
                manager.get_all_users_async(),
                manager.get_all_groups_async(),
                db.execute(select(ADCachedUser).where(ADCachedUser.domain_id == domain.id)),
                db.execute(select(ADCachedGroup).where(ADCachedGroup.domain_id == domain.id))
            )

            fresh_users_map = {u['dn']: u for u in fresh_users_list}
            fresh_groups_map = {g['dn']: g for g in fresh_groups_list}
            cached_users_map = {u.user_dn: u for u in cached_users_res.scalars().all()}
            cached_groups_map = {g.group_dn: g for g in cached_groups_res.scalars().all()}

            users_to_add, users_processed = [], 0
            for dn, data in fresh_users_map.items():
                if cached := cached_users_map.get(dn):
                    if (cached.display_name != data['displayName'] or cached.user_principal_name != data.get('upn')):
                        cached.display_name, cached.user_principal_name = data['displayName'], data.get('upn')
                        users_processed += 1
                else:
                    users_to_add.append(ADCachedUser(domain_id=domain.id, user_dn=dn, display_name=data['displayName'], user_principal_name=data.get('upn')))
            if users_to_add: db.add_all(users_to_add)

            if to_delete := set(cached_users_map.keys()) - set(fresh_users_map.keys()):
                await db.execute(delete(ADCachedUser).where(ADCachedUser.user_dn.in_(to_delete)))

            groups_to_add = []
            for dn, data in fresh_groups_map.items():
                if cached := cached_groups_map.get(dn):
                    if cached.group_name != data['name']:
                        cached.group_name = data['name']
                else:
                    groups_to_add.append(ADCachedGroup(domain_id=domain.id, group_dn=dn, group_name=data['name']))
            if groups_to_add: db.add_all(groups_to_add)

            if to_delete := set(cached_groups_map.keys()) - set(fresh_groups_map.keys()):
                 await db.execute(delete(ADCachedGroup).where(ADCachedGroup.group_dn.in_(to_delete)))

            await db.commit()
            logging.info(f"Cache sync for domain {domain.name} completed.")
        except Exception as e:
            await db.rollback()
            logging.error(f"Error during smart cache sync for domain ID {domain_id}: {e}")


async def update_ad_cache_task():
    while True:
        logging.info("Running periodic AD cache update for all domains...")
        async with AsyncSessionLocal() as db:
            result = await db.execute(select(ADDomain.id))
            domain_ids = [d_id for (d_id,) in result.all()]

        await asyncio.gather(*(update_single_domain_cache(d_id) for d_id in domain_ids))
        await asyncio.sleep(settings.AD_CACHE_REFRESH_MINUTES * 60)


async def periodic_banlist_update_task():
    while True:
        await banlist_modified.wait()
        logging.info(
            f"Banlist change detected. Debouncing for {settings.BANLIST_UPDATE_INTERVAL_MINUTES} min."
        )
        await asyncio.sleep(settings.BANLIST_UPDATE_INTERVAL_MINUTES * 60)
        banlist_modified.clear()
        logging.info("Updating and archiving banlist file...")
        await update_and_archive_banlist_file()


# =====================================================================================
# 9. IP REPUTATION LOGIC
# =====================================================================================

async def query_abuseipdb(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not (key := get_abuseipdb_key()):
        return {"provider": "abuseipdb", "error": "API key not configured"}
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {"ipAddress": ip, "maxAgeInDays": 90}
    headers = {"Key": key, "Accept": "application/json"}
    try:
        response = await client.get(url, params=params, headers=headers, timeout=20.0)
        response.raise_for_status()
        data = response.json().get("data", {})
        score = data.get("abuseConfidenceScore")
        return {
            "provider": "abuseipdb",
            "score": float(score) if score is not None else None,
            "raw": data,
        }
    except Exception as e:
        logging.error(f"AbuseIPDB query for {ip} failed: {e}")
        return {"provider": "abuseipdb", "error": "Provider query failed"}


async def query_virustotal(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not (key := get_virustotal_key()):
        return {"provider": "virustotal", "error": "API key not configured"}
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": key}
    try:
        response = await client.get(url, headers=headers, timeout=20.0)
        if response.status_code == 404:
            return {"provider": "virustotal", "score": 0, "raw": {}}
        response.raise_for_status()

        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        last_analysis = attributes.get("last_analysis_stats", {})
        malicious = last_analysis.get("malicious", 0)
        suspicious = last_analysis.get("suspicious", 0)
        total = sum(last_analysis.values())
        score = 100 * (malicious + suspicious) / max(1, total) if total > 0 else 0

        return {"provider": "virustotal", "score": round(score, 2), "raw": attributes}
    except Exception as e:
        logging.error(f"VirusTotal query for {ip} failed: {e}")
        return {"provider": "virustotal", "error": "Provider query failed"}


async def query_otx(client: httpx.AsyncClient, ip: str) -> Dict[str, Any]:
    if not (key := get_otx_key()):
        return {"provider": "otx", "error": "API key not configured"}
    url = f"https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/reputation"
    headers = {"X-OTX-API-KEY": key}
    try:
        response = await client.get(url, headers=headers, timeout=20.0)
        if response.status_code == 404:
            return {"provider": "otx", "score": 0, "raw": {}}
        response.raise_for_status()
        data = response.json()
        reputation_val = data.get("reputation")
        score = max(0, min(100, int(reputation_val))) if reputation_val else None
        return {"provider": "otx", "score": score, "raw": data}
    except Exception as e:
        logging.error(f"OTX query for {ip} failed: {e}")
        return {"provider": "otx", "error": "Provider query failed"}


async def get_ip_cache(
    redis: aioredis.Redis, ip: str, provider: str
) -> Optional[Dict]:
    cache_key = f"ip_cache:{provider}:{ip}"
    if cached_data := await redis.get(cache_key):
        try:
            return json.loads(cached_data)
        except json.JSONDecodeError:
            return None
    return None


async def set_ip_cache(
    redis: aioredis.Redis, ip: str, provider: str, percent: float, provider_data: Any
):
    cache_key = f"ip_cache:{provider}:{ip}"
    ttl = int(timedelta(days=settings.CACHE_TTL_DAYS).total_seconds())
    await redis.set(cache_key, json.dumps({"percent": percent, "raw": provider_data}), ex=ttl)


async def _process_ip_check_results(
    request: Request,
    ips: List[str],
    responses: List[Dict],
    provider: str,
    should_ban: bool,
    threshold: float,
    user: User,
    db: AsyncSession,
    redis: aioredis.Redis,
    reason: Optional[str] = None,
) -> Tuple[List[Dict], List[Dict]]:
    results, added_to_ban, made_changes = [], [], False
    bannable_ips = {ip for ip in ips if not await is_ip_in_exceptions(ip, redis)}

    for ip, res in zip(ips, responses):
        if isinstance(res, Exception):
            results.append({"ip": ip, "error": str(res)})
            continue

        score = res.get("score", 0) if isinstance(res.get("score"), (int, float)) else 0.0
        entry = {"ip": ip, "percent": score, "provider": provider, "raw": res.get("raw"), "auto_banned": False}

        if should_ban and score >= threshold and ip in bannable_ips:
            ban_reason = (
                f"{reason} ({score}%)" if reason else f"Auto-banned via {provider} ({score}%)"
            )
            status, _ = await upsert_ban(db, ip, ban_reason, user.username)
            added_to_ban.append({"ip": ip, "status": status})
            entry["auto_banned"] = True
            made_changes = True

            audit_action = "AUTO_BAN_ADD" if status == "added" else "AUTO_BAN_UPDATE"
            await log_audit_event(
                db, request, user.username, audit_action, f"IP: {ip}, Reason: {ban_reason}"
            )
            webhook_event = "ban.added" if status == "added" else "ban.updated"
            asyncio.create_task(
                trigger_webhooks(webhook_event, {"ip": ip, "reason": ban_reason, "source": user.username})
            )

        results.append(entry)

    if made_changes:
        banlist_modified.set()
    return results, added_to_ban


async def _api_check_logic(
    request_data: CheckRequestSingle,
    request: Request,
    user: User,
    db: AsyncSession,
    redis: aioredis.Redis,
):
    if request_data.provider not in settings.PROVIDERS:
        raise HTTPException(status_code=400, detail="Invalid provider selected")

    valid_ips = list({ip.strip() for ip in request_data.ips if ip.strip()})
    if not valid_ips:
        raise HTTPException(status_code=400, detail="No valid IPs provided")
    try:
        [ip_address(ip) for ip in valid_ips]
    except ValueError as e:
        raise HTTPException(status_code=400, detail=f"Invalid IP address format: {e}")

    ips_to_fetch, cached_map = [], {}
    for ip in valid_ips:
        if cached := await get_ip_cache(redis, ip, request_data.provider):
            cached_map[ip] = {"score": cached.get("percent", 0.0), "raw": cached.get("raw", {})}
        else:
            ips_to_fetch.append(ip)

    fetched_map = {}
    if ips_to_fetch:
        provider_map = {
            "abuseipdb": query_abuseipdb,
            "virustotal": query_virustotal,
            "otx": query_otx,
        }
        query_func = provider_map.get(request_data.provider)

        async def fetch_one(client, ip):
            async with check_semaphore:
                return await query_func(client, ip)

        async with httpx.AsyncClient() as client:
            tasks = [fetch_one(client, ip) for ip in ips_to_fetch]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            fetched_map = dict(zip(ips_to_fetch, results))

        cache_tasks = []
        for ip, res in fetched_map.items():
            if isinstance(res, dict) and "error" not in res:
                score = res.get("score", 0.0) if isinstance(res.get("score"), (int, float)) else 0.0
                cache_tasks.append(set_ip_cache(redis, ip, request_data.provider, score, res.get("raw", {})))
        if cache_tasks:
            await asyncio.gather(*cache_tasks)

    all_responses = {**cached_map, **fetched_map}
    responses = [all_responses[ip] for ip in valid_ips]

    processed, banned = await _process_ip_check_results(
        request, valid_ips, responses, request_data.provider, request_data.ban,
        request_data.threshold_percent, user, db, redis, request_data.reason
    )
    if banned:
        await db.commit()
    return {"ok": True, "results": processed, "auto_banned": banned}


# =====================================================================================
# 10. API ROUTERS
# =====================================================================================

api_router = APIRouter()
ad_router = APIRouter(prefix="/ad", tags=["Active Directory"])
bans_router = APIRouter(prefix="/bans", tags=["Bans"])
exceptions_router = APIRouter(prefix="/exceptions", tags=["Exceptions"])
users_router = APIRouter(prefix="/users", tags=["Users"])
token_router = APIRouter(prefix="/token", tags=["Token"])
check_router = APIRouter(prefix="/check", tags=["Check"])
stats_router = APIRouter(prefix="/stats", tags=["Stats"])
webhooks_router = APIRouter(prefix="/webhooks", tags=["Webhooks"])
audit_router = APIRouter(prefix="/audit", tags=["Audit"])
playbooks_router = APIRouter(prefix="/playbooks", tags=["Playbooks"])
notes_router = APIRouter(prefix="/notes", tags=["Notes"])


def _get_period_params(period: str) -> Tuple[datetime, str, str, timedelta]:
    now = datetime.now(timezone.utc)
    if period == "day":
        start_date = now - timedelta(hours=24)
        return start_date, 'hour', "%H:00", timedelta(hours=1)
    elif period == "week":
        start_date = now - timedelta(days=7)
        return start_date, 'day', "%d.%m", timedelta(days=1)
    else:
        start_date = now - timedelta(days=30)
        return start_date, 'day', "%d.%m", timedelta(days=1)

def _truncate_datetime(dt: datetime, period_type: str) -> datetime:
    if period_type == 'hour':
        return dt.replace(minute=0, second=0, microsecond=0)
    return dt.replace(hour=0, minute=0, second=0, microsecond=0)


@ad_router.get("/domains", dependencies=[Depends(require_editor)])
async def list_ad_domains(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(ADDomain))
    return [
        {
            "id": d.id, "name": d.name, "host": d.host, "port": d.port,
            "use_ssl": d.use_ssl, "base_dn": d.base_dn, "bind_user": d.bind_user,
        }
        for d in result.scalars().all()
    ]


@ad_router.post("/domains", dependencies=[Depends(require_admin)])
async def create_ad_domain(
    request: Request, data: ADDomainCreate, background_tasks: BackgroundTasks,
    user: User = Depends(require_admin), db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(ADDomain.id).where(ADDomain.name == data.name))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="A domain with this name already exists.")
    new_domain = ADDomain(
        name=data.name, host=data.host, port=data.port, use_ssl=data.use_ssl,
        base_dn=data.base_dn, bind_user=data.bind_user,
        bind_pass_encrypted=encryptor.encrypt(data.bind_pass),
    )
    db.add(new_domain)
    await log_audit_event(db, request, user.username, "AD_DOMAIN_CREATE", f"Name: {data.name}")
    try:
        await db.commit()
        await db.refresh(new_domain)
        background_tasks.add_task(update_single_domain_cache, new_domain.id)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="A domain with this name already exists.")
    return {"ok": True}


@ad_router.post("/domains/update", dependencies=[Depends(require_admin)])
async def update_ad_domain(
    request: Request, data: ADDomainUpdate, background_tasks: BackgroundTasks,
    user: User = Depends(require_admin), db: AsyncSession = Depends(get_db),
):
    domain = await db.get(ADDomain, data.domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found.")
    domain.name, domain.host, domain.port = data.name, data.host, data.port
    domain.use_ssl, domain.base_dn, domain.bind_user = data.use_ssl, data.base_dn, data.bind_user
    if data.bind_pass:
        domain.bind_pass_encrypted = encryptor.encrypt(data.bind_pass)
    await log_audit_event(db, request, user.username, "AD_DOMAIN_UPDATE", f"Name: {data.name}")
    try:
        await db.commit()
        background_tasks.add_task(update_single_domain_cache, domain.id)
    except IntegrityError:
        await db.rollback()
        raise HTTPException(status_code=409, detail="A domain with this name already exists.")
    return {"ok": True}


@ad_router.post("/domains/test", dependencies=[Depends(require_admin)])
async def test_ad_domain(data: ADDomainCreate):
    temp_domain = ADDomain(
        name=data.name, host=data.host, port=data.port, use_ssl=data.use_ssl,
        base_dn=data.base_dn, bind_user=data.bind_user,
        bind_pass_encrypted=encryptor.encrypt(data.bind_pass),
    )
    is_ok, message = await ADManager(temp_domain).test_connection_async()
    if not is_ok:
        raise HTTPException(status_code=400, detail=message)
    return {"ok": True, "message": message}


@ad_router.post("/domains/delete", dependencies=[Depends(require_admin)])
async def delete_ad_domain(
    request: Request, data: ADDomainDelete, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    domain = await db.get(ADDomain, data.domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found.")
    
    await db.execute(delete(ADMembership).where(ADMembership.domain_name == domain.name))
    await db.execute(delete(ADManagedGroup).where(ADManagedGroup.domain_id == data.domain_id))
    await db.execute(delete(ADCachedUser).where(ADCachedUser.domain_id == data.domain_id))
    await db.execute(delete(ADCachedGroup).where(ADCachedGroup.domain_id == data.domain_id))
    await db.delete(domain)

    await log_audit_event(db, request, user.username, "AD_DOMAIN_DELETE", f"Name: {domain.name}")
    await db.commit()
    return {"ok": True}


@ad_router.post("/domains/refresh_cache", dependencies=[Depends(require_admin)])
async def refresh_ad_domain_cache(
    request: Request, data: ADDomainRefresh, background_tasks: BackgroundTasks,
    user: User = Depends(require_admin), db: AsyncSession = Depends(get_db),
):
    domain = await db.get(ADDomain, data.domain_id)
    if not domain:
        raise HTTPException(status_code=404, detail="Domain not found.")
    await log_audit_event(db, request, user.username, "AD_CACHE_REFRESH", f"For domain: {domain.name}")
    await db.commit()
    background_tasks.add_task(update_single_domain_cache, domain.id)
    return {"ok": True, "message": f"Cache refresh for domain '{domain.name}' initiated."}


@ad_router.get("/groups/search", dependencies=[Depends(require_admin)])
async def search_ad_groups(domain_id: int, q: str, db: AsyncSession = Depends(get_db)):
    query = (
        select(ADCachedGroup)
        .where(ADCachedGroup.domain_id == domain_id, ADCachedGroup.group_name.ilike(f"%{q}%"))
        .limit(20)
    )
    result = await db.execute(query)
    return {"ok": True, "results": [{"name": g.group_name, "dn": g.group_dn} for g in result.scalars().all()]}


@ad_router.get("/groups/managed", dependencies=[Depends(require_editor)])
async def get_managed_groups(domain_id: int = 0, db: AsyncSession = Depends(get_db)):
    query = select(ADManagedGroup)
    if domain_id > 0:
        query = query.where(ADManagedGroup.domain_id == domain_id)
    result = await db.execute(query)
    return [g.__dict__ for g in result.scalars().all()]


@ad_router.post("/groups/managed", dependencies=[Depends(require_admin)])
async def add_managed_group(
    request: Request, data: ADGroupCreate, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(ADManagedGroup.id).where(ADManagedGroup.group_dn == data.group_dn))
    if res.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="This group is already managed.")
    db.add(ADManagedGroup(**data.model_dump()))
    await log_audit_event(db, request, user.username, "AD_GROUP_ADD_MANAGED", f"Group: {data.group_name}")
    await db.commit()
    return {"ok": True}


@ad_router.post("/groups/managed/toggle_cleanup", dependencies=[Depends(require_admin)])
async def toggle_group_cleanup(
    request: Request, data: ADManagedGroupCleanupToggle, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    group = await db.get(ADManagedGroup, data.group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Managed group not found.")
    group.cleanup_enabled = data.enabled
    status = "enabled" if data.enabled else "disabled"
    await log_audit_event(
        db, request, user.username, "AD_GROUP_CLEANUP_TOGGLE", f"Group: {group.group_name}, Status: {status}"
    )
    await db.commit()
    return {"ok": True, "new_status": status}


@ad_router.post("/groups/managed/delete", dependencies=[Depends(require_admin)])
async def delete_managed_group(
    request: Request, data: ADManagedGroupDelete, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    group = await db.get(ADManagedGroup, data.group_id)
    if not group:
        raise HTTPException(status_code=404, detail="Managed group not found.")
    await log_audit_event(db, request, user.username, "AD_GROUP_REMOVE_MANAGED", f"Group: {group.group_name}")
    await db.delete(group)
    await db.commit()
    return {"ok": True}


@ad_router.get("/users/search", dependencies=[Depends(require_editor)])
async def search_ad_users(domain_id: int, q: str, db: AsyncSession = Depends(get_db)):
    query = (
        select(ADCachedUser)
        .where(
            ADCachedUser.domain_id == domain_id,
            (ADCachedUser.display_name.ilike(f"%{q}%"))
            | (ADCachedUser.user_principal_name.ilike(f"%{q}%")),
        )
        .limit(20)
    )
    result = await db.execute(query)
    return {
        "ok": True,
        "results": [
            {"id": u.id, "displayName": u.display_name, "dn": u.user_dn, "upn": u.user_principal_name}
            for u in result.scalars().all()
        ],
    }


@ad_router.get("/memberships", dependencies=[Depends(require_editor)])
async def list_memberships(
    page: int = 1, limit: int = 50, search: str = "", sort_by: str = "granted_at",
    sort_order: str = "desc", db: AsyncSession = Depends(get_db),
):
    query = select(ADMembership).join(ADMembership.user)
    if search:
        term = f"%{search}%"
        query = query.where(
            ADCachedUser.display_name.ilike(term)
            | ADMembership.group_dn.ilike(term)
            | ADCachedUser.user_principal_name.ilike(term)
        )
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    paginated_query = apply_sorting_and_pagination(
        query, ADMembership, sort_by, sort_order, page, limit
    ).options(selectinload(ADMembership.user))
    grants = (await db.execute(paginated_query)).scalars().unique().all()
    result = [
        {
            "id": g.id, "user": g.user.display_name, "user_principal_name": g.user.user_principal_name,
            "group": g.group_dn, "domain": g.domain_name, "granted_by": g.granted_by,
            "approved_by": g.approved_by, "sync_status": g.sync_status, "sync_message": g.sync_message,
            "granted_at": to_msk(g.granted_at).strftime("%d.%m.%Y %H:%M"),
            "expires_at": to_msk(g.expires_at).strftime("%d.%m.%Y %H:%M") if g.expires_at else "Permanent",
        }
        for g in grants if g.user
    ]
    return {"grants": result, "page": page, "total_pages": (total + limit - 1) // limit}


@ad_router.post("/memberships", dependencies=[Depends(require_editor)])
async def create_membership(
    request: Request, data: ADMembershipCreate, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db),
):
    domain = await db.get(ADDomain, data.domain_id)
    cached_user = await db.get(ADCachedUser, data.user_cache_id)
    if not domain or not cached_user or cached_user.domain_id != data.domain_id:
        raise HTTPException(status_code=404, detail="Domain or User not found.")

    res = await db.execute(select(ADMembership.id).where(
        ADMembership.user_cache_id == data.user_cache_id, ADMembership.group_dn == data.group_dn
    ))
    if res.scalar_one_or_none():
        raise HTTPException(status_code=409, detail="This user already has a grant for this group.")

    new_grant = ADMembership(
        user_cache_id=data.user_cache_id, group_dn=data.group_dn, domain_name=domain.name,
        granted_by=user.username, approved_by=data.approved_by, expires_at=data.expires_at,
        sync_status=ADMembershipStatus.PENDING_ADD
    )
    db.add(new_grant)
    await log_audit_event(
        db, request, user.username, "AD_MEMBERSHIP_GRANT_QUEUED",
        f"User: {cached_user.display_name}, Group: {data.group_dn}",
    )
    await db.commit()
    return {"ok": True, "message": "Access grant has been queued for processing."}


@ad_router.post("/memberships/delete", dependencies=[Depends(require_editor)])
async def delete_membership(
    request: Request, data: ADMembershipDelete, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db),
):
    grant_res = await db.execute(
        select(ADMembership).where(ADMembership.id == data.grant_id).options(selectinload(ADMembership.user))
    )
    grant = grant_res.scalar_one_or_none()
    if not grant:
        raise HTTPException(status_code=404, detail="Membership grant not found.")
    
    grant.sync_status = ADMembershipStatus.PENDING_REMOVE
    grant.retry_count = 0
    grant.expires_at = datetime.now(timezone.utc)
    
    user_display_name = grant.user.display_name if grant.user else f"CachedUserID: {grant.user_cache_id}"
    await log_audit_event(
        db, request, user.username, "AD_MEMBERSHIP_REVOKE_QUEUED",
        f"User: {user_display_name}, Group: {grant.group_dn}",
    )
    await db.commit()
    return {"ok": True, "message": "Access revocation has been queued for processing."}


@ad_router.post("/memberships/retry", dependencies=[Depends(require_admin)])
async def retry_membership_sync(
    request: Request, data: ADMembershipRetry, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    grant = await db.get(ADMembership, data.grant_id)
    if not grant:
        raise HTTPException(status_code=404, detail="Membership grant not found.")

    if grant.sync_status != ADMembershipStatus.ERROR:
        raise HTTPException(status_code=400, detail="Can only retry grants in ERROR state.")

    grant.retry_count = 0
    grant.sync_status = (
        ADMembershipStatus.PENDING_REMOVE
        if grant.expires_at and grant.expires_at <= datetime.now(timezone.utc)
        else ADMembershipStatus.PENDING_ADD
    )
    grant.sync_message = f"Retried manually by {user.username}"

    await log_audit_event(
        db, request, user.username, "AD_MEMBERSHIP_RETRY", f"Retrying grant ID: {grant.id}"
    )
    await db.commit()
    return {"ok": True, "message": "Grant has been re-queued for synchronization."}


@bans_router.post("")
async def add_ban(
    request: Request, data: BanCreate, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    try:
        ip_address(data.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if await is_ip_in_exceptions(data.ip, redis):
        raise HTTPException(status_code=400, detail="IP address is in the exceptions list")
    
    await upsert_ban(db, data.ip, data.reason or "", user.username)
    await log_audit_event(db, request, user.username, "ADD_BAN", f"IP: {data.ip}, Reason: {data.reason}")
    await db.commit()
    banlist_modified.set()
    asyncio.create_task(trigger_webhooks(
        "ban.added", {"ip": data.ip, "reason": data.reason, "source": user.username}
    ))
    return {"ok": True}


@bans_router.post("/update")
async def update_ban(
    request: Request, data: BanUpdate, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    try:
        ip_address(data.ip)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    if await is_ip_in_exceptions(data.ip, redis):
        raise HTTPException(status_code=400, detail="IP address is in the exceptions list")

    ban = await db.get(Ban, data.ban_id)
    if not ban:
        raise HTTPException(status_code=404, detail="Ban not found")

    old_ip = ban.ip
    ban.ip, ban.ip_int = data.ip, ip_to_int(data.ip)
    ban.reason, ban.banned_by = data.reason, user.username
    ban.timestamp = datetime.now(timezone.utc)

    await log_audit_event(db, request, user.username, "UPDATE_BAN", f"ID: {data.ban_id}, From: {old_ip}, To: {data.ip}")
    await db.commit()
    banlist_modified.set()
    asyncio.create_task(trigger_webhooks("ban.updated", {
        "ban_id": data.ban_id, "old_ip": old_ip, "new_ip": data.ip,
        "reason": data.reason, "source": user.username,
    }))
    return {"ok": True}


@bans_router.post("/delete")
async def api_delete_ban(
    request: Request, data: BanDelete, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db),
):
    ban = await delete_ban(db, data.ban_id)
    if not ban:
        raise HTTPException(status_code=404, detail="Ban not found")
    
    await log_audit_event(db, request, user.username, "DELETE_BAN", f"IP: {ban.ip}")
    await db.commit()
    banlist_modified.set()
    asyncio.create_task(trigger_webhooks("ban.deleted", {"ip": ban.ip, "source": user.username}))
    return {"ok": True}


@bans_router.post("/bulk")
async def add_bulk_bans(
    request: Request, file: UploadFile = File(...), reason: str = Form(""),
    user: User = Depends(require_editor), db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    content = await file.read()
    ips = {line.strip() for line in content.decode("utf-8", "ignore").splitlines() if line.strip()}
    
    added_count = 0
    for ip in ips:
        try:
            ip_address(ip)
            if not await is_ip_in_exceptions(ip, redis):
                await upsert_ban(db, ip, reason, user.username)
                added_count += 1
        except ValueError:
            continue
    
    if added_count > 0:
        await log_audit_event(
            db, request, user.username, "BULK_ADD_BANS", f"Added {added_count} IPs from {file.filename}"
        )
        await db.commit()
        banlist_modified.set()
    return {"ok": True, "added": added_count}


@bans_router.get("/list")
async def list_bans(
    page: int = 1, limit: int = 50, search: str = "", sort_by: str = "timestamp",
    sort_order: str = "desc", db: AsyncSession = Depends(get_db), user: User = Depends(require_viewer),
):
    query = select(Ban)
    if search:
        query = query.where(Ban.ip.contains(search) | Ban.reason.contains(search))
    
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    paginated_query = apply_sorting_and_pagination(query, Ban, sort_by, sort_order, page, limit)
    bans = (await db.execute(paginated_query)).scalars().all()
    
    result = [{
        "id": b.id, "ip": b.ip, "reason": b.reason, "banned_by": b.banned_by,
        "timestamp_msk": to_msk(b.timestamp).strftime("%d.%m.%Y %H:%M:%S"),
        "timestamp_iso": b.timestamp.isoformat(),
    } for b in bans]
    return {"bans": result, "page": page, "total_pages": (total + limit - 1) // limit}


@bans_router.get("/export/{file_format}")
async def export_bans(
    file_format: str, db: AsyncSession = Depends(get_db), user: User = Depends(require_viewer),
):
    result = await db.execute(select(Ban.ip).order_by(Ban.ip_int))
    ips = [ip for (ip,) in result.all()]
    now = datetime.now().strftime("%Y%m%d-%H%M%S")

    if file_format == "nginx":
        content = "\n".join(f"deny {ip};" for ip in ips)
        filename, media_type = f"nginx_deny_{now}.conf", "text/plain"
    elif file_format == "iptables":
        content = "\n".join(f"-A INPUT -s {ip} -j DROP" for ip in ips)
        filename, media_type = f"iptables_rules_{now}.sh", "application/x-sh"
    elif file_format == "json":
        content = json.dumps(ips, indent=2)
        filename, media_type = f"banlist_{now}.json", "application/json"
    else:
        raise HTTPException(status_code=400, detail="Unsupported format")
    
    return Response(content=content, media_type=media_type, headers={"Content-Disposition": f'attachment; filename="{filename}"'})


@exceptions_router.post("")
async def add_exception(
    request: Request, data: ExceptionCreate, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    try:
        deleted_count = await upsert_exception(db, data.ip, data.reason or "", user.username, redis)
        await log_audit_event(
            db, request, user.username, "ADD_EXCEPTION", f"Network: {data.ip}, Reason: {data.reason}"
        )
        await db.commit()
        if deleted_count > 0:
            banlist_modified.set()
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP or CIDR format")
    return {"ok": True}


@exceptions_router.post("/update")
async def update_exception(
    request: Request, data: ExceptionUpdate, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    exc = await db.get(ExceptionIP, data.exc_id)
    if not exc:
        raise HTTPException(status_code=404, detail="Exception not found")
    try:
        old_ip = exc.ip
        network = ip_network(data.ip, strict=False)
        exc.ip, exc.ip_int = str(network), int(network.network_address)
        exc.reason, exc.added_by = data.reason, user.username
        exc.timestamp = datetime.now(timezone.utc)
        
        stmt = delete(Ban).where(Ban.ip_int >= exc.ip_int, Ban.ip_int <= int(network.broadcast_address))
        deleted_count = (await db.execute(stmt)).rowcount

        await log_audit_event(db, request, user.username, "UPDATE_EXCEPTION", f"ID: {data.exc_id}, From: {old_ip}, To: {data.ip}")
        await db.commit()
        if deleted_count > 0:
            banlist_modified.set()
        await redis.delete("exception_networks")
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP or CIDR format")
    return {"ok": True}


@exceptions_router.post("/delete")
async def api_delete_exception(
    request: Request, data: ExceptionDelete, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    if not await delete_exception(db, data.exc_id, redis):
        raise HTTPException(status_code=404, detail="Exception not found")
    await log_audit_event(db, request, user.username, "DELETE_EXCEPTION", f"ID: {data.exc_id}")
    await db.commit()
    return {"ok": True}


@exceptions_router.post("/bulk")
async def add_bulk_exceptions(
    request: Request, file: UploadFile = File(...), reason: str = Form(""),
    user: User = Depends(require_editor), db: AsyncSession = Depends(get_db),
    redis: aioredis.Redis = Depends(get_redis),
):
    content = await file.read()
    lines = {line.strip() for line in content.decode("utf-8", "ignore").splitlines() if line.strip()}
    total_deleted = 0
    for line in lines:
        try:
            total_deleted += await upsert_exception(db, line, reason, user.username, redis)
        except ValueError:
            continue
    
    await log_audit_event(
        db, request, user.username, "BULK_ADD_EXCEPTIONS", f"Added {len(lines)} networks from {file.filename}"
    )
    await db.commit()
    if total_deleted > 0:
        banlist_modified.set()
    return {"ok": True, "added": len(lines)}


@exceptions_router.get("/list")
async def list_exceptions(
    page: int = 1, limit: int = 50, search: str = "", sort_by: str = "timestamp",
    sort_order: str = "desc", db: AsyncSession = Depends(get_db), user: User = Depends(require_viewer),
):
    query = select(ExceptionIP)
    if search:
        query = query.where(ExceptionIP.ip.contains(search) | ExceptionIP.reason.contains(search))
    
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    paginated_query = apply_sorting_and_pagination(query, ExceptionIP, sort_by, sort_order, page, limit)
    exceptions = (await db.execute(paginated_query)).scalars().all()
    
    result = [{
        "id": e.id, "ip": e.ip, "reason": e.reason, "added_by": e.added_by,
        "timestamp_msk": to_msk(e.timestamp).strftime("%d.%m.%Y %H:%M:%S"),
        "timestamp_iso": e.timestamp.isoformat(),
    } for e in exceptions]
    return {"exceptions": result, "page": page, "total_pages": (total + limit - 1) // limit}


@users_router.post("")
async def create_user(
    request: Request, data: UserCreate, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(User.id).where(User.username == data.username))
    if res.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="User with this username already exists")
    
    new_user = User(
        username=data.username, 
        password=bcrypt.hash(data.password), 
        role=data.role,
        audit_settings=UserAuditSettings()
    )
    db.add(new_user)
    await log_audit_event(
        db, request, user.username, "CREATE_USER", f"Username: {data.username}, Role: {data.role.value}"
    )
    await db.commit()
    return {"ok": True}


@users_router.get("/list")
async def list_users(
    page: int = 1, limit: int = 50, search: str = "", sort_by: str = "username",
    sort_order: str = "desc", db: AsyncSession = Depends(get_db), user: User = Depends(require_admin),
):
    query = select(User)
    if search:
        query = query.where(User.username.contains(search))
    
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    
    sort_col = User.role if sort_by == "role" else User.username
    query = query.order_by(sort_col.asc() if sort_order.lower() == "asc" else sort_col.desc())
    
    users = (await db.execute(query.offset((page - 1) * limit).limit(limit))).scalars().all()
    result = [{"id": u.id, "username": u.username, "role": u.role} for u in users]
    return {"users": result, "page": page, "total_pages": (total + limit - 1) // limit}


@users_router.post("/update_password")
async def update_user_password(
    request: Request, data: UserUpdate, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    target_user = await db.get(User, data.user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    
    target_user.password = bcrypt.hash(data.password)
    await log_audit_event(
        db, request, user.username, "UPDATE_USER_PASSWORD", f"Username: {target_user.username}"
    )
    await db.commit()
    return {"ok": True}


@users_router.post("/update_role")
async def update_user_role(
    request: Request, data: UserRoleUpdate, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    target_user = await db.get(User, data.user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    if target_user.id == user.id and data.role != UserRole.ADMIN:
        raise HTTPException(status_code=400, detail="You cannot demote yourself")
    
    old_role = target_user.role
    target_user.role = data.role
    await log_audit_event(
        db, request, user.username, "UPDATE_USER_ROLE", f"Username: {target_user.username}, From: {old_role}, To: {data.role.value}"
    )
    await db.commit()
    return {"ok": True}


@users_router.post("/delete")
async def delete_user(
    request: Request, data: UserDelete, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    target_user = await db.get(User, data.user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
    if target_user.id == user.id:
        raise HTTPException(status_code=400, detail="You cannot delete yourself")
    
    await log_audit_event(db, request, user.username, "DELETE_USER", f"Username: {target_user.username}")
    await db.delete(target_user)
    await db.commit()
    return {"ok": True}

@users_router.get("/{user_id}/audit_settings", dependencies=[Depends(require_admin)], response_model=AuditSettingsUpdate)
async def get_audit_settings(user_id: int = FastApiPath(...), db: AsyncSession = Depends(get_db)):
    settings = await db.scalar(
        select(UserAuditSettings).where(UserAuditSettings.user_id == user_id)
    )
    if not settings:
        user = await db.get(User, user_id)
        if not user:
            raise HTTPException(status_code=404, detail="User not found")
        settings = UserAuditSettings(user_id=user_id)
        db.add(settings)
        await db.commit()
        await db.refresh(settings)
    return settings

@users_router.post("/{user_id}/audit_settings", dependencies=[Depends(require_admin)])
async def update_audit_settings(
    request: Request, data: AuditSettingsUpdate, user_id: int = FastApiPath(...),
    current_user: User = Depends(require_admin), db: AsyncSession = Depends(get_db),
):
    target_user = await db.get(User, user_id)
    if not target_user:
        raise HTTPException(status_code=404, detail="User not found")
        
    settings = await db.scalar(
        select(UserAuditSettings).where(UserAuditSettings.user_id == user_id)
    )
    if not settings:
        settings = UserAuditSettings(user_id=user_id)
        db.add(settings)

    for key, value in data.model_dump().items():
        setattr(settings, key, value)
        
    await log_audit_event(
        db, request, current_user.username, "UPDATE_AUDIT_SETTINGS", f"For user: {target_user.username}"
    )
    await db.commit()
    return {"ok": True, "message": "Audit settings updated."}


@token_router.post("")
async def create_api_token(
    request: Request, user: User = Depends(require_editor), db: AsyncSession = Depends(get_db),
):
    if not user.api_token:
        user.api_token = generate_api_token()
        await log_audit_event(db, request, user.username, "CREATE_API_TOKEN", "")
        await db.commit()
    return {"api_token": user.api_token}


@token_router.post("/bans")
async def api_add_bans_with_token(
    request: Request, data: BanRequest, user: User = Depends(get_user_by_token),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    results, added_count = [], 0
    for ip in data.ips:
        try:
            ip_address(ip)
            if await is_ip_in_exceptions(ip, redis):
                results.append({"ip": ip, "status": "in_exceptions"})
            else:
                status, _ = await upsert_ban(db, ip, data.reason or "", user.username)
                results.append({"ip": ip, "status": status})
                added_count += 1
        except ValueError:
            results.append({"ip": ip, "status": "invalid"})
    
    if added_count > 0:
        await log_audit_event(db, request, user.username, "API_BULK_ADD_BANS", f"Added {added_count} IPs")
        await db.commit()
        banlist_modified.set()
    return {"ok": True, "results": results}


@token_router.post("/check")
async def api_check_token_single(
    request: Request, request_data: CheckRequestSingle, user: User = Depends(get_user_by_token),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    return await _api_check_logic(request_data, request, user, db, redis)


@token_router.post("/playbooks", status_code=201)
async def api_create_playbook(
    request: Request, data: PlaybookCreate, user: User = Depends(get_user_by_token),
    db: AsyncSession = Depends(get_db),
):
    new_playbook = Playbook(name=data.name, content=data.content, created_by=user.username)
    db.add(new_playbook)
    await log_audit_event(db, request, user.username, "API_CREATE_PLAYBOOK", f"Name: {data.name}")
    await db.commit()
    await db.refresh(new_playbook)
    return {"ok": True, "playbook_id": new_playbook.id}


@check_router.post("")
async def api_check_single(
    request: Request, request_data: CheckRequestSingle, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    return await _api_check_logic(request_data, request, user, db, redis)


@check_router.post("/file")
async def api_check_file_single(
    request: Request, file: UploadFile = File(...), provider: str = Form(...),
    threshold_percent: float = Form(50.0), ban: bool = Form(False),
    reason: Optional[str] = Form(None), user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    content = await file.read()
    ips = [line.strip() for line in content.decode("utf-8", "ignore").splitlines() if line.strip()]
    payload = CheckRequestSingle(
        ips=ips, provider=provider, threshold_percent=threshold_percent, ban=ban, reason=reason
    )
    return await _api_check_logic(payload, request, user, db, redis)


@check_router.post("/confirm")
async def api_check_confirm(
    request: Request, data: ConfirmRequest, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db), redis: aioredis.Redis = Depends(get_redis),
):
    results, changes_made = [], False
    for ip in data.ips:
        try:
            ip_address(ip)
            if data.ban:
                if await is_ip_in_exceptions(ip, redis):
                    results.append({"ip": ip, "status": "in_exceptions"})
                else:
                    status, _ = await upsert_ban(db, ip, data.reason, user.username)
                    results.append({"ip": ip, "status": status})
                    changes_made = True
            else:
                results.append({"ip": ip, "status": "no_action"})
        except ValueError:
            results.append({"ip": ip, "status": "invalid"})
    
    if changes_made:
        await log_audit_event(
            db, request, user.username, "CONFIRM_BANS_FROM_CHECK", f"Banned {len(data.ips)} IPs"
        )
        await db.commit()
        banlist_modified.set()
    return {"ok": True, "results": results}


@stats_router.get("")
async def get_summary_stats(
    period: str = Query("day", enum=["day", "week", "month"]), db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    start_date, _, _, _ = _get_period_params(period)
    
    ban_actions = ["ADD_BAN", "AUTO_BAN_ADD", "API_BULK_ADD_BANS", "CONFIRM_BANS_FROM_CHECK", "BULK_ADD_BANS"]
    exc_actions = ["ADD_EXCEPTION", "BULK_ADD_EXCEPTIONS"]

    total_bans_q = select(func.count()).select_from(Ban)
    bans_period_q = select(func.count()).select_from(AuditLog).where(AuditLog.action.in_(ban_actions), AuditLog.timestamp >= start_date)
    exc_period_q = select(func.count()).select_from(AuditLog).where(AuditLog.action.in_(exc_actions), AuditLog.timestamp >= start_date)
    grants_period_q = select(func.count()).select_from(AuditLog).where(AuditLog.action.like('AD_MEMBERSHIP_GRANT%'), AuditLog.timestamp >= start_date)

    total, bans, exc, grants = await asyncio.gather(
        db.execute(total_bans_q), db.execute(bans_period_q),
        db.execute(exc_period_q), db.execute(grants_period_q)
    )
    return {
        "ok": True,
        "stats": {
            "total_active_bans": total.scalar_one(), "bans_in_period": bans.scalar_one(),
            "exceptions_in_period": exc.scalar_one(), "grants_in_period": grants.scalar_one(),
        },
    }


@stats_router.get("/chart")
async def get_chart_data(
    period: str = Query("day", enum=["day", "week", "month"]), db: AsyncSession = Depends(get_db),
    user: User = Depends(require_viewer),
):
    start_date, trunc_unit, label_format, step = _get_period_params(period)
    now = datetime.now(timezone.utc)

    query = (
        select(func.date_trunc(trunc_unit, Ban.timestamp).label("p"), func.count(Ban.id).label("c"))
        .where(Ban.timestamp >= start_date)
        .group_by("p")
    )
    result = await db.execute(query)
    data_map = {row.p: row.c for row in result.all()}

    labels, data = [], []
    
    current_date = _truncate_datetime(start_date, trunc_unit)

    while current_date <= now:
        labels.append(to_msk(current_date).strftime(label_format))
        data.append(data_map.get(current_date, 0))
        current_date += step

    return {"ok": True, "labels": labels, "data": data}


@webhooks_router.get("/list", dependencies=[Depends(require_admin)])
async def list_webhooks(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Webhook).order_by(Webhook.timestamp.desc()))
    return [{
        "id": h.id, "url": h.url, "created_by": h.created_by,
        "timestamp_msk": to_msk(h.timestamp).strftime("%d.%m.%Y %H:%M:%S"),
    } for h in result.scalars().all()]


@webhooks_router.post("", dependencies=[Depends(require_admin)])
async def create_webhook(
    request: Request, data: WebhookCreate, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    res = await db.execute(select(Webhook.id).where(Webhook.url == str(data.url)))
    if res.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Webhook URL already exists")
    
    db.add(Webhook(url=str(data.url), created_by=user.username))
    await log_audit_event(db, request, user.username, "CREATE_WEBHOOK", f"URL: {data.url}")
    await db.commit()
    return {"ok": True}


@webhooks_router.post("/delete", dependencies=[Depends(require_admin)])
async def delete_webhook(
    request: Request, data: WebhookDelete, user: User = Depends(require_admin),
    db: AsyncSession = Depends(get_db),
):
    hook = await db.get(Webhook, data.webhook_id)
    if not hook:
        raise HTTPException(status_code=404, detail="Webhook not found")
    
    await log_audit_event(db, request, user.username, "DELETE_WEBHOOK", f"URL: {hook.url}")
    await db.delete(hook)
    await db.commit()
    return {"ok": True}


@audit_router.get("/list", dependencies=[Depends(require_admin)])
async def list_audit_logs(
    page: int = 1, limit: int = 50, search: str = "", sort_by: str = "timestamp",
    sort_order: str = "desc", db: AsyncSession = Depends(get_db),
):
    query = select(AuditLog)
    if search:
        query = query.where(
            AuditLog.username.contains(search) | AuditLog.action.contains(search) |
            AuditLog.details.contains(search) | AuditLog.ip_address.contains(search)
        )
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    paginated_query = apply_sorting_and_pagination(query, AuditLog, sort_by, sort_order, page, limit)
    logs = (await db.execute(paginated_query)).scalars().all()
    result = [{
        "id": log.id, "username": log.username, "action": log.action, "details": log.details,
        "ip_address": log.ip_address, "timestamp_msk": to_msk(log.timestamp).strftime("%d.%m.%Y %H:%M:%S"),
    } for log in logs]
    return {"logs": result, "page": page, "total_pages": (total + limit - 1) // limit}


@playbooks_router.get("/list", dependencies=[Depends(require_editor)])
async def list_playbooks(
    page: int = 1, limit: int = 50, search: str = "", sort_by: str = "timestamp",
    sort_order: str = "desc", db: AsyncSession = Depends(get_db),
):
    query = select(Playbook)
    if search:
        query = query.where(
            Playbook.name.contains(search) | Playbook.content.contains(search) |
            Playbook.created_by.contains(search)
        )
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    paginated_query = apply_sorting_and_pagination(query, Playbook, sort_by, sort_order, page, limit)
    playbooks = (await db.execute(paginated_query)).scalars().all()
    result = [{
        "id": p.id, "name": p.name, "content": p.content, "created_by": p.created_by,
        "timestamp_msk": to_msk(p.timestamp).strftime("%d.%m.%Y %H:%M:%S"),
    } for p in playbooks]
    return {"playbooks": result, "page": page, "total_pages": (total + limit - 1) // limit}


@playbooks_router.post("", dependencies=[Depends(require_editor)])
async def create_playbook(
    request: Request, data: PlaybookCreate, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db),
):
    db.add(Playbook(name=data.name, content=data.content, created_by=user.username))
    await log_audit_event(db, request, user.username, "CREATE_PLAYBOOK", f"Name: {data.name}")
    await db.commit()
    return {"ok": True}


@playbooks_router.post("/update", dependencies=[Depends(require_editor)])
async def update_playbook(
    request: Request, data: PlaybookUpdate, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db),
):
    playbook = await db.get(Playbook, data.playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    playbook.name, playbook.content = data.name, data.content
    await log_audit_event(
        db, request, user.username, "UPDATE_PLAYBOOK", f"ID: {data.playbook_id}, Name: {data.name}"
    )
    await db.commit()
    return {"ok": True}


@playbooks_router.post("/delete", dependencies=[Depends(require_editor)])
async def delete_playbook(
    request: Request, data: PlaybookDelete, user: User = Depends(require_editor),
    db: AsyncSession = Depends(get_db),
):
    playbook = await db.get(Playbook, data.playbook_id)
    if not playbook:
        raise HTTPException(status_code=404, detail="Playbook not found")
    await log_audit_event(
        db, request, user.username, "DELETE_PLAYBOOK", f"ID: {playbook.id}, Name: {playbook.name}"
    )
    await db.delete(playbook)
    await db.commit()
    return {"ok": True}


@notes_router.get("/list", dependencies=[Depends(require_viewer)])
async def list_notes(
    page: int = 1, limit: int = 50, search: str = "", sort_by: str = "timestamp",
    sort_order: str = "desc", db: AsyncSession = Depends(get_db), user: User = Depends(require_viewer),
):
    query = select(Note).where(Note.user_id == user.id)
    if search:
        query = query.where(
            Note.title.ilike(f"%{search}%") | Note.content.ilike(f"%{search}%")
        )
    
    total = (await db.execute(select(func.count()).select_from(query.subquery()))).scalar_one()
    paginated_query = apply_sorting_and_pagination(query, Note, sort_by, sort_order, page, limit)
    notes = (await db.execute(paginated_query)).scalars().all()
    
    result = [{
        "id": n.id, "title": n.title, "content": n.content, "is_pinned": n.is_pinned,
        "timestamp_msk": to_msk(n.timestamp).strftime("%d.%m.%Y %H:%M:%S"),
    } for n in notes]
    return {"notes": result, "page": page, "total_pages": (total + limit - 1) // limit}

@notes_router.post("", dependencies=[Depends(require_viewer)])
async def create_note(
    data: NoteCreate, user: User = Depends(require_viewer), db: AsyncSession = Depends(get_db),
):
    new_note = Note(title=data.title, content=data.content, user_id=user.id)
    db.add(new_note)
    await db.commit()
    return {"ok": True}

@notes_router.post("/update", dependencies=[Depends(require_viewer)])
async def update_note(
    data: NoteUpdate, user: User = Depends(require_viewer), db: AsyncSession = Depends(get_db),
):
    stmt = select(Note).where(Note.id == data.note_id, Note.user_id == user.id)
    note = (await db.execute(stmt)).scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found or you don't have permission")
    
    note.title = data.title
    note.content = data.content
    await db.commit()
    return {"ok": True}

@notes_router.post("/delete", dependencies=[Depends(require_viewer)])
async def delete_note(
    data: NoteDelete, user: User = Depends(require_viewer), db: AsyncSession = Depends(get_db),
):
    stmt = select(Note).where(Note.id == data.note_id, Note.user_id == user.id)
    note = (await db.execute(stmt)).scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found or you don't have permission")
    
    await db.delete(note)
    await db.commit()
    return {"ok": True}

@notes_router.post("/toggle_pin", dependencies=[Depends(require_viewer)])
async def toggle_pin_note(
    data: NotePinToggle, user: User = Depends(require_viewer), db: AsyncSession = Depends(get_db),
):
    stmt = select(Note).where(Note.id == data.note_id, Note.user_id == user.id)
    note = (await db.execute(stmt)).scalar_one_or_none()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found or you don't have permission")
    
    note.is_pinned = not note.is_pinned
    await db.commit()
    return {"ok": True, "is_pinned": note.is_pinned}


# =====================================================================================
# 11. APP SETUP & FRONTEND ROUTES
# =====================================================================================

settings.FILES_DIR.mkdir(exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")
app.mount(f"/{settings.FILES_DIR}", StaticFiles(directory=settings.FILES_DIR, html=False), name=str(settings.FILES_DIR))

api_router.include_router(bans_router)
api_router.include_router(exceptions_router)
api_router.include_router(users_router)
api_router.include_router(token_router)
api_router.include_router(check_router)
api_router.include_router(stats_router)
api_router.include_router(webhooks_router)
api_router.include_router(audit_router)
api_router.include_router(playbooks_router)
api_router.include_router(notes_router)
api_router.include_router(ad_router)
app.include_router(api_router, prefix="/api")


@app.on_event("startup")
async def startup_event():
    await create_db_tables()
    await create_default_admin()
    asyncio.create_task(cleanup_task())
    asyncio.create_task(periodic_banlist_update_task())
    asyncio.create_task(audit_cleanup_task())
    asyncio.create_task(expired_membership_cleanup_task())
    asyncio.create_task(update_ad_cache_task())
    asyncio.create_task(group_cleanup_task())
    asyncio.create_task(membership_sync_task())
    if not settings.BANLIST_FILE_PATH.exists():
        logging.info("banlist.txt not found. Triggering initial file generation.")
        banlist_modified.set()


@app.on_event("shutdown")
async def shutdown_event():
    await redis_pool.close()


@app.exception_handler(StarletteHTTPException)
async def http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 401:
        response = RedirectResponse(url="/login")
        if request.cookies.get("user"):
            response.delete_cookie("user")
        return response
    
    if request.url.path.startswith("/api/"):
        return JSONResponse(status_code=exc.status_code, content={"detail": exc.detail})
    
    return templates.TemplateResponse(
        "error.html", {"request": request, "status_code": exc.status_code, "detail": exc.detail}
    )


async def _render_page(request: Request, user: User, template_name: str, context: dict = None):
    page_context = {"request": request, "user": user, **(context or {})}
    if request.headers.get("x-requested-with") == "fetch":
        return templates.TemplateResponse(f"partials/{template_name}.html", page_context)
    
    page_context["page"] = template_name
    return templates.TemplateResponse("index.html", page_context)


@app.get("/", response_class=HTMLResponse, include_in_schema=False)
async def root(user: Optional[User] = Depends(get_current_user_optional)):
    return RedirectResponse("/login" if not user else "/bans")


@app.get("/login", response_class=HTMLResponse, include_in_schema=False)
async def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request})


@app.post("/login", include_in_schema=False)
async def login(
    request: Request, username: str = Form(...), password: str = Form(...),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.username == username))
    user = result.scalar_one_or_none()
    
    if not user or not bcrypt.verify(password, user.password):
        await log_audit_event(db, request, username, "LOGIN_FAILURE", "Invalid credentials")
        await db.commit()
        return templates.TemplateResponse(
            "login.html", {"request": request, "error": "Invalid username or password"}, status_code=400
        )
    
    session_expire = timedelta(hours=settings.SESSION_EXPIRE_HOURS)
    session_token = secrets.token_urlsafe(32)
    user.session_token, user.session_expiry = session_token, datetime.now(timezone.utc) + session_expire
    await log_audit_event(db, request, username, "LOGIN_SUCCESS", "")
    await db.commit()
    
    response = RedirectResponse(url="/bans", status_code=303)
    response.set_cookie(
        key="user", value=session_token, httponly=True, secure=settings.HTTPS_ENABLED,
        samesite="Lax", max_age=int(session_expire.total_seconds())
    )
    return response


@app.get("/logout", include_in_schema=False)
async def logout(
    request: Request, user: User = Depends(get_current_user), db: AsyncSession = Depends(get_db)
):
    await log_audit_event(db, request, user.username, "LOGOUT", "")
    await db.commit()
    response = RedirectResponse(url="/login", status_code=303)
    response.delete_cookie("user")
    return response


@app.get("/bans", response_class=HTMLResponse, include_in_schema=False)
async def bans_page(request: Request, user: User = Depends(require_viewer)):
    return await _render_page(request, user, "bans")


@app.get("/exceptions", response_class=HTMLResponse, include_in_schema=False)
async def exceptions_page(request: Request, user: User = Depends(require_viewer)):
    return await _render_page(request, user, "exceptions")


@app.get("/users", response_class=HTMLResponse, include_in_schema=False)
async def users_page(request: Request, user: User = Depends(require_admin)):
    return await _render_page(request, user, "users")


@app.get("/stats", response_class=HTMLResponse, include_in_schema=False)
async def stats_page(request: Request, user: User = Depends(require_viewer)):
    return await _render_page(request, user, "stats")


@app.get("/check", response_class=HTMLResponse, include_in_schema=False)
async def check_page(request: Request, user: User = Depends(require_editor)):
    providers = {
        "abuseipdb": bool(settings.ABUSEIPDB_KEYS),
        "virustotal": bool(settings.VIRUSTOTAL_KEYS),
        "otx": bool(settings.OTX_KEYS),
    }
    return await _render_page(request, user, "check", context={"providers": providers})


@app.get("/webhooks", response_class=HTMLResponse, include_in_schema=False)
async def webhooks_page(request: Request, user: User = Depends(require_admin)):
    return await _render_page(request, user, "webhooks")


@app.get("/audit", response_class=HTMLResponse, include_in_schema=False)
async def audit_page(request: Request, user: User = Depends(require_admin)):
    return await _render_page(request, user, "audit")


@app.get("/playbooks", response_class=HTMLResponse, include_in_schema=False)
async def playbooks_page(request: Request, user: User = Depends(require_editor)):
    return await _render_page(request, user, "playbooks")


@app.get("/notes", response_class=HTMLResponse, include_in_schema=False)
async def notes_page(request: Request, user: User = Depends(require_viewer)):
    return await _render_page(request, user, "notes")


@app.get("/ad_access", response_class=HTMLResponse, include_in_schema=False)
async def ad_access_page(request: Request, user: User = Depends(require_editor)):
    return await _render_page(request, user, "ad_access")


@app.get("/ad_settings", response_class=HTMLResponse, include_in_schema=False)
async def ad_settings_page(request: Request, user: User = Depends(require_admin)):
    return await _render_page(request, user, "ad_settings")