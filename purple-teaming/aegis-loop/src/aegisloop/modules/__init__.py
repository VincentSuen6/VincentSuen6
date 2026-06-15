from .broken_auth import PathTraversalModule
from .cmdi import CommandInjectionModule
from .credential_stuffing import CredentialStuffingModule
from .idor import IDORModule
from .injection import SQLInjectionModule
from .open_redirect import OpenRedirectModule
from .sec_headers import SecurityHeadersModule
from .ssrf import SSRFModule
from .xss import ReflectedXSSModule
from .xxe import XXEModule

ALL_MODULES = [
    SQLInjectionModule,
    ReflectedXSSModule,
    PathTraversalModule,
    IDORModule,
    CommandInjectionModule,
    SSRFModule,
    XXEModule,
    OpenRedirectModule,
    CredentialStuffingModule,
    SecurityHeadersModule,
]

__all__ = [
    "ALL_MODULES",
    "CommandInjectionModule",
    "CredentialStuffingModule",
    "IDORModule",
    "OpenRedirectModule",
    "PathTraversalModule",
    "ReflectedXSSModule",
    "SQLInjectionModule",
    "SSRFModule",
    "SecurityHeadersModule",
    "XXEModule",
]
