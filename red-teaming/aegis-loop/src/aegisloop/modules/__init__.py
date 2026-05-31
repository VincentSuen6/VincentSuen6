from .broken_auth import PathTraversalModule
from .idor import IDORModule
from .injection import SQLInjectionModule
from .xss import ReflectedXSSModule

ALL_MODULES = [SQLInjectionModule, ReflectedXSSModule, PathTraversalModule, IDORModule]

__all__ = ["ALL_MODULES", "SQLInjectionModule", "ReflectedXSSModule", "PathTraversalModule", "IDORModule"]
