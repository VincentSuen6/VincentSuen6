import importlib
from typing import Tuple

TTP_PACKAGE = "ttps"


def dispatch(task_type: str, params: dict) -> Tuple[str, str, dict]:
    try:
        module = importlib.import_module(f"{TTP_PACKAGE}.{task_type}")
        return module.run(params)
    except ModuleNotFoundError:
        return "failed", f"unknown TTP module: {task_type}", {}
    except Exception as exc:
        return "failed", str(exc), {}
