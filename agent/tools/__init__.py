"""Tool registry with auto-discovery."""

import logging

logger = logging.getLogger(__name__)

# Global registry
TOOL_REGISTRY: dict[str, callable] = {}
TOOL_SPECS: list[dict] = []


def register_tool(spec: dict):
    """Decorator to register a tool function with its spec."""
    def decorator(func):
        TOOL_REGISTRY[spec["name"]] = func
        TOOL_SPECS.append(spec)
        return func
    return decorator


def _import_all_tools():
    """Import all tool modules to trigger @register_tool decorators."""
    # Core tools
    from . import nuclei, sqlmap, ffuf, recon, set_phish, cleanup
    from . import bettercap, zphisher, cyberstrike, read_log, payloads
    from . import human_input, report

    # New tools (optional — don't crash if missing)
    _optional = [
        "nmap_scan", "whatweb_tool", "screenshot",
        "auth_manager", "mission_diff",
    ]
    for mod_name in _optional:
        try:
            __import__(f"tools.{mod_name}", fromlist=[mod_name])
        except ImportError as e:
            logger.debug("Optional tool '%s' not available: %s", mod_name, e)


# Auto-register all tools on import — fallback to manual if decorator not used
_import_all_tools()

# If tools didn't use @register_tool, build from TOOL_SPEC attributes
if not TOOL_SPECS:
    from .nuclei import run as run_nuclei, TOOL_SPEC as nuclei_spec
    from .sqlmap import run as run_sqlmap, TOOL_SPEC as sqlmap_spec
    from .ffuf import run as run_ffuf, TOOL_SPEC as ffuf_spec
    from .recon import run as run_recon, TOOL_SPEC as recon_spec
    from .set_phish import run as generate_phish_template, TOOL_SPEC as phish_spec
    from .cleanup import run as cleanup_temp, TOOL_SPEC as cleanup_spec
    from .bettercap import run as run_bettercap, TOOL_SPEC as bettercap_spec
    from .zphisher import run as generate_zphisher_template, TOOL_SPEC as zphisher_spec
    from .cyberstrike import run as run_cyberstrike, TOOL_SPEC as cyberstrike_spec
    from .read_log import run as read_log, TOOL_SPEC as read_log_spec
    from .payloads import run as run_payloads, TOOL_SPEC as payloads_spec
    from .human_input import run as request_human_input, TOOL_SPEC as human_input_spec
    from .report import run as generate_report, TOOL_SPEC as report_spec

    _specs = [
        nuclei_spec, sqlmap_spec, ffuf_spec, recon_spec, phish_spec, cleanup_spec,
        bettercap_spec, zphisher_spec, cyberstrike_spec, read_log_spec, payloads_spec,
        human_input_spec, report_spec,
    ]
    _funcs = {
        "run_nuclei": run_nuclei, "run_sqlmap": run_sqlmap, "run_ffuf": run_ffuf,
        "run_recon": run_recon, "generate_phish_template": generate_phish_template,
        "cleanup_temp": cleanup_temp, "run_bettercap": run_bettercap,
        "generate_zphisher_template": generate_zphisher_template,
        "run_cyberstrike": run_cyberstrike, "read_log": read_log,
        "run_payloads": run_payloads, "request_human_input": request_human_input,
        "generate_report": generate_report,
    }
    TOOL_SPECS.extend(_specs)
    TOOL_REGISTRY.update(_funcs)

    # Try loading new tools manually
    try:
        from .nmap_scan import run as _nmap_run, TOOL_SPEC as _nmap_spec
        TOOL_SPECS.append(_nmap_spec)
        TOOL_REGISTRY[_nmap_spec["name"]] = _nmap_run
    except ImportError:
        pass
    try:
        from .whatweb_tool import run as _ww_run, TOOL_SPEC as _ww_spec
        TOOL_SPECS.append(_ww_spec)
        TOOL_REGISTRY[_ww_spec["name"]] = _ww_run
    except ImportError:
        pass
    try:
        from .screenshot import run as _ss_run, TOOL_SPEC as _ss_spec
        TOOL_SPECS.append(_ss_spec)
        TOOL_REGISTRY[_ss_spec["name"]] = _ss_run
    except ImportError:
        pass
    try:
        from .auth_manager import run as _auth_run, TOOL_SPEC as _auth_spec
        TOOL_SPECS.append(_auth_spec)
        TOOL_REGISTRY[_auth_spec["name"]] = _auth_run
    except ImportError:
        pass
    try:
        from .mission_diff import run as _diff_run, TOOL_SPEC as _diff_spec
        TOOL_SPECS.append(_diff_spec)
        TOOL_REGISTRY[_diff_spec["name"]] = _diff_run
    except ImportError:
        pass


# Public API
ALL_TOOLS = TOOL_SPECS


def get_tool_mapping() -> dict[str, callable]:
    """Return {tool_name: function} mapping for all registered tools."""
    return dict(TOOL_REGISTRY)
