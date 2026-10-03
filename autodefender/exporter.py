"""CSV and JSON export for threats.

The web console builds exports in memory for download; the CLI writes them
to the exports/ directory.
"""

import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from typing import List

from autodefender.mitre import technique_labels, techniques_for
from autodefender.models import Threat
from autodefender.utils.path_utils import sanitize_filename

logger = logging.getLogger(__name__)


# Leading characters that make Excel/Sheets treat a cell as a formula
_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

CSV_HEADER = [
    'ID', 'Timestamp', 'Source IP', 'Destination IP', 'Destination Port',
    'Event Type', 'Severity', 'Description', 'MITRE ATT&CK', 'AI Explanation'
]


def _safe_cell(value) -> str:
    """Neutralize spreadsheet formulas in log-derived CSV values."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_FORMULA_PREFIXES) else text


def threats_to_csv(threats: List[Threat]) -> str:
    """Return threats as CSV text."""
    buffer = io.StringIO()
    writer = csv.writer(buffer, quoting=csv.QUOTE_ALL)
    writer.writerow(CSV_HEADER)
    for threat in threats:
        writer.writerow([_safe_cell(v) for v in (
            threat.id,
            threat.timestamp.isoformat() if threat.timestamp else '',
            threat.source_ip or '',
            threat.dest_ip or '',
            threat.dest_port or '',
            threat.event_type,
            threat.severity,
            threat.description,
            technique_labels(threat),
            threat.ai_explanation or '',
        )])
    return buffer.getvalue()


def threats_to_json(threats: List[Threat]) -> str:
    """Return threats as a JSON document."""
    data = {
        'export_timestamp': datetime.now(timezone.utc).isoformat(),
        'total_threats': len(threats),
        'threats': [
            {
                'id': threat.id,
                'timestamp': threat.timestamp.isoformat() if threat.timestamp else None,
                'source_ip': threat.source_ip,
                'dest_ip': threat.dest_ip,
                'dest_port': threat.dest_port,
                'event_type': threat.event_type,
                'severity': threat.severity,
                'description': threat.description,
                'mitre_attack': [t['id'] for t in techniques_for(threat)],
                'ai_explanation': threat.ai_explanation,
            }
            for threat in threats
        ],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def _prepare_output_path(filename: str) -> str:
    """Return a path for filename inside the exports directory.

    Only the sanitized base name is used, so the file can't land anywhere else.
    """
    safe_filename = os.path.basename(sanitize_filename(filename, default="export"))
    exports_dir = os.path.realpath(os.path.join(os.getcwd(), "exports"))
    os.makedirs(exports_dir, exist_ok=True)
    return os.path.join(exports_dir, safe_filename)


def write_export(threats: List[Threat], filename: str, export_format: str) -> str:
    """Write threats to exports/<filename> as 'csv' or 'json' and return the path.

    Raises:
        OSError: If the file can't be written
    """
    content = threats_to_csv(threats) if export_format.lower() == 'csv' else threats_to_json(threats)
    path = _prepare_output_path(filename)
    with open(path, 'w', newline='', encoding='utf-8') as f:
        f.write(content)
    if os.name == "posix":
        # Exports contain IP addresses; keep them readable by this user only
        os.chmod(path, 0o600)
    logger.info(f"Exported {len(threats)} threats to {path}")
    return path
