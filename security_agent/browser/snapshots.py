"""
Snapshot repository and structural diff analysis for DOM snapshots.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional, Set
from security_agent.browser.dom import DOMSnapshot


class SnapshotRepository:
    """In-memory and persistent catalog for DOM snapshots."""

    def __init__(self):
        self._snapshots: Dict[str, DOMSnapshot] = {}
        self._url_index: Dict[str, List[str]] = {}

    def store_snapshot(self, snapshot: DOMSnapshot) -> str:
        self._snapshots[snapshot.snapshot_id] = snapshot
        if snapshot.url not in self._url_index:
            self._url_index[snapshot.url] = []
        self._url_index[snapshot.url].append(snapshot.snapshot_id)
        return snapshot.snapshot_id

    def get_snapshot(self, snapshot_id: str) -> Optional[DOMSnapshot]:
        return self._snapshots.get(snapshot_id)

    def list_snapshots(self, url: Optional[str] = None) -> List[DOMSnapshot]:
        if url:
            ids = self._url_index.get(url, [])
            return [self._snapshots[sid] for sid in ids if sid in self._snapshots]
        return list(self._snapshots.values())

    @staticmethod
    def diff_snapshots(snap_a: Optional[DOMSnapshot], snap_b: Optional[DOMSnapshot]) -> Dict[str, Any]:
        """
        Computes structural delta between two DOM snapshots.
        Identifies newly exposed forms, links, APIs, and authentication changes.
        """
        if not snap_a or not snap_b:
            return {
                "is_identical": False,
                "new_forms": len(snap_b.forms) if snap_b else 0,
                "new_links": len(snap_b.links) if snap_b else 0,
                "new_apis": len(snap_b.api_candidates) if snap_b else 0,
                "new_websockets": len(snap_b.websockets) if snap_b else 0,
                "information_gain": 1.0 if snap_b else 0.0,
            }

        # Compare Forms
        forms_a = {f.form_id for f in snap_a.forms}
        new_forms = [f for f in snap_b.forms if f.form_id not in forms_a]

        # Compare Links
        links_a = {l.href for l in snap_a.links}
        new_links = [l for l in snap_b.links if l.href not in links_a]

        # Compare APIs
        apis_a = {a.url for a in snap_a.api_candidates}
        new_apis = [a for a in snap_b.api_candidates if a.url not in apis_a]

        # Compare WebSockets
        ws_a = {w.url for w in snap_a.websockets}
        new_ws = [w for w in snap_b.websockets if w.url not in ws_a]

        # Compute information gain
        info_gain = (
            len(new_forms) * 3.0
            + len(new_apis) * 2.0
            + len(new_ws) * 2.0
            + len(new_links) * 0.5
        )

        return {
            "is_identical": (len(new_forms) == 0 and len(new_links) == 0 and len(new_apis) == 0 and len(new_ws) == 0),
            "new_forms": [f.to_dict() for f in new_forms],
            "new_links": [l.to_dict() for l in new_links],
            "new_apis": [a.to_dict() for a in new_apis],
            "new_websockets": [w.to_dict() for w in new_ws],
            "information_gain": round(info_gain, 3),
        }
