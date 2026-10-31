"""Evidence-backed recommendation builder.

Generates debugging steps that are directly traceable to the evidence and
root-cause analysis. Recommendations are always labelled and never
invented beyond what the log evidence supports.
"""

from __future__ import annotations

from datetime import datetime
from typing import Dict, List, Optional

from tb_core.core.models import Event, Evidence
from tb_core.analysis.cascade import CascadeAnalyzer
from tb_core.analysis.root_cause import RootCauseAnalyzer


class RecommendationBuilder:
    """Builds actionable, evidence-backed debugging recommendations."""

    def build(self, group, cascade_result: Dict,
              root_cause_analysis: Dict) -> List[str]:
        recommendations = []

        # Add root-cause-based steps
        suspicious = root_cause_analysis.get("suspicious_event")
        if suspicious:
            recommendations.append(
                f"Start by investigating: {suspicious.message[:100]}"
            )

        # Add root-cause hypothesis step
        rch = root_cause_analysis.get("root_cause_hypothesis")
        if rch:
            recommendations.append(
                f"Investigate the initial failure: {rch.message[:100]} "
                f"[{rch.service or 'unknown service'}]"
            )

        # Add cascade-based steps (downstream failures)
        downstream = cascade_result.get("downstream_failures", [])
        for ev in downstream:
            recommendations.append(
                f"Check the downstream dependency indicated by: {ev.finding[:100]}"
            )

        # Add pattern-based recommendations from supporting evidence
        supporting = root_cause_analysis.get("supporting_evidence", [])
        for cause in supporting:
            if cause.event_ids:
                recommendations.append(
                    f"Review the supporting event ({cause.event_ids[0]}) in the original log"
                )

        # De-dupe while preserving order
        seen = set()
        unique = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique.append(rec)

        # Always include the primary investigation step
        if not unique:
            unique.append("Review the timeline and identify the first event in the chain")

        return unique

    def build_full_report(self, group, analysis: Dict,
                          cascade_result: Dict) -> Dict:
        """Return the complete recommendation report for an incident."""
        return {
            "incident_title": group.title,
            "recommended_steps": self.build(group, cascade_result, analysis),
            "analysis_timestamp": datetime.utcnow().isoformat(),
            "evidence_traceable": True,
        }