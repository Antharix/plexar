"""
Plexar AI Engine.

LLM-powered intelligence layer for network automation.

  AIParser      — Parse any CLI output into typed models using LLM fallback
  RCAEngine     — Root cause analysis for network events
  NetworkQuery  — Natural language queries across your fleet

Usage:
    from plexar.ai import AIParser, RCAEngine, NetworkQuery

    # Parse unknown vendor output
    parser = AIParser(model="gpt-4o-mini")
    bgp    = await parser.parse_bgp_summary(raw_output)

    # Root cause analysis
    rca       = RCAEngine()
    diagnosis = await rca.analyze(event, device=d, topology=topo)
    print(diagnosis.render())

    # Natural language queries
    nq     = NetworkQuery(network=net)
    result = await nq.ask("which leafs have BGP peers down?")
    print(result.answer)
"""

from plexar.ai.parser import AIParser
from plexar.ai.rca    import RCAEngine, RCADiagnosis, RemediationAction
from plexar.ai.query  import NetworkQuery, QueryResult, QueryPlan

__all__ = [
    "AIParser",
    "RCAEngine", "RCADiagnosis", "RemediationAction",
    "NetworkQuery", "QueryResult", "QueryPlan",
]
