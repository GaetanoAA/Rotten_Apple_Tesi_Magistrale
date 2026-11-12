from langgraph.graph import StateGraph, START, END

from core.state import ExperimentState
from core.aggregator import aggregate_votes
from core.logger import log_event

from agents.nodes import (
    run_agent_a,
    run_agent_b,
    run_agent_c,
    run_agent_d,
    run_agent_e,
)


def run_aggregator(state: ExperimentState) -> dict:
    final_decision = aggregate_votes(
        state["votes"]
    )

    log_event(
        state["run_id"],
        "AGGREGATION",
        {
            "votes": state["votes"],
            "final_decision": final_decision,
        },
    )

    return {
        **state,
        "final_decision": final_decision,
    }


def build_workflow():
    builder = StateGraph(ExperimentState)

    builder.add_node("A", run_agent_a)
    builder.add_node("B", run_agent_b)
    builder.add_node("C", run_agent_c)
    builder.add_node("D", run_agent_d)
    builder.add_node("E", run_agent_e)
    builder.add_node("aggregator", run_aggregator)

    builder.add_edge(START, "A")
    builder.add_edge("A", "B")
    builder.add_edge("B", "C")
    builder.add_edge("C", "D")
    builder.add_edge("D", "E")
    builder.add_edge("E", "aggregator")
    builder.add_edge("aggregator", END)

    return builder.compile()