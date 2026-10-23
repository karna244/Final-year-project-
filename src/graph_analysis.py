"""Graph-based contextual and entity-relationship analysis using NetworkX.
Inspired by NoDoze (Hassan et al., NDSS 2019) adapted for alert-level triage.
"""
import networkx as nx
import pandas as pd
import numpy as np
from typing import Dict, Any, Tuple


def build_entity_graph(df: pd.DataFrame) -> nx.DiGraph:
    """
    Construct a directed entity communication graph from alert records.
    Nodes: Source and Destination IP addresses.
    Edges: Communication events with aggregated weights and counts.
    """
    G = nx.DiGraph()

    for _, row in df.iterrows():
        u = str(row["source_ip"])
        v = str(row["destination_ip"])

        # Add nodes with initial metadata
        if not G.has_node(u):
            G.add_node(u, entity_type="source_host")
        if not G.has_node(v):
            G.add_node(v, entity_type="dest_host")

        # Add or update edge weight
        if G.has_edge(u, v):
            G[u][v]["weight"] += 1
            G[u][v]["event_types"].add(str(row["event_type"]))
        else:
            G.add_edge(u, v, weight=1, event_types={str(row["event_type"])})

    return G


def compute_graph_features(
    df: pd.DataFrame,
    G: nx.DiGraph = None,
    hub_percentile: int = 90,
    scale_factor: float = 12.5,
) -> Tuple[pd.DataFrame, nx.DiGraph, Dict[str, Any]]:
    """
    Calculate contextual topological metrics for each alert:
    - Node degrees (in/out/total)
    - Hub detection (high-centrality entities)
    - Contextual Risk Weight (0 - 100)
    """
    if G is None:
        G = build_entity_graph(df)

    # Compute node degrees
    degrees = dict(G.degree())
    in_degrees = dict(G.in_degree())
    out_degrees = dict(G.out_degree())

    degree_values = list(degrees.values()) if degrees else [1]
    hub_cutoff = np.percentile(degree_values, hub_percentile) if degree_values else 1

    df = df.copy()

    src_deg = df["source_ip"].map(lambda ip: degrees.get(str(ip), 1))
    dst_deg = df["destination_ip"].map(lambda ip: degrees.get(str(ip), 1))

    # Combined connectivity degree
    avg_deg = (src_deg + dst_deg) / 2.0
    df["graph_degree"] = avg_deg

    # Flag whether incident involves a structural hub
    df["is_hub_incident"] = (src_deg >= hub_cutoff) | (dst_deg >= hub_cutoff)

    # Normalized Context Score: scale to [0, 100]
    df["context_score"] = np.clip(avg_deg * scale_factor, 0.0, 100.0).round(1)

    graph_stats = {
        "num_nodes": G.number_of_nodes(),
        "num_edges": G.number_of_edges(),
        "density": round(nx.density(G), 4) if G.number_of_nodes() > 0 else 0,
        "hub_threshold_degree": hub_cutoff,
        "top_connected_nodes": sorted(degrees.items(), key=lambda x: x[1], reverse=True)[:5],
    }

    return df, G, graph_stats


def extract_incident_subgraph(
    G: nx.DiGraph,
    source_ip: str,
    destination_ip: str,
    hops: int = 1,
) -> nx.DiGraph:
    """
    Extract a localized k-hop neighborhood subgraph surrounding an incident.
    Enables focused visual investigation in the Streamlit dashboard.
    """
    target_nodes = {str(source_ip), str(destination_ip)}
    current_nodes = set(target_nodes)

    for _ in range(hops):
        next_nodes = set(current_nodes)
        for n in current_nodes:
            if G.has_node(n):
                next_nodes.update(G.predecessors(n))
                next_nodes.update(G.successors(n))
        current_nodes = next_nodes

    sub = G.subgraph(current_nodes).copy()
    return sub
