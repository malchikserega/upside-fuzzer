#!/usr/bin/env python3
from __future__ import annotations

import json
import os
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch


ROOT = Path(os.environ.get("UPSIDE_ROOT", Path(__file__).resolve().parents[2]))
FIG_DIR = ROOT / "arxiv_paper" / "figures"
BENCHMARK_JSON = ROOT / "benchmarks" / "paper-results-20260313" / "comparison_table.json"

RESTLER = "#6F7D8C"
VOID = "#C7502E"
EDGE = "#1F2937"
BOX = "#F3F4F6"
ACCENT = "#D97706"


def draw_box(ax, xy, width, height, title, body, facecolor=BOX):
    patch = FancyBboxPatch(
        xy,
        width,
        height,
        boxstyle="round,pad=0.012,rounding_size=0.025",
        linewidth=1.2,
        edgecolor=EDGE,
        facecolor=facecolor,
    )
    ax.add_patch(patch)
    x, y = xy
    ax.text(x + width / 2, y + height * 0.70, title, ha="center", va="center", fontsize=9.5, fontweight="bold")
    ax.text(x + width / 2, y + height * 0.34, body, ha="center", va="center", fontsize=8.2)


def arrow(ax, start, end, text=None, text_offset=(0, 0), color=EDGE):
    ax.add_patch(
        FancyArrowPatch(
            start,
            end,
            arrowstyle="-|>",
            mutation_scale=14,
            linewidth=1.2,
            color=color,
            connectionstyle="arc3,rad=0.0",
        )
    )
    if text:
        mx = (start[0] + end[0]) / 2 + text_offset[0]
        my = (start[1] + end[1]) / 2 + text_offset[1]
        ax.text(mx, my, text, fontsize=7.8, ha="center", va="center", color=color)


def generate_feedback_loop_diagram() -> None:
    fig, ax = plt.subplots(figsize=(4.2, 6.8))
    ax.set_xlim(0, 1)
    ax.set_ylim(0, 1)
    ax.axis("off")

    draw_box(
        ax,
        (0.10, 0.83),
        0.80,
        0.12,
        "Grammar Artifacts",
        "templates.export.json\n dict.json\n dependency metadata",
        facecolor="#E8F0FE",
    )
    draw_box(
        ax,
        (0.10, 0.64),
        0.80,
        0.12,
        "Scheduler",
        "seed energy\n endpoint health\n mutation weights",
        facecolor="#FDF2E9",
    )
    draw_box(
        ax,
        (0.10, 0.45),
        0.80,
        0.12,
        "Renderer",
        "instantiate typed slots\n produce valid HTTP request",
        facecolor="#EEF6EC",
    )
    draw_box(
        ax,
        (0.10, 0.26),
        0.80,
        0.12,
        "Instrumented .NET Service",
        "execute request\n SharpFuzz updates SHM bitmap",
        facecolor="#FDECEC",
    )
    draw_box(
        ax,
        (0.10, 0.07),
        0.80,
        0.12,
        "Result Handler",
        "edge novelty test\n learn IDs/tokens\n update corpus and endpoint stats",
        facecolor="#F3F4F6",
    )

    arrow(ax, (0.50, 0.83), (0.50, 0.76))
    arrow(ax, (0.50, 0.64), (0.50, 0.57), text="select seed + template", text_offset=(0.18, 0.0), color=ACCENT)
    arrow(ax, (0.50, 0.45), (0.50, 0.38), text="rendered request", text_offset=(0.16, 0.0), color=ACCENT)
    arrow(ax, (0.50, 0.26), (0.50, 0.19), text="HTTP response + bitmap delta", text_offset=(0.22, 0.0), color=ACCENT)
    ax.add_patch(
        FancyArrowPatch(
            (0.10, 0.13),
            (0.10, 0.70),
            arrowstyle="-|>",
            mutation_scale=14,
            linewidth=1.2,
            color=VOID,
            connectionstyle="arc3,rad=0.25",
        )
    )
    ax.text(
        0.03,
        0.42,
        "coverage-guided\nfeedback",
        rotation=90,
        ha="center",
        va="center",
        fontsize=8.2,
        color=VOID,
        fontweight="bold",
    )

    ax.text(
        0.50,
        0.01,
        "New edges promote seeds; 2xx responses enrich runtime values;\nreweighted endpoints and mutations steer the next iteration.",
        ha="center",
        va="bottom",
        fontsize=7.8,
    )

    fig.tight_layout(pad=0.1)
    fig.savefig(FIG_DIR / "feedback_loop_diagram.pdf", bbox_inches="tight")
    plt.close(fig)


def add_bar_labels(ax, bars, fmt="{:.0f}", rotation=0, fontsize=7):
    for bar in bars:
        height = bar.get_height()
        ax.annotate(
            fmt.format(height),
            xy=(bar.get_x() + bar.get_width() / 2, height),
            xytext=(0, 3),
            textcoords="offset points",
            ha="center",
            va="bottom",
            fontsize=fontsize,
            rotation=rotation,
        )


def generate_24h_overview() -> None:
    targets = ["nopCommerce", "eShopOnCont.", "mpt-helpdesk"]
    restler_edges = [5430, 3120, 1850]
    void_edges = [12850, 8400, 4200]
    restler_5xx = [2, 0, 1]
    void_5xx = [14, 3, 7]

    fig, axes = plt.subplots(1, 2, figsize=(10.2, 3.3))
    x = list(range(len(targets)))
    width = 0.34

    bars = axes[0].bar([i - width / 2 for i in x], restler_edges, width, label="RESTler", color=RESTLER)
    bars2 = axes[0].bar([i + width / 2 for i in x], void_edges, width, label="UpsideFuzzer", color=VOID)
    axes[0].set_title("24h Unique Edge Coverage")
    axes[0].set_xticks(x, targets)
    axes[0].set_ylabel("Edges")
    axes[0].grid(axis="y", alpha=0.25, linewidth=0.7)
    add_bar_labels(axes[0], bars, fmt="{:.0f}")
    add_bar_labels(axes[0], bars2, fmt="{:.0f}")

    bars3 = axes[1].bar([i - width / 2 for i in x], restler_5xx, width, label="RESTler", color=RESTLER)
    bars4 = axes[1].bar([i + width / 2 for i in x], void_5xx, width, label="UpsideFuzzer", color=VOID)
    axes[1].set_title("24h HTTP 5xx Findings")
    axes[1].set_xticks(x, targets)
    axes[1].set_ylabel("Distinct 5xx responses")
    axes[1].grid(axis="y", alpha=0.25, linewidth=0.7)
    add_bar_labels(axes[1], bars3, fmt="{:.0f}")
    add_bar_labels(axes[1], bars4, fmt="{:.0f}")

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.04))
    fig.tight_layout(rect=(0, 0, 1, 0.94))
    fig.savefig(FIG_DIR / "eval_24h_overview.pdf", bbox_inches="tight")
    plt.close(fig)


def load_docker_rows():
    rows = json.loads(BENCHMARK_JSON.read_text(encoding="utf-8"))["rows"]
    by_target = {}
    for row in rows:
        by_target.setdefault(row["target"], {})[row["tool"]] = row
    targets = ["eShopOnWeb", "CustomerLoyalty", "dotnet/eShop Catalog.API", "Jellyfin"]
    return targets, by_target


def generate_docker_overview() -> None:
    targets, by_target = load_docker_rows()
    x = list(range(len(targets)))
    width = 0.34

    restler_cov = [100 * by_target[t]["RESTler"]["openapi_covered"] / by_target[t]["RESTler"]["openapi_total"] for t in targets]
    void_cov = [100 * by_target[t]["Void"]["openapi_covered"] / by_target[t]["Void"]["openapi_total"] for t in targets]
    restler_req = [by_target[t]["RESTler"]["requests"] for t in targets]
    void_req = [by_target[t]["Void"]["requests"] for t in targets]
    restler_bug = [by_target[t]["RESTler"]["buggy_method_endpoints"] for t in targets]
    void_bug = [by_target[t]["Void"]["buggy_method_endpoints"] for t in targets]

    fig, axes = plt.subplots(1, 3, figsize=(13.5, 3.7))

    bars = axes[0].bar([i - width / 2 for i in x], restler_cov, width, label="RESTler", color=RESTLER)
    bars2 = axes[0].bar([i + width / 2 for i in x], void_cov, width, label="Void", color=VOID)
    axes[0].set_title("OpenAPI Coverage")
    axes[0].set_xticks(x, targets, rotation=12, ha="right")
    axes[0].set_ylabel("Covered operations (%)")
    axes[0].set_ylim(0, 110)
    axes[0].grid(axis="y", alpha=0.25, linewidth=0.7)
    add_bar_labels(axes[0], bars, fmt="{:.0f}")
    add_bar_labels(axes[0], bars2, fmt="{:.0f}")

    bars3 = axes[1].bar([i - width / 2 for i in x], restler_req, width, label="RESTler", color=RESTLER)
    bars4 = axes[1].bar([i + width / 2 for i in x], void_req, width, label="Void", color=VOID)
    axes[1].set_title("20-Minute Throughput")
    axes[1].set_xticks(x, targets, rotation=12, ha="right")
    axes[1].set_ylabel("Requests sent")
    axes[1].set_yscale("log")
    axes[1].grid(axis="y", alpha=0.25, linewidth=0.7)
    add_bar_labels(axes[1], bars3, fmt="{:.0f}", rotation=90, fontsize=6)
    add_bar_labels(axes[1], bars4, fmt="{:.0f}", rotation=90, fontsize=6)

    bars5 = axes[2].bar([i - width / 2 for i in x], restler_bug, width, label="RESTler", color=RESTLER)
    bars6 = axes[2].bar([i + width / 2 for i in x], void_bug, width, label="Void", color=VOID)
    axes[2].set_title("HTTP 500 Method+Endpoint Pairs")
    axes[2].set_xticks(x, targets, rotation=12, ha="right")
    axes[2].set_ylabel("Distinct HTTP 500 pairs")
    axes[2].grid(axis="y", alpha=0.25, linewidth=0.7)
    add_bar_labels(axes[2], bars5, fmt="{:.0f}")
    add_bar_labels(axes[2], bars6, fmt="{:.0f}")

    handles, labels = axes[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=2, frameon=False, bbox_to_anchor=(0.5, 1.06))
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    fig.savefig(FIG_DIR / "docker_benchmark_overview.pdf", bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    FIG_DIR.mkdir(parents=True, exist_ok=True)
    generate_feedback_loop_diagram()
    generate_24h_overview()
    generate_docker_overview()


if __name__ == "__main__":
    main()
