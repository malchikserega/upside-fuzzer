# Preparation Plan: arXiv Publication for UpsideFuzz (Void)

## 1. Goal
Publish a tool paper or short research paper on arXiv (and potentially submit to an academic/industry conference like IEEE STC, Black Hat Arsenal, or OFFZONE) detailing the architecture and effectiveness of **UpsideFuzz**, a hybrid API fuzzer combining RESTler's black-box grammar generation with C# source-aware semantic extraction and Go-based coverage-guided local execution.

## 2. Target Venues
1. **Primary Immediate Goal:** arXiv (Computer Science > Cryptography and Security).
2. **Secondary Goals:**
   - **Academic Conferences:** IEEE/ACM International Conference on Software Engineering (ICSE) - Tool Demonstrations Track.
   - **Industry Conferences:** Black Hat Arsenal, DEF CON AppSec Village, OFFZONE.

## 3. Timeline & Milestones (Estimated 4-5 weeks)

### Week 1: Literature Review & Evaluation Setup
- **Tasks:**
  - Research related works: RESTler, AFL, SharpFuzz, Dredd, and state-of-the-art hybrid API fuzzers.
  - Setup benchmarks: Ensure nopCommerce, eShop, and mpt-helpdesk are fully instrumented.
  - Instrument the RESTler baseline (without `enhance-grammar.py` and SHM coverage) to serve as a comparison point.
- **Deliverable:** Working benchmark environments and a list of 5-10 key related papers.

### Week 2: Data Collection (Evaluation)
- **Tasks:**
  - Run **Baseline (RESTler default)** for 24 hours on all 3 target applications.
  - Run **UpsideFuzz (Full pipeline)** for 24 hours on all 3 target applications.
  - Collect metrics:
    1. Code Coverage over time (lines/branches).
    2. Number of unique crashes/500 errors discovered over time.
    3. Time-to-first-crash.
- **Deliverable:** Raw CSV/JSON data of the fuzzing results and generated plots (Coverage vs. Time).

### Week 3: Drafting the Article
- **Tasks:**
  - Convert `SKETCH.md` into a formal LaTeX document (using standard IEEE or ACM templates).
  - Draft Introduction, Related Work, Architecture (Methodology), and Evaluation sections.
  - Create professional diagrams: 
    - End-to-End Architecture.
    - Semantic Extraction Flow (`enhance-grammar.py` logic).
- **Deliverable:** First complete draft of the PDF paper.

### Week 4: Refinement and Proofreading
- **Tasks:**
  - Review the draft for clarity, academic tone, and flow.
  - Fix any formatting issues (citations, math, tables).
  - Write a compelling Abstract.
- **Deliverable:** Final Draft ready for submission.

### Week 5: Submission
- **Tasks:**
  - Register on arXiv and upload the LaTeX source + figures.
  - Publish a corresponding blog post on Medium/Habr or a Twitter thread summarizing the paper to gain traction.
- **Deliverable:** Live arXiv link.

## 4. Required Artifacts
- **The Text (`paper.tex`):** The main manuscript.
- **Figures:** 
  - `fig-architecture.pdf` (Mermaid/Draw.io diagram of the pipeline).
  - `fig-coverage-eshop.png` (Benchmark graph).
  - `fig-semantic-extraction.pdf` (How C# attributes map to fuzzing values).
- **Data Tables:** Summary of bugs found.

## Next Action Items
1. Review the `SKETCH.md` in this directory.
2. Decide on the exact benchmark targets.
3. Start the 24-hour fuzzing runs to collect evaluation data.
