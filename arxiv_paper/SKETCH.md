# Paper Sketch: Automated Greybox REST API Fuzzing for .NET via Source-Aware Grammar Enhancement

**Proposed Title:** Automated Greybox REST API Fuzzing for .NET via Source-Aware Grammar Enhancement  
**Authors:** [Your Name / Team Names]  
**Target:** arXiv (cs.CR - Cryptography and Security)

---

## 1. Abstract (approx. 200 words)
Modern microservices heavily rely on REST APIs, making them a critical attack surface. While black-box API fuzzers (like RESTler) efficiently generate requests from OpenAPI specifications, they suffer from two major limitations: lack of code-coverage feedback and inability to generate semantic payloads that pass deep backend validation rules (e.g., string lengths, regex patterns). Conversely, traditional coverage-guided fuzzers (like AFL) struggle with the structured nature of HTTP protocols. 

In this paper, we present **UpsideFuzz** (internally *Void*), a novel hybrid fuzzer specifically designed for .NET applications. UpsideFuzz introduces a unique *Semantic Source Extraction* phase that statically analyzes C# source code (including attributes and FluentValidation rules) to automatically enrich the OpenAPI fuzzing grammar with highly precise, boundary-focused test cases. Furthermore, we bridge the gap between black-box payload generation and white-box execution by integrating a lightweight Go-based fuzzing engine that receives real-time edge coverage feedback directly from the .NET Runtime via shared memory (SHM). 

Our evaluation on three real-world .NET e-commerce and enterprise applications demonstrates that UpsideFuzz achieves [X]% deeper code coverage and discovers [Y] unique vulnerabilities significantly faster than baseline black-box approaches.

---

## 2. Introduction
- **Context:** The rise of APIs and the difficulty of automated security testing.
- **The Problem:** 
  - Black-box fuzzers get stuck at the API gateway because payloads are rejected by basic validation (e.g., sending `"fuzzstring"` when a field requires a valid email or a string of exactly 10 characters).
  - Coverage-guided fuzzers are too slow for network APIs or require manually writing complex harnesses.
- **Our Solution (UpsideFuzz):** 
  - Combine OpenAPI specs with *source-code hints*.
  - Use high-performance Shared Memory (SHM) coverage collection for fast feedback loops.
- **Contributions:**
  1. A static analysis technique to automatically extract semantic constraints (Regex, boundaries, Enums) from C# code and inject them into API fuzzing dictionaries.
  2. A highly concurrent Go-based fuzzing engine tailored for .NET applications.
  3. An empirical evaluation showing significant improvements in coverage and bug discovery.

---

## 3. Background & Related Work
- **API Fuzzing:** RESTler, Dredd, EvoMaster. Discuss their reliance on Swagger and lack of coverage.
- **Coverage-Guided Fuzzing:** AFL/AFL++, libFuzzer, SharpFuzz. Discuss their difficulty with structured protocols.
- **Hybrid Approaches:** Highlight the gap that UpsideFuzz fills (automatically bridging source constraints into request generation).

---

## 4. Methodology & Architecture (The Core of the Paper)
*This section will heavily feature the architecture components described in the project's README.*

### 4.1. The UpsideFuzz Pipeline
- Explain the end-to-end flow: `fuzz-prep-multi.py` -> `compile-grammar.sh` -> Go Fuzzer.

### 4.2. Semantic Source Extraction (`enhance-grammar.py`)
- **The "Secret Sauce":** How the Python script parses Swagger, and more importantly, how it scans C# source files using regex/AST.
- **Constraint Mapping:** Show examples of how C# attributes translate to fuzzing values.
  - *Example:* `[StringLength(50, MinimumLength=10)]` -> Generates strings of length 10, 50, and 51.
  - *Example:* `RuleFor(x => x.Age).InclusiveBetween(18, 65)` -> Generates values 17, 18, 65, 66.
- **Multipart Generation:** How we inject realistic file upload requests into the RESTler grammar.

### 4.3. High-Performance Fuzzing Engine (The Void Go Component)
- **Concurrency Model:** How the Go workers distribute requests.
- **Coverage Collection:** Integrating SharpFuzz via direct Shared Memory (`-direct-shm`) vs. HTTP coverage, avoiding the overhead of file I/O or pure network delays.

---

## 5. Evaluation
*This section needs actual data from our tests.*

### 5.1. Experimental Setup
- **Targets:** nopCommerce (large open-source e-commerce), eShopOnContainers (microservice reference), mpt-helpdesk (custom enterprise app).
- **Environment:** Docker containers, constraints (CPUs/RAM).

### 5.2. Code Coverage Analysis
- **Metric:** Edge/Branch coverage over 24 hours.
- **Comparison:** UpsideFuzz vs. Standard RESTler vs. Random Fuzzing.
- **Hypothesis/Result:** UpsideFuzz reaches deeper code paths faster because semantic payloads survive the initial validation checks. Plot a "Coverage over Time" graph.

### 5.3. Vulnerability Discovery
- **Metric:** Number of unique HTTP 500s or native crashes found.
- **Qualitative Analysis:** Case studies of complex bugs found (e.g., a specific bug in nopCommerce requiring a specific Enum and boundary value that only `enhance-grammar.py` could guess).

---

## 6. Discussion
- **Limitations:** The static extraction relies on regex heuristics and might miss complex, dynamically constructed validations.
- **Future Work:** Moving from Regex-based constraint extraction to Roslyn-based AST extraction; supporting Java/Spring or Node.js via similar semantic mapping.

---

## 7. Conclusion
- Summary of the impact: Bridging the gap between static code semantics and dynamic API fuzzing dramatically increases testing efficacy for modern .NET microservices.

---

## 8. References
- [1] RESTler: Stateful REST API Fuzzing (ICSE '19)
- [2] SharpFuzz: Coverage-guided fuzzing for .NET
- [X] ...

---

*Note: This is the structured skeleton. To make it a real paper, we need to execute the benchmarks (Section 5) and fill in the exact numbers, graphs, and case studies.*
