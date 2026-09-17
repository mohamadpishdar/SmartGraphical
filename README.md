# \# SmartGraphical

# 

# SmartGraphical is a pattern-based static analysis tool for detecting logical vulnerabilities in Solidity smart contracts. Unlike syntax-oriented scanners that target reentrancy and arithmetic errors, SmartGraphical focuses on business-logic flaws that arise from defective contract design rather than from incorrect code syntax. The tool combines automated heuristic detection with a graphical representation of a contract's functional dependencies, allowing a developer to inspect flagged code within its structural context before deciding whether a warning reflects a genuine issue.

# 

# This repository accompanies the paper \*SmartGraphical Detects Logical Vulnerabilities in Smart Contracts via Pattern-Based Static Analysis and Human-in-the-Loop Review\*, and contains the tool itself along with the benchmark data, comparison results, and supplementary material described in that paper.

# 

# \## How the Tool Works

# 

# SmartGraphical parses a Solidity source file and checks it against eleven heuristic categories, grouped into four broader concerns:

# 

# \*\*External dependency and state integrity.\*\* The tool flags critical values, such as total supply or fee parameters, that are derived from an external contract without adequate range checks, and it examines whether arbitrary mint or burn operations remain consistent with the contract's own accounting.

# 

# \*\*Transactional and economic logic.\*\* Deposit and withdrawal functions are checked for consistency, so that a user cannot withdraw more than a legitimate balance permits. Internal reward or point systems are checked for an earn-before-spend ordering. Asset transfers that depend on a price value are checked for the possibility that the price and the transfer become decoupled, which is the pattern behind many flash-loan and sandwich-attack exploits.

# 

# \*\*Computational and operational flaws.\*\* The tool highlights complex multi-step calculations for manual review, checks whether non-deterministic system calls such as low-level calls are handled with a logically sound error-recovery path, and flags public functions that alter critical state without an access-control modifier.

# 

# \*\*Semantic and maintenance errors.\*\* When a contract appears to be a rewrite of an earlier version, the tool checks whether function signatures still match across versions. It also flags variable or function names that are similar enough to one another that a developer could substitute one for the other by mistake.

# 

# Each of these checks produces a heuristic alert rather than a confirmed finding. The design assumption behind SmartGraphical is that a human reviewer, working from the tool's graphical representation of the contract, is far better positioned than an automated system alone to judge whether a given alert corresponds to a real logical flaw or to an intentional and safe design choice.

# 

# \## Usage

# 

# ```bash

# python SmartGraphical.py <path-to-contract>.sol

# ```

# 

# Running the script presents a menu of the eleven detection tasks described above, along with an option to run all tasks at once and an option to render the contract's dependency graph.

# 

# \## Repository Structure

# 

# | Path | Contents |

# |---|---|

# | `SmartGraphical.py` | The tool itself. |

# | `SimpleAuction.sol` | The worked example used throughout the paper to illustrate the tool's graphical output. |

# | `Test contracts.zip` | A small set of additional contracts used during development. |

# | `Benchmark/` | The full 100-contract benchmark dataset referenced in the paper, split into a training subset used to design the heuristics and a held-out subset reserved for evaluation. |

# | `SYFI-FORM.7z` | Source code for the two real-world case-study contracts (SYFI and FORM) discussed in the paper's case-study section, along with the raw output of Slither and Mythril when run directly against this code. |

# | `LLMs results/` | Raw, unedited output from Claude Sonnet 5 and Gemini Flash 3.5 when each model was given the held-out benchmark contracts and asked to identify security issues, with no prior knowledge of the reported vulnerability. |

# | `Tables results/` | The underlying spreadsheets for the detection-comparison and alert-precision tables reported in the paper, including the per-case reasoning behind each true-positive or false-negative classification. |

# | `Survey Results.zip` | Anonymized responses from the developer user study described in the paper. No names, contact details, or other personally identifiable information were collected at any stage of the study. |

# 

# \## Citation

# 

# If you use this tool or the accompanying data, please cite the paper:

# 

# ```bibtex

# @article{pishdar2026smartgraphical,

# &#x20; title   = {SmartGraphical Detects Logical Vulnerabilities in Smart Contracts via Pattern-Based Static Analysis and Human-in-the-Loop Review},

# &#x20; author  = {Pishdar, Mohammad and Fattahdizaji, Ali and Shukur, Zarina},

# &#x20; journal = {Scientific Reports},

# &#x20; year    = {2026}

# }

# ```

# 

# \## License

# 

# See the repository's license file for terms of use.

