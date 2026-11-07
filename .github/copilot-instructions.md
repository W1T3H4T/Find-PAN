# Copilot Instructions

## Project Guidelines
- The user expects precise regular expressions that encode the required data format rather than broad digit-only matching.
- Use pytest for configuration-processing tests in this repository.
- The baseline system's associated files belong under RegressionTests, and paths should be defined once rather than duplicated.
- Avoid blocking terminal commands when commands may hang; run them in the background and monitor with a timeout.