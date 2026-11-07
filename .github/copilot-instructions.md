# Copilot Instructions

## Project Guidelines
- The user expects precise regular expressions that encode the required data format rather than broad digit-only matching.
- Use pytest for configuration-processing tests in this repository.
- The baseline system's associated files belong under RegressionTests, and paths should be defined once rather than duplicated.
- When cleaning RegressionTests, retain files containing invalid PAN or invalid TRACK data, as well as baseline configuration files.