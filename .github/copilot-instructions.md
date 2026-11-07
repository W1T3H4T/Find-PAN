# Copilot Instructions

## Project Guidelines
- The user expects precise regular expressions that encode the required data format rather than broad digit-only matching.
- Use pytest for configuration-processing tests in this repository.
- The baseline system's associated files belong under RegressionTests, and paths should be defined once rather than duplicated.
- When cleaning RegressionTests, retain files containing invalid PAN or invalid TRACK data, as well as baseline configuration files.
- Never bypass plyint errors or warnings; always address them.
- Address plyint recommendations, even if they are not explicitly requested by the user; all others should be raised to the user for confirmation before proceeding.
- 