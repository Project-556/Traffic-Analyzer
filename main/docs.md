# **Run the Program**

## **Dependencies**

To run the program, install the following dependencies:<br>
<br>

- `google-genai >= 1.0.0`  <br>
  Used for Gemini integration<br>
  <br>

- `python-dotenv`  <br>
  Used for loading API keys and other confidential configuration values<br>
<br><br>

## **Execution Syntax**

Use the following commands to run the program:

py main.py --input path/to/the/logs.json<br>
Runs the analyzer without AI-generated explanations.<br><br>

py main.py --input path.to/the/logs.json --explain<br>
Runs the analyzer with AI-generated explanations.<br><br>


# Future addition
We are actively working on removing the requirement for manually providing the input file path and plan to introduce automatic threat detection in future versions.<br>
This project was developed as a solo submission for the TechSprint Hackathon by Rachit Negi.<br>
The project will be open-sourced after the completion of the TechSprint Hackathon. Contributions will be welcome at that stage.<br>