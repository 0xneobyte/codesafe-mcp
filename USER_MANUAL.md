# CodeSafe MCP - User Manual

Group E

## Table of Contents

1. [Introduction](#1-introduction)
2. [Prerequisites](#2-prerequisites)
3. [Installation Instructions](#3-installation-instructions)
4. [Running the Program](#4-running-the-program)
5. [Using the Tools](#5-using-the-tools)
6. [Troubleshooting](#6-troubleshooting)

---

## 1. Introduction

CodeSafe MCP is a security helper for AI coding assistants like Claude Code. When an AI assistant writes code for you, it can sometimes make mistakes that create security problems. For example, it might write code with a hidden password, or it might tell you to install a package that does not really exist.

CodeSafe MCP connects to the AI assistant and gives it six tools it can call automatically while it writes code for you:

1. **analyze_security** - Checks a piece of code for common security problems, such as SQL injection or missing input checks.
2. **scan_secrets** - Looks for hardcoded passwords, API keys, and tokens left in your code, including in old git history.
3. **audit_dependencies** - Checks your project's dependencies (like `package.json`) for known security bugs.
4. **verify_package_safety** - Checks if a package name is real and safe before it gets installed. This stops fake or copycat packages.
5. **get_security_docs** - Answers security questions in plain language, using a knowledge base of official security documentation.
6. **setup_codesafe_enforcement** - Sets up a project one time so that unsafe package installs get blocked automatically for everyone on the team.

The project has two parts:

- A **MCP server** written in TypeScript. This is the part that plugs into your AI assistant. It runs on your own computer.
- A **backend server** written in Python (FastAPI). This part only powers the `get_security_docs` tool. It answers security questions using Google Gemini.

You do not need to be a security expert to use this program. Just follow the steps below.

---

## 2. Prerequisites

Before you start, make sure you have the following installed on your computer.

### Required for everyone

- **Node.js** version 18 or newer. This runs the main MCP server.
  - Check by opening a terminal and typing: `node -v`
- **npm** (comes bundled with Node.js).
  - Check by typing: `npm -v`
- **Git**, so you can download the project and use the git-history scan feature.
- **Claude Code** (or another MCP-compatible AI assistant) installed and working.

### Required only if you want the get_security_docs tool

- **Python** version 3.10 or newer.
  - Check by typing: `python3 --version`
- **pip** (comes bundled with Python).
- A **Google Gemini API key**. You can get one for free from Google AI Studio.

If you only want tools 1 to 4 and 6 (code scanning, secret scanning, dependency checks, package safety, and enforcement setup), you do **not** need Python or a Gemini key. Only the `get_security_docs` tool needs the backend server.

---

## 3. Installation Instructions

### Step 1: Get the project files

If you received this project as a ZIP file, unzip it first.

- On Windows: right click the ZIP file and choose "Extract All".
- On Mac: double click the ZIP file.
- On Linux: run `unzip codesafe-mcp.zip` in a terminal.

If you are using git instead, clone the repository:

```
git clone https://github.com/0xneobyte/codesafe-mcp.git
cd codesafe-mcp
```

### Step 2: Install the MCP server

Open a terminal inside the `codesafe-mcp` folder and run:

```
npm install
```

This downloads the small number of libraries the server needs.

### Step 3: Build the server

The server is written in TypeScript, so it needs to be compiled into plain JavaScript before it can run.

```
npm run build
```

If this step finishes with no red error text, it worked. You will now see a new `build` folder appear.

### Step 4 (optional): Set up the backend for get_security_docs

Skip this step if you do not need the `get_security_docs` tool.

1. Open a terminal inside the `backend` folder:

   ```
   cd backend
   ```

2. Create a virtual environment. A virtual environment keeps this project's Python packages separate from everything else on your computer.

   ```
   python3 -m venv venv
   ```

3. Turn on the virtual environment.

   - On Mac or Linux:
     ```
     source venv/bin/activate
     ```
   - On Windows:
     ```
     venv\Scripts\activate
     ```

4. Install the required packages.

   ```
   pip install -r requirements.txt
   ```

5. Create your settings file by copying the example file.

   - On Mac or Linux:
     ```
     cp .env.example .env
     ```
   - On Windows:
     ```
     copy .env.example .env
     ```

6. Open the new `.env` file in a text editor and fill in the values:

   ```
   ENVIRONMENT=development
   GEMINI_API_KEY=paste-your-gemini-key-here
   GEMINI_STORE_ID=
   GEMINI_MODEL=gemini-2.5-flash
   BACKEND_API_KEY=pick-any-long-random-text
   ADMIN_TOKEN=pick-a-different-long-random-text
   ```

   Leave `GEMINI_STORE_ID` empty for now. You will fill it in after you upload some security documents (see Step 5).

### Step 5 (optional): Upload security documents

The `get_security_docs` tool needs some documents to search through before it can answer questions. Sample documents are already included in the `backend/docs` folder.

First, create a new File Search Store. From inside the `backend` folder, with your virtual environment still turned on, run:

```
python -c "import os; from dotenv import load_dotenv; from google import genai; load_dotenv(); c = genai.Client(api_key=os.getenv('GEMINI_API_KEY')); s = c.file_search_stores.create(config={'display_name': 'codesafe-docs'}); print(s.name)"
```

This prints a store ID that looks like `fileSearchStores/xxxxxxxx`. Copy that value into the `GEMINI_STORE_ID` line in your `.env` file now.

Next, upload the documents into that store:

```
python scripts/upload_docs.py --docs ./docs --store fileSearchStores/xxxxxxxx
```

Replace `fileSearchStores/xxxxxxxx` with the store ID you copied above.

---

## 4. Running the Program

### Start the backend (only if you set it up in Step 4 above)

From inside the `backend` folder, with the virtual environment turned on, run:

```
uvicorn main:app --host 127.0.0.1 --port 8000
```

Leave this terminal window open while you work. To check it is running, open a new terminal and type:

```
curl http://127.0.0.1:8000/health
```

You should see a reply like `{"status":"ok", ...}`.

### Connect the MCP server to your AI assistant

The project includes a ready-made `.mcp.json` file that tells Claude Code how to start the server. Open that file and check the path matches where you placed the project on your computer:

```json
{
  "mcpServers": {
    "codesafe": {
      "type": "stdio",
      "command": "node",
      "args": ["/full/path/to/codesafe-mcp/build/index.js"],
      "env": {
        "CODESAFE_BACKEND_URL": "http://localhost:8000",
        "CODESAFE_API_KEY": "the-same-value-as-BACKEND_API_KEY-in-backend/.env"
      }
    }
  }
}
```

Then open Claude Code inside your own project folder (the folder where you want the security checks to run, not necessarily inside `codesafe-mcp` itself). Claude Code will read `.mcp.json` and start the CodeSafe server automatically the next time you use it. You do not need to run the MCP server by hand.

### Quick manual check (optional)

If you want to confirm the server itself starts correctly without Claude Code, run:

```
npm start
```

You should see this message printed:

```
CodeSafe MCP server running on stdio
```

Press `Ctrl+C` to stop it.

---

## 5. Using the Tools

Once everything is connected, you do not need to call the tools yourself. While you chat with Claude Code and ask it to write code, it will call the right CodeSafe tool automatically. For example:

- Ask it to "build a login API route" and it will call `get_security_docs` and `analyze_security` before and after writing the code.
- Ask it to "add the axios package" and it will call `verify_package_safety` first.
- Ask it to "scan my project for leaked secrets" and it will call `scan_secrets` with the `directory` option.

If you want every teammate's copy of Claude Code to always check packages before installing them, ask Claude Code to run the one-time setup tool:

```
Run setup_codesafe_enforcement on this project.
```

This writes a small rule file and a hook script into your project. Commit these generated files to git so the protection applies to your whole team, not just your own computer.

---

## 6. Troubleshooting

**Problem: `npm run build` shows errors.**
Make sure you ran `npm install` first, and that your Node.js version is 18 or newer (`node -v`).

**Problem: Claude Code does not seem to see the CodeSafe tools.**
Check that the file path inside `.mcp.json` is correct and points to `build/index.js` on your own computer. Also make sure you ran `npm run build` so that the `build` folder actually exists.

**Problem: `get_security_docs` returns an error about `CODESAFE_BACKEND_URL`.**
This means the MCP server does not know where your backend is. Check the `env` section inside `.mcp.json` and make sure `CODESAFE_BACKEND_URL` and `CODESAFE_API_KEY` are set.

**Problem: `get_security_docs` returns "No File Search Store configured".**
This means you have not uploaded any documents yet, or you forgot to copy the store ID into `backend/.env`. Go back to Step 5 in the Installation section.

**Problem: The backend will not start, or shows "ModuleNotFoundError".**
This usually means your virtual environment is not turned on, or the packages were not installed. Run `source venv/bin/activate` (or `venv\Scripts\activate` on Windows) and then `pip install -r requirements.txt` again.

**Problem: `verify_package_safety` or `audit_dependencies` seem slow or fail.**
These two tools need an internet connection because they check real package registries (npm, PyPI) and a vulnerability database (OSV.dev). Check your internet connection and try again.

**Problem: I get a 401 "Invalid API key" error from the backend.**
The `CODESAFE_API_KEY` value in `.mcp.json` must exactly match the `BACKEND_API_KEY` value in `backend/.env`. Copy one over the other so they match exactly.

---

*This manual covers setup and basic use only. For a full list of every option each tool accepts, see the files inside the `docs` folder.*
