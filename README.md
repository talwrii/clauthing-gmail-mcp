# Clauthing Gmail MCP — Selective Access

Give an LLM agent selective, read-only access to Gmail through MCP, with a
command-line interface for your own use. The agent requests a specific scope;
you approve it in your client's permission dialog (MCP elicitation).

This is AI-generated and unreviewed (including parts of the documentation).

## Install

Requires Python 3.11+ and [pipx](https://pipx.pypa.io/).

```bash
pipx install clauthing-gmail-mcp
```

## Set up Google access

Unfortunately, Google grants are set up for websites rather than individuals. You therefore must set up a "client" as though you were creating a website and then grant this app access to your data, as though you were using your website.

### Setting up your "website" (client) in Google Cloud

You need your own Google OAuth client. You only do this setup once.

1. Open [Google Cloud Console](https://console.cloud.google.com/). Use the
   project selector at the top to create or select a project.
2. Open the [Gmail API page](https://console.cloud.google.com/apis/library/gmail.googleapis.com)
   in that project and click **Enable**.
3. Open **Google Auth Platform → Branding**. If prompted, click **Get started**
   and enter an app name, support email, and contact email. For a personal
   Gmail account, choose **External** as the audience.
4. Under [Audience](https://console.cloud.google.com/auth/audience), leave the
   app in **Testing** and add your Google account under **Test users**. Use the
   exact email shown when you sign in. This lets you use your app without
   completing Google's public verification process.
5. Under **Data Access**, add the scope
   `https://www.googleapis.com/auth/gmail.readonly`.
6. Under [Clients](https://console.cloud.google.com/auth/clients), click
   **Create client**, choose **Desktop app**, and create it. Copy its client ID
   and client secret, or download its JSON credentials.

You then give these "website" details to `clauthing-gmail-mcp`. `clauthing-gmail-mcp` then immediately asks Google to provide "your website" with this data.

```bash
clauthing-gmail-mcp auth --client-id 'YOUR_CLIENT_ID' --client-secret 'YOUR_CLIENT_SECRET'
```

Complete Google sign-in in the browser. If it requests access to localhost,
allow it so the login can finish. Credentials and login tokens are saved;
subsequent commands reuse them and refresh access tokens automatically.

Check that it works:

```bash
clauthing-gmail-mcp top
```

If you need to sign in again, run `clauthing-gmail-mcp auth` without the
credentials arguments. Google apps in Testing have refresh tokens that expire
after seven days for Gmail access.

See Google's [OAuth setup guide](https://developers.google.com/workspace/gmail/api/quickstart/python)
and [test-user guidance](https://support.google.com/cloud/answer/15549945).

## Connect your agent

For Codex:

```bash
codex mcp add clauthing-gmail -- clauthing-gmail-mcp mcp
```

For another MCP client, configure `clauthing-gmail-mcp` as the command and
`mcp` as its argument. If the client cannot find the executable, use its full
path (`command -v clauthing-gmail-mcp`). The client needs form elicitation
support to show approval dialogs.

Restart your client after registration. The MCP starts its own broker and
creates its client identity automatically; no separate server command is
needed. [Codex MCP configuration](https://learn.chatgpt.com/docs/extend/mcp).

## Choose what the agent can access

For example, ask your agent to find recent Anthropic login emails. It proposes
a name and scope, such as **Anthropic login emails**: list headers from
`*@anthropic.com` received within the last ten minutes. Review the actual
sender pattern and operation before approving.

Choose one of:

| Choice | What happens |
| --- | --- |
| **Precisely once** | Allow one matching list or read call. |
| **Ask each time** | Save the named scope; confirm each use with **Yes / No**. |
| **Allow automatically** | Choose a duration in a second dialog, defaulting to **1 hour**. Enter values such as `30m`, `2h`, or `7d`. |
| **Deny access** | Optionally explain why in a second dialog. The agent receives your reason and can request narrower access. |

Listing exposes IDs and From, Subject, Date, and received timestamps. Reading
bodies requires a separate read scope. The age filter keeps rolling: “last ten
minutes” always means the most recent ten minutes, independently of how long
permission lasts. Sender patterns match addresses, not display names.

The agent uses the returned `access` ID for subsequent `list_messages` or
`read_message` calls. The name labels the approved scope; changing its sender,
age, or operation requires a new approval.

Cancelling grants nothing. Cancelling a denial-reason prompt still denies.
An unused one-use approval expires silently after ten minutes; a failed mail
fetch still consumes it. Without elicitation, requests remain pending for
manual CLI approval.

## Command line

Read the newest email directly, without agent permission prompts:

```bash
clauthing-gmail-mcp top
clauthing-gmail-mcp top --json
```

Manage the current directory's agent permissions:

```bash
clauthing-gmail-mcp grants
clauthing-gmail-mcp revoke grant GRANT_ID
clauthing-gmail-mcp clients
clauthing-gmail-mcp revoke client CLIENT_ID
clauthing-gmail-mcp requests
clauthing-gmail-mcp approve REQUEST_ID --for 1h
clauthing-gmail-mcp audit
```

Use `clauthing-gmail-mcp --help` or a subcommand's `--help` for other options.
The optional `serve` command provides a local HTTP broker for standalone
permission-controlled CLI clients. Per-use elicitation requires the default
embedded MCP broker.

## Storage and access boundaries

The Google login is shared across projects. Agent permissions and client tokens
are separate for each resolved MCP process directory, stored outside the
workspace:

```text
~/.config/clauthing-gmail-mcp/oauth-client.json
~/.local/share/clauthing-gmail-mcp/google-token.json
~/.local/share/clauthing-gmail-mcp/projects/<directory-name>-<hash>/
    policy.sqlite
    client.token
```

Run `clauthing-gmail-mcp paths` to see the selected locations. `--state` overrides
policy storage; `--auth-state` overrides login storage. XDG config and data
paths are respected. The owner CLI must run in the same directory as the MCP
to select the same permissions by default.

Google grants this application mailbox-wide **read-only** access; the broker
enforces the narrower scopes exposed to the agent. The MCP host is trusted to
relay your approval responses. An agent with filesystem access to the Google
tokens, policy database, or owner CLI can bypass those restrictions. Keeping
files outside the workspace does not itself isolate them; enforce that boundary
with your sandbox or OS permissions.

No sending, deleting, marking as read, or attachment-download tools are exposed.
Message bodies are returned as untrusted text or HTML, capped at 20,000
characters. Lists scan at most 1,000 candidates and report when that limit is
reached. Revocation blocks future access; it cannot retract content already
returned.

## Development

For an editable checkout install:

```bash
pipx install --editable .
python3 -m unittest discover -s tests
```

`demo-mail.json` supplies fake mail for `serve --fixture demo-mail.json`.
