# Clauthing Gmail MCP — Selective Access

A local read-only Gmail broker, JSON CLI, and stdio MCP adapter. Clients get
their own revocable bearer token. The broker keeps Google credentials and
saved permissions separately. Prototype: tested with synthetic mail; real
Google authentication and a real MCP host have not yet been exercised.

## First workflow

1. Ask to **list** messages from `*anthropic*` received in the last ten minutes.
2. Choose Precisely once, Ask each time, Allow automatically, or Deny access.
3. See only message IDs, From, Subject, Date, and received timestamps.
4. Discover the actual sender address.
5. Separately ask to **read** messages from that exact address. That grant can
   have a different message-age limit and permission lifetime.

The example wildcard is deliberately broad discovery, not an assertion about
Anthropic's real sending addresses. Patterns use shell-style glob syntax on
the parsed From address, case-insensitively. Display names do not count. A From
match is not a cryptographic guarantee of sender identity.

**Message age and permission lifetime are independent:** a saved list grant
with a 10-minute age limit always shows only the most recent ten minutes. A
15-minute read grant with no age limit can read matching historical messages
for fifteen minutes. Read does not imply list, or vice versa. Pass the returned `access` ID to select the approved scope. Without an ID,
legacy automatic grants combine by union within the operation; ask-each-time
rules require explicit selection and confirmation.

## Connect Gmail

Requires Python 3.11+ and pipx. Google's OAuth library is installed automatically.
Core policy, demo, and tests use the standard library.

Install from the parent workspace (editable so source changes are picked up):

```bash
pipx install --editable ./clauthing-gmail-mcp
```

Enable the [Gmail API](https://console.cloud.google.com/apis/library/gmail.googleapis.com)
in your Google project and create a dedicated **Desktop app** OAuth client.
Then authenticate:

```bash
clauthing-gmail-mcp auth --client-id YOUR_CLIENT_ID --client-secret YOUR_CLIENT_SECRET
```

This saves the client ID and secret in
`~/.config/clauthing-gmail-mcp/oauth-client.json` (file mode `0600`, directory
mode `0700`), then opens Google's browser consent for **gmail.readonly only**.
`XDG_CONFIG_HOME` is respected; `auth --config-dir PATH` overrides the directory.
These are this tool's own credentials; rclone configuration is never read.
Once saved, reuse the login without re-entering credentials or opening a browser:

```bash
clauthing-gmail-mcp auth
```

Access and refresh tokens are cached locally. Expired access tokens refresh
automatically. `auth --reauth` forces a new browser sign-in; revoked/expired
refresh tokens also require sign-in. Network refresh failures preserve the
saved login and report an error rather than forcing browser consent.

Alternatively, `auth --credentials /path/to/desktop-oauth.json` imports and saves
the Desktop OAuth registration. Both ID and secret must be supplied together
when setting/replacing the pair. They are saved before browser consent, so a
cancelled login can be retried. Command arguments may be retained in shell
history/process listings; JSON-file import avoids putting the secret in argv.

The `mcp` command creates its private client identity on first launch and runs
its permission broker inside the MCP process. No `client-add` or separate
`serve` command is needed for MCP. Existing identities are reused, including
revoked identities: restarting never grants access or resets permissions.
Google authentication is separate; the MCP can start and advertise tools before
login, but reading approved mail requires `auth` first.

For the standalone HTTP CLI, the optional setup remains:

```bash
clauthing-gmail-mcp client-add codex
clauthing-gmail-mcp serve
```

This broker listens on `127.0.0.1:8767`. To connect the MCP adapter to it instead
of using the embedded broker, use `mcp --external-broker`.

Google's Testing-mode refresh tokens can expire after seven days. Do not put
OAuth credentials, client tokens, or owner state into version control. The
Google token is stored in `~/.local/share/clauthing-gmail-mcp/google-token.json`
and is shared across projects. Policies and client tokens are stored separately
for each current directory, outside the workspace:

```text
~/.local/share/clauthing-gmail-mcp/projects/home-user-project-<hash>/
  policy.sqlite
  client.token
```

The readable name and hash come from the resolved current directory of the
process. Symlink aliases share a policy; different paths get separate policies.
Run `clauthing-gmail-mcp paths` to see the selected paths without creating files.
The broker, owner CLI, and MCP adapter must start in the same directory to use
the same defaults. This uses the MCP process directory; it does not discover a
separate Codex workspace directory. No `cwd` configuration is required here.
`--state` overrides policy storage, `--auth-state` overrides Google login storage;
`XDG_DATA_HOME` and `XDG_CONFIG_HOME` are respected. Existing global policy files
are not automatically migrated. Only one broker can use a given port at once.

For MCP, configure the installed executable in your host, substituting your
actual home directory for `/home/YOU`:

```toml
[mcp_servers.clauthing-gmail]
command = "/home/YOU/.local/bin/clauthing-gmail-mcp"
args = ["mcp"]
```

Reconnect/restart the MCP host as required. No separate broker is needed.

## CLI

For direct owner use, fetch the newest email with the shared Google login:

```bash
clauthing-gmail-mcp top
clauthing-gmail-mcp top --json
```

`top` prints headers and the body (up to 20,000 characters), or JSON with
`--json`. It requires only the saved OAuth login: no client token, broker, or
permission prompts. It fetches the first message in Gmail's normal mailbox
listing (which excludes spam and trash). It does not change read/unread state.
This is an owner command and is not exposed as an MCP tool. Any process with
access to the owner CLI and Google credentials can use it.


From this project directory, use `python3 -m clauthing_gmail_mcp` or the
installed `clauthing-gmail-mcp` command (`clauthing-gmail` remains an alias).
Client options precede the subcommand.

```bash
# Request permission without accessing any mail.
clauthing-gmail request list --sender '*anthropic*' --last 10m

# Owner reviews requests and approves the exact stored scope.
clauthing-gmail requests
clauthing-gmail approve REQUEST_ID --for 15m

# Client lists permitted headers; filters can narrow but never widen grants.
clauthing-gmail list --sender '*anthropic*' --last 10m

# Separate read request for a discovered address, any message age.
clauthing-gmail request read --sender 'actual-sender@example.com'
clauthing-gmail approve REQUEST_ID --for saved
clauthing-gmail read MESSAGE_ID

# Owner administration.
clauthing-gmail clients
clauthing-gmail grants
clauthing-gmail revoke grant GRANT_ID
clauthing-gmail revoke client CLIENT_ID
clauthing-gmail audit
```

The project token is selected automatically. Override it with `--token-file`
or `CLAUTHING_GMAIL_TOKEN`.
Client tokens are hashed in the policy database; the bearer value is written
only to the token file. A token remains stable while grants change.

## Elicitation and trust boundary

MCP exposes only `request_access`, `list_messages`, and `read_message`.
The HTTP client API has **no grant/approve/revoke operations**. An ordinary
client token cannot grant itself access.

For elicitation, launch the MCP adapter as a **trusted owner-side process**:

```bash
clauthing-gmail mcp
```

When the host advertises elicitation, the adapter sends an `elicitation/create`
form describing the immutable requested operation, sender pattern, and age.
The client supplies a descriptive name with `request_access`; the approval
prompt displays it together with the exact scope, without asking you to fill
in a name. The first form offers four choices:

- **Precisely once:** one matching list or read call. Anonymous; no duration
  follow-up. It silently expires if unused for ten minutes. Consumption is
  atomic across processes and happens before provider I/O, so a failed backend
  call still uses the approval.
- **Ask each time:** save the reviewed scope and its name until revoked. Each
  selected use opens a Yes/No confirmation naming the rule and operation,
  without repeating the scope settings. Confirmation is per tool call. List
  and read remain separate permissions. Denying a use leaves the named rule
  available for future requests.
- **Allow automatically:** opens a separate duration form prefilled with `1h`.
  Enter intervals such as `30m`, `2h`, `7d`, or `1 hour`. Cancelling or entering
  an invalid interval saves no grant. Access expires after the selected period.
- **Deny access:** records the denial and opens an optional reason form. The
  reason is returned to the agent so it can consider narrower access.

The host's native Decline action also opens the reason form. Cancelling the
initial prompt opens no follow-up. Skipping the reason prompt still denies;
reasons are returned directly rather than saved in policy. No passwords, login
codes, or OAuth tokens are requested. Unsupported elicitation and timeouts grant
nothing. `mcp --no-elicitation` leaves requests for manual owner approval.

`request_access` requires a client-supplied `name` in its tool schema. Its approval result
contains an `access` ID, `name`, and `mode`. Use the ID with subsequent tools:

```json
{"name": "list_messages", "arguments": {"access": "ACCESS_ID", "limit": 20}}
```

The ID selects the exact stored operation, sender, and rolling age; names are
labels, not authorization. Broader filters cannot widen that rule. A changed
scope requires another approval. Existing policies migrate with their previous
automatic behavior intact. CLI duration-based owner grants remain available.
Ask-each-time confirmation requires the default embedded MCP broker; the
standalone HTTP broker cannot approve uses and denies those rules. Automatic
and one-use rules work with both transports.

**The MCP host and owner-side adapter are trusted to relay real human
responses.** An arbitrary host can forge its own elicitation responses. The
adapter's owner state is therefore privileged: never give its filesystem
access to an untrusted client, agent shell, or an untrusted MCP host. An agent
that can read Google credentials or edit policy/source files can bypass this
broker. File modes alone do not isolate processes running as the same OS user;
use an OS sandbox/separate account/container and protect owner state, adapter
code, and dependency files. This prototype does not configure that isolation.

Google enforces mailbox read-only access using `gmail.readonly`. Our broker
enforces selective disclosure. It checks expiry and revocation on each call
and again before returning data. Revocation cannot retract content already
returned or cached by a client. The broker must access metadata internally to
filter sender/age, even when that metadata is not disclosed to a client.

## Limits

- Local loopback HTTP broker only; bearer tokens must not be exposed remotely.
- No send, delete, archive, label changes, mark-as-read, thread expansion, or
  attachment-download tools. Bodies are returned as untrusted text/HTML data,
  never rendered; capped at 20,000 characters.
- Listing scans at most 1,000 candidate messages, newest window first as
  returned by Gmail; `scan_limit_reached` reports possible incomplete results.
  There is no promise of a complete historical inbox listing.
- Temporary grants are time-based, not single-use. Saved grants last until
  revoked. No background mailbox export or message-body disk cache.
- Synchronous requests; each default MCP process embeds its own broker. Account selection is through the
  owner's Google sign-in; separate state directories separate accounts.
- Elicitation implementation uses the 2025-06-18 form schema; older clients
  fall back to CLI approval. Native Codex integration is not configured yet.

## Offline demo and verification

```bash
python3 -m unittest discover -s tests -v
python3 -m clauthing_gmail_mcp --state .state client-add demo --out .state/client.token
python3 -m clauthing_gmail_mcp --state .state serve --fixture demo-mail.json
```

In another terminal, use the same CLI flow with `--state .state` for owner
commands and `--token-file .state/client.token` for client commands. Use sender
`*@anthropic.example` for the fake login message. This directory contains fake
mail only; do not treat the workspace-local demo state as isolated credentials.

The tests exercise list/read separation, sender and rolling-age filtering,
expiry/revocation, cross-client isolation, non-disclosure on denial, saved
grants, and a real stdio elicitation request/response exchange with fake mail.

## Prior art

Existing tools cover much of ordinary Gmail access; these were surveyed rather
than audited: [klodr/gmail-mcp](https://github.com/klodr/gmail-mcp),
[your-mail-mcp](https://github.com/wildsurfer/your-mail-mcp), and
[GigaMail](https://github.com/adecubed/gigamail). This prototype explores the
separate list/read sender-and-age permission workflow instead.

References: [Gmail scopes](https://developers.google.com/workspace/gmail/api/auth/scopes),
[Google desktop OAuth](https://developers.google.com/identity/protocols/oauth2/native-app),
[MCP elicitation](https://modelcontextprotocol.io/specification/2025-06-18/client/elicitation).
