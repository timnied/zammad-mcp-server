# Running behind a gateway: profiles, on-behalf-of, internal notes

This describes the hardened mode used for the internal deployment: the MCP server runs in
a container next to agentgateway; the gateway authenticates the user (Entra ID), the
server talks to Zammad with **one service account** and acts **on behalf of the real user**.

```
Claude Desktop -> bridge -> nginx (TLS) -> agentgateway (validates Entra token, sets x-mcp-user)
                                              |  plain HTTP, internal Docker network only
                                              v
                                        zammad-mcp (this server)
                                              |  HTTPS + service token + X-On-Behalf-Of: <user>
                                              v
                                           Zammad
```

## 1. What the model may do

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCP_PROFILE` | `helpdesk` | `readonly`: only read tools. `helpdesk`: reads plus create/update ticket, create article, tags, link tickets. `full`: everything (old behaviour). |
| `MCP_ALLOWED_TOOLS` | unset | Explicit allow-list (names or `fnmatch` patterns). When set, everything else is denied. |
| `MCP_DENIED_TOOLS` | unset | Extra deny list (names or patterns). Deny always wins. |
| `MCP_ARTICLE_POLICY` | `internal_only` (`any` in profile `full`) | `internal_only` forces every article, including the first article of a new ticket, to be an internal note without recipients. |
| `MCP_OUTBOUND_MAIL` | `off` | `on` exposes the two mail tools `send_ticket_mail` and `create_ticket_with_mail` (see below). Only affects profile `helpdesk`; `readonly` never has them, `full` always does. |
| `MCP_MAIL_MAX_RECIPIENTS` | `10` | Maximum recipients (`to` plus `cc`) per mail. `0` disables the limit. |
| `MCP_MAIL_RATE_LIMIT_PER_MINUTE` | `10` | Mails per minute and user (separate from the general call limit). `0` disables the limit. |
| `MCP_DEFAULT_PERMISSION` | `write` | Existing permission level; profiles and lists are applied on top. |

Blocked in `readonly` and `helpdesk`: `delete_ticket`, `delete_user`, `delete_organization`,
`merge_tickets` (destructive) and `create_user`, `update_user`, `create_organization`,
`update_organization`, `create_group` (change who exists in Zammad). Neither the allow-list
nor `MCP_DEFAULT_PERMISSION=admin` re-enables them; use `MCP_PROFILE=full` for that.

### Sending e-mail from tickets

`create_article` and `create_ticket` stay internal-note-only (`MCP_ARTICLE_POLICY=internal_only`);
the model cannot turn them into outbound mail through a parameter. E-mail goes out only
through two dedicated tools, available when `MCP_OUTBOUND_MAIL=on`:

- `send_ticket_mail(ticket_id, to, body, subject?, cc?)`: any mail from within an existing
  ticket (reply or not). Subject defaults to the ticket title.
- `create_ticket_with_mail(title, group, to, body, subject?, cc?, customer?, state?, priority?, pending_time?)`:
  creates a ticket whose first article is the sent mail. The customer defaults to the first `to` address.

Rules enforced by the server: recipients are arbitrary plain addresses (no domain list),
validated strictly (no display names, line breaks, quotes); no BCC, no attachments, plain
text only; at most `MCP_MAIL_MAX_RECIPIENTS` recipients; `MCP_MAIL_RATE_LIMIT_PER_MINUTE`
mails per minute and user (only requests that passed validation count); group and
ticket scope (`MCP_ALLOWED_GROUPS`) still apply; every mail is logged as `outbound_mail`
with the acting user, recipients and ticket. Enabling mail does not unlock any destructive
tool. Behind agentgateway the tool names carry the `zammad_` prefix; allow them only for
the roles that may send mail. Zammad hands the mail to the group's mail channel, so
delivery is not confirmed by the tool result.

Zammad prerequisites: the group needs a sender address (outgoing mail channel), and the
acting user needs agent rights on that group. Test with a ticket addressed to yourself first.

Blocked tools are removed from `tools/list` (the model never sees them) **and** refused if
called anyway. The old deny-list bug (denied tools still passed the write check) is fixed
at its root: `can_read`/`can_write`/`can_admin` now include the deny decision.

`get_allowed_tools` reports what is active. The startup log lists blocked tools.

## 2. Who is acting (`X-On-Behalf-Of`)

| Variable | Default | Meaning |
| --- | --- | --- |
| `MCP_OBO_SOURCE` | `none` | `header`: identity from a request header. `jwt`: identity from a claim of the Bearer token. `none`: calls run as the service account. |
| `MCP_OBO_HEADER` | `x-mcp-user` | Header name for `header` mode. |
| `MCP_OBO_JWT_CLAIMS` | `preferred_username,upn,email` | Claim order for `jwt` mode. |
| `MCP_OBO_ALLOWED_DOMAINS` | unset | Only accept identities of these email domains. |
| `MCP_OBO_LOWERCASE` | `false` | Lower-case the identity before sending it. |
| `MCP_OBO_PROXY_SECRET` | unset | If set, requests must carry this value in `x-mcp-proxy-secret`. |

Rules the code enforces:

- The identity comes from the HTTP request, **never from a tool argument**, so a prompt-injected model cannot choose whom to impersonate.
- **Fail closed.** If on-behalf-of is on and the request has no valid identity, nothing is sent to Zammad. There is no fallback to the service account. This includes stdio (no HTTP request), so use HTTP when on-behalf-of is on.
- The identity must look like a login/email (no spaces, commas, quotes or control characters). A header that appears twice is rejected, so a client-forged `x-mcp-user` next to the gateway's own cannot win.
- The header is resolved on **every** Zammad call and never stored on the shared client. Caches (groups, states, priorities) are kept per user, and the rate limit is per user.
- The `mcp_access` audit log line contains the user: `{"tool": "create_article", "allowed": true, "client": {"user": "alice@example.com"}}`. Set `MCP_LOG_LEVEL=WARNING` to quiet it.

**Trust boundary.** The server does not validate signatures. Anyone who can reach port 8000 can claim any identity. Therefore: no `ports:` mapping, only the gateway's Docker network, and the gateway sets the header itself. `MCP_OBO_PROXY_SECRET` is a second lock for the case that another container on that network misbehaves. Do not use `jwt` mode unless the gateway forwards the already validated token; the payload is only decoded here.

### Zammad side

- Create a dedicated service account and an access token (Profile -> Token Access). Zammad's API docs state that acting on behalf of another user requires the **`admin.user`** permission for the account that makes the call. That is a powerful permission (user administration): keep the token in a secret file, reachable only from this container.
- With on-behalf-of the request runs with the impersonated user's rights. Read-only at Zammad level is therefore not possible this way; the profile and allow-list in this server are the guard rail for the model. Zammad's history shows the impersonated user as the actor (verify once in your instance, see section 4).
- The Entra identity sent in `x-mcp-user` must equal the user's Zammad **login or email**. A user without a Zammad account gets a Zammad error, not a fallback.

## 3. Deployment

`deploy/compose.agentgateway.yaml` builds the image from `uv.lock` (reproducible), runs it as
an unprivileged user, read-only, without capabilities and **without a published port**, and
reads the Zammad token and the proxy secret from files (`ZAMMAD_HTTP_TOKEN_FILE`,
`MCP_OBO_PROXY_SECRET_FILE`). With a public CA (e.g. GlobalSign) nothing is needed. For an internal CA see the commented `SSL_CERT_FILE` and `ca/` lines in the compose file.
`deploy/agentgateway-target.snippet.yaml` shows the gateway side.

## 4. Acceptance checklist on the real system

1. `docker compose up -d --build`; `docker logs zammad-mcp` shows `profile=helpdesk ... on_behalf_of=header` and the blocked tools.
2. From the gateway host: `curl` without `x-mcp-user` -> tool call fails with "No caller identity".
3. Through Claude with your own account: `get_current_user` returns **you**, not the service account.
4. Add an internal note via Claude; in Zammad the article is internal and its author is **you**.
5. Ask Claude to delete or merge a ticket: the tools are not offered.
6. Forged header: send your own `x-mcp-user: someone@else` through the gateway; the call must fail (duplicate) or carry your identity, never the forged one.

## 5. Tested / not tested

Tested (automatically, `tests/`): profile and allow-list logic including the deny-list regression; the real HTTP server against a fake Zammad: hidden and blocked tools, `X-On-Behalf-Of` per request and under concurrency, no identity / invalid / duplicate / wrong domain / missing proxy secret, no identity through tool arguments or client-sent `X-On-Behalf-Of`, internal-note enforcement, JWT mode, secret files, internal CA via `SSL_CERT_FILE`.

Not tested here: the Docker image build itself (Docker Hub was not reachable from the build sandbox; the same steps were run with `uv sync --frozen` and the container command as an unprivileged user), a real Zammad instance (permission needed for `X-On-Behalf-Of`, history attribution, how Zammad evaluates rights for the impersonated user), and the agentgateway transformation snippet.
