# Action firewall (`action.firewall`)

The action firewall stops Cracky from approving refunds, restricted coupons, data exports and
order changes that the logged-in user is not allowed to make. It targets the
**LLM03 - Overpowered Assistant** lab (`llm03-3`, OWASP LLM06 Excessive Agency in the 2025 list).

The rule it enforces: permissions are checked in code, outside the model. A prompt can change what
the model says. It cannot change the user row behind the JWT, the orders that user owns, or the
coupon table.

Code: `app/defense/controls/action_firewall.py`. Tests: `tests/test_action_firewall.py`.

## How it works

The control runs at defense Levels 1 and 2 on the `chat.cracky` surface, at two points:

1. **Input**: before the message reaches the model. A request like "refund order #1003" is
   checked here, so a blocked request never reaches Mistral.
2. **Output**: before the reply is shown. A reply that claims "I've processed a refund for
   order #1003" is checked here and replaced if the action is not allowed.

At each point it detects the action, checks it against the policy below, and returns one decision:
**allow**, **confirm** (a member of staff must approve; nothing has happened yet) or **block**
(the text is replaced with a refusal). Every decision on a detected action is appended to
`logs/action_firewall_audit.jsonl`.

## Switching it on and off

Level 0 never runs it: Level 0 stays vulnerable on purpose.

| Setting | Effect |
| --- | --- |
| `ACTION_FIREWALL_ENABLED=1` (default) | Firewall runs at Levels 1 and 2 |
| `ACTION_FIREWALL_ENABLED=0` | Firewall is listed but passes everything through |

The setting is read when the backend starts, so restart the backend after changing it.
For the demo: stay at Level 1, run the attack with the firewall off, restart with it on,
run the same attack again.

## Policy

"Owned" means the order's `user_id` in the database matches the logged-in user.

| Action | Customer | Staff (`is_staff`) |
| --- | --- | --- |
| Refund an order | Own order, delivered or shipped, at most $250 and at most what was paid → confirm. Anything else → block | Confirm. Amount over what was paid → block |
| Apply a coupon | Coupon open to everyone → allow. Staff or admin coupon, or unknown code → block | Public and staff coupons → allow. Admin coupon or unknown code → block |
| Export customer data | Own data → confirm. Other customers → block | Confirm |
| Change order status | Cancel own pending order → confirm. Anything else → block | Confirm |
| Other customers' orders, emails or data | Block | Allow |
| No identity available | Block | Block |

## Limitations

What the firewall does not catch, or gets wrong:

- **Detection uses patterns, not understanding.** Misspellings ("rfund"), other languages,
  encoded text (base64) and numbers written as words can slip through. Two checkpoints and the
  ownership check on every order number reduce this; they do not remove it.
- **Nothing executes in this lab.** In `llm03-3` the bot only claims actions. The firewall stops
  false promises and disclosures; it does not gate real tool calls. The agent lab (`llm03-1`),
  where `issue_refund` writes to the database, is not wired to the firewall.
- **Streamed replies flash before they are replaced.** The output check runs after the whole reply
  has streamed, so the user briefly sees it before the replacement. Input blocks do not have this
  problem.
- **"Confirm" is only a message.** There is no approval queue: the user is told a member of staff
  must approve, and nothing records a pending request.
- **One message at a time.** It has no memory of earlier turns. An attack split over several
  messages is caught only if one message or reply names the action.
- **Codes without digits.** An unknown coupon code with no digits (for example `SUPERSECRET`) is not
  recognised as a code. Known codes from the database are always recognised.
- **Card numbers are not checked here.** Level 1's output moderation masks card numbers; the
  firewall checks order numbers and email addresses only.
- **Possible false positives.** A 3+ digit number in a refund sentence is treated as an order
  number ("a refund for my 2024 order"). "Every customer" next to a verb like "send" or "list"
  is treated as a bulk data request.
- **Staff refund amounts.** For staff, the amount is checked only against orders the staff
  account owns; other refunds go to confirmation without an amount check.
- **The defense panel shows the wrong name.** When the firewall replaces a reply, the panel
  credits `output.moderate`. The audit log has the correct control and reason.
- **The audit log is a local file.** It is not tamper-proof, and its 200-character previews can
  contain personal data.
