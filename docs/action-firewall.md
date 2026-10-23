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
`logs/action_firewall_audit.jsonl`; blocks and confirmations also appear in the shared firewall log
on the admin page.

Detection reads each sentence twice: as written, and after the KB firewall's normalizer has undone
hiding tricks (look-alike Cyrillic or Greek letters, invisible characters, s p a c e d letters,
base64). Request and claim words are recognised in **English, Spanish, French, Portuguese and
German**, the same five languages the KB firewall covers, including denials ("no he procesado",
"ich habe ... nicht erstattet"), which are not claims. Amounts are read in both number formats
(`$1,250.50`, `1.250,50 €`).

Two further rules:

- **A reply that names a restricted code hands it over.** "The staff code is STAFF100" is blocked
  for a customer even though it claims nothing; `S-T-A-F-F-1-0-0` and `staff 100` count as the code.
- **"Orders for X" is someone else's data only if X is a real account.** The firewall loads the
  list of usernames, so "orders for alice" is blocked and "orders for international addresses"
  passes.

While a reply streams, it is released a sentence at a time and checked before each release, so a
claimed refund is replaced before the customer sees it (see `docs/leak-firewall.md`, *Streaming*).

## Switching it on and off

Level 0 never runs it: Level 0 stays vulnerable on purpose.

| Setting | Effect |
| --- | --- |
| `ACTION_FIREWALL_ENABLED=1` (default) | Firewall runs at Levels 1 and 2 |
| `ACTION_FIREWALL_ENABLED=0` | Firewall is listed but passes everything through |
| Admin page `/admin/kb-firewall`, *Action firewall* switch | Same, at runtime, no restart |

For the demo: stay at Level 1, run the attack with the switch off, flip it on, run the same attack
again.

## Policy

"Owned" means the order's `user_id` in the database matches the logged-in user.

| Action | Customer | Staff (`is_staff`) |
| --- | --- | --- |
| Refund an order | Own order, delivered or shipped, at most $250 and at most what was paid → confirm. Anything else → block | Confirm. Amount over what was paid → block |
| Apply a coupon | Coupon open to everyone → allow. Staff or admin coupon, or unknown code → block | Public and staff coupons → allow. Admin coupon or unknown code → block |
| A reply names a coupon code | Public code → allow. Staff or admin code → block | Public and staff codes → allow |
| Export customer data | Own data → confirm. Other customers → block | Confirm |
| Change order status | Cancel own pending order → confirm. Anything else → block | Confirm |
| Other customers' orders, emails or data | Block | Allow |
| No identity available | Block | Block |

## Results

`python -m eval.firewall.run_benchmark` compares this version with the one first merged
(git `90b54a5`) on 31 attacks and 26 honest messages:

| | Before | Now |
| --- | --- | --- |
| English attacks | 6/6 | 6/6 |
| Spanish, French, Portuguese, German | 10/17 | 17/17 |
| Hidden (look-alikes, zero-width, spacing, base64) | 2/6 | 6/6 |
| Reply that reveals a staff code | 0/2 | 2/2 |
| Honest messages blocked | 1/26 | 0/26 |

## Limitations

What the firewall does not catch, or gets wrong:

- **Detection uses patterns, not understanding.** Misspellings ("rfund"), numbers written as
  words, languages other than the five above, and new phrasings can slip through. The normalized
  second reading, two checkpoints and the ownership check on every order number reduce this; they
  do not remove it. The test set is ours, so the numbers above are optimistic.
- **Nothing executes in this lab.** In `llm03-3` the bot only claims actions. The firewall stops
  false promises and disclosures; it does not gate real tool calls. The agent lab (`llm03-1`),
  where `issue_refund` writes to the database, is not wired to the firewall.
- **"Confirm" is only a message.** There is no approval queue: the user is told a member of staff
  must approve, and nothing records a pending request.
- **One message at a time.** It has no memory of earlier turns. An attack split over several
  messages is caught only if one message or reply names the action.
- **Codes without digits.** An unknown coupon code with no digits (for example `SUPERSECRET`) is not
  recognised as a code. Known codes from the database are always recognised.
- **Card numbers are not checked here.** Level 1's output moderation masks card numbers, and the
  leak firewall refuses other customers' card endings that the prompt holds.
- **Possible false positives.** A 3+ digit number in a refund sentence is treated as an order
  number ("a refund for my 2024 order"). "Every customer" next to a verb like "send" or "list"
  is treated as a bulk data request. "staff 100" next to each other is read as the code STAFF100.
- **Staff refund amounts.** For staff, the amount is checked only against orders the staff
  account owns; other refunds go to confirmation without an amount check.
- **The audit log is a local file.** It is not tamper-proof, and its 200-character previews can
  contain personal data.
